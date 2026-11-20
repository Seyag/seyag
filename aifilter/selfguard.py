"""Keep the proxy from reaching this Mac's own services.

The admin page trusts requests from the Mac itself (Tailscale whois of the
client address). A filtered device talking through the proxy arrives at those
services *as the Mac*, so the proxy must never forward to:

  - any loopback or unspecified address, on any port;
  - any address of this Mac (LAN, Tailscale, IPv6) on the filter's own ports
    (admin, PAC, DNS, the proxy itself).

Other ports on the Mac's tailnet name stay reachable (the Telegram bridge
panel on :10000, Tailscale Serve previews on :443).
"""

import asyncio
import ipaddress
import socket
import time

_LOCAL_CACHE: dict[str, tuple[float, bool]] = {}
_CACHE_TTL = 300.0


def _ip(value: str):
    try:
        addr = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


def is_local_address(ip: str) -> bool:
    """True when the address belongs to this machine (binding to it succeeds)."""
    addr = _ip(ip)
    if addr is not None and (addr.is_loopback or addr.is_unspecified):
        return True  # known locally even when a sandbox disallows bind probes
    hit = _LOCAL_CACHE.get(ip)
    if hit and time.monotonic() - hit[0] < _CACHE_TTL:
        return hit[1]
    if addr is None:
        return False
    family = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.bind((ip if addr.version == 6 and "%" in ip else str(addr), 0))
        local = True
    except OSError:
        local = False
    if len(_LOCAL_CACHE) > 4096:
        _LOCAL_CACHE.clear()
    _LOCAL_CACHE[ip] = (time.monotonic(), local)
    return local


async def resolve(host: str, port: int, timeout: float = 3.0) -> list[str]:
    """All addresses a name may connect to. Literal addresses resolve to themselves."""
    host = (host or "").strip("[]").rstrip(".").lower()
    if _ip(host) is not None:
        return [host]
    if host == "localhost" or host.endswith(".localhost"):
        return ["127.0.0.1", "::1"]
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout)
    except (OSError, asyncio.TimeoutError, UnicodeError):
        return []  # The caller must refuse; never allow a second, unchecked lookup.
    result = ResolvedIPs(dict.fromkeys(
        f"{info[4][0]}%{info[4][3]}" if info[0] == socket.AF_INET6 and info[4][3] else info[4][0]
        for info in infos))
    result.addrinfos = tuple(infos)
    return result


class ResolvedIPs(list):
    """Numeric addresses with original IPv6 flow/scope information for the dialer."""


class PinnedHost(str):
    """Logical host identity carrying only the addresses checked for this dial.

    Ordinary str equality/hash preserves mitmproxy connection reuse. The resolver
    below returns these numeric addresses without consulting DNS a second time.
    """
    def __new__(cls, host, port, ips):
        value = super().__new__(cls, host)
        value.port = port
        infos = []
        for ip in ips:
            if _ip(ip) is None:
                raise ValueError("pin requires numeric addresses")
            infos.extend(socket.getaddrinfo(ip, port, type=socket.SOCK_STREAM,
                                           flags=socket.AI_NUMERICHOST | socket.AI_NUMERICSERV))
        if not infos:
            raise ValueError("cannot pin an empty DNS result")
        # IPv4 first: some IPv6 routes to Apple's CDN black-hole at home (2026-11-12, SYN never answered),
        # and the dialer tries addresses one by one, so one dead IPv6 edge stalled App Store downloads.
        value.addrinfos = tuple(sorted(getattr(ips, "addrinfos", tuple(infos)), key=lambda i: i[0] != socket.AF_INET))
        return value


class PinnedResolver:
    """Narrow adapter for CPython's asyncio dialer; ordinary DNS is unchanged.

    A literal first-IP rewrite of Server.address breaks mitmproxy reuse and
    asyncio's multi-address fallback. This pins the checked address list while
    keeping the logical identity and normal dial/fallback implementation.
    """
    def __init__(self, loop):
        if type(loop) is not asyncio.SelectorEventLoop:
            raise RuntimeError("unsupported event loop for pinned DNS")
        self.loop, self.original = loop, loop.getaddrinfo
        self.original_create_connection = loop.create_connection
        self.wrapper = self.getaddrinfo
        self.connect_wrapper = self.create_connection
        loop.getaddrinfo = self.wrapper
        loop.create_connection = self.connect_wrapper

    @classmethod
    def install(cls, loop):
        resolver = getattr(loop, "_aifilter_pinned_resolver", None)
        if resolver is None:
            resolver = cls(loop)
            loop._aifilter_pinned_resolver = resolver
        if loop.getaddrinfo is not resolver.wrapper:
            raise RuntimeError("pinned resolver was replaced")
        return resolver

    async def getaddrinfo(self, host, port, *, family=0, type=0, proto=0, flags=0):
        if isinstance(host, PinnedHost):
            if port != host.port or type not in (0, socket.SOCK_STREAM) or proto not in (0, socket.IPPROTO_TCP):
                raise OSError("pinned destination changed")
            infos = [info for info in host.addrinfos if family in (0, info[0])]
            if not infos:
                raise OSError("no checked addresses for this family")
            return infos
        return await self.original(host, port, family=family, type=type, proto=proto, flags=flags)

    async def create_connection(self, protocol_factory, host=None, port=None, **kwargs):
        """Race checked addresses for pinned hosts instead of waiting on a dead CDN edge.

        asyncio only enables its RFC 8305-style address fallback when
        ``happy_eyeballs_delay`` is supplied.  Mitmproxy does not supply it, so a
        black-holed first Apple address otherwise consumes the whole upstream
        timeout without trying the other DNS answers.
        """
        if isinstance(host, PinnedHost):
            kwargs.setdefault("happy_eyeballs_delay", 0.25)
            kwargs.setdefault("interleave", 1)
        return await self.original_create_connection(protocol_factory, host, port, **kwargs)

    def close(self):
        # Script hot reload invokes done while the loop is still running. Pending
        # dials must retain this stateless adapter; the next addon reuses it.
        if not self.loop.is_running() and self.loop.getaddrinfo is self.wrapper:
            self.loop.getaddrinfo = self.original
            if self.loop.create_connection is self.connect_wrapper:
                self.loop.create_connection = self.original_create_connection
            if getattr(self.loop, "_aifilter_pinned_resolver", None) is self:
                del self.loop._aifilter_pinned_resolver


def refusal(ips: list[str], port: int, protected_ports: set[int], is_local=None) -> str | None:
    """Why this destination is refused, or None when it is fine."""
    if not ips:
        return "DNS lookup failed"
    is_local = is_local or is_local_address
    for raw in ips:
        addr = _ip(raw)
        if addr is None:
            return "invalid DNS address"
        if addr.is_loopback or addr.is_unspecified:
            return f"loopback {raw}"
        if port in protected_ports and is_local(raw if "%" in raw else str(addr)):
            return f"this Mac {raw}:{port}"
    return None
