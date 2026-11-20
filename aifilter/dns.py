"""Home-network DNS filter: the router points every device here.

Blocks the community blocklists and admin "block" decisions for every device in
the house (TVs and guests included), forces safe search on search engines, and
turns off encrypted-DNS bypasses. Everything else is answered by an upstream
family resolver.

Run:  .venv/bin/python -m aifilter.dns
"""

import ipaddress
import re
import socket
import socketserver
import threading
import time

from dnslib import QTYPE, RCODE, RR, A, CNAME, DNSRecord

from aifilter import config
from aifilter.export_settings import listen_ip
from aifilter import probe
from aifilter import safesearch
from aifilter.store import Store

# Answered as NXDOMAIN so devices switch off their own bypasses on this network:
# Firefox DNS-over-HTTPS canary and Apple iCloud Private Relay.
BYPASS_CANARIES = {"use-application-dns.net", "mask.icloud.com", "mask-h2.icloud.com"}


# Never blocked at network level, whatever a list says: the services this Mac and
# its agents depend on, so the filter can never lock out its own management.
PROTECTED = (
    "anthropic.com", "claude.ai", "claude.com", "github.com", "githubusercontent.com",
    "githubassets.com", "openai.com", "chatgpt.com", "google.com", "googleapis.com",
    "gstatic.com", "apple.com", "icloud.com", "tailscale.com", "tailscale.io",
    "telegram.org", "brew.sh", "pypi.org", "pythonhosted.org", "npmjs.org",
    "supabase.co", "vercel.com", "cloudflare.com", "oisd.nl",
)


def protected(name: str) -> bool:
    return any(name == d or name.endswith("." + d) for d in PROTECTED)


ALLOWED_CLIENTS = [ipaddress.ip_network(n) for n in
                   ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8")]


class Resolver:
    def __init__(self, store: Store, upstreams: list[str], timeout: float = 2.0, policy_exempt=()):
        self.store = store
        # Devices that skip the social-feed policy (the Mac running the agents).
        self.policy_exempt = set(policy_exempt)
        self.upstreams = upstreams
        self.timeout = timeout
        self._cache: dict[tuple[str, int], tuple[float, bytes]] = {}
        self._lock = threading.Lock()

    def _blocked(self, name, client):
        return not protected(name) and (self.store.network_blocked(name) or (
            client not in self.policy_exempt and self.store.policy_blocked(name)))

    def _block_reply(self, req, name, client=""):
        try:
            # Only a query carrying the install's probe marker is a health probe; real lookups
            # of the same names, from this Mac too, stay in the report.
            self.store.log("probe-blocked" if probe.dns_marked(req) else "dns-blocked", name, "")
        except Exception:  # telemetry cannot turn a block into upstream fallback
            pass
        reply = req.reply()
        if req.q.qtype == QTYPE.A:
            reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
        return reply.pack()

    def _check_chain(self, req, resp, client):
        names = {str(rr.rname).lower().rstrip(".") for rr in resp.rr}
        names.update(str(rr.rdata).lower().rstrip(".") for rr in resp.rr if rr.rtype == QTYPE.CNAME)
        for name in names:
            if name in BYPASS_CANARIES or self._blocked(name, client):
                return self._block_reply(req, name, client)
        return None

    def answer(self, data: bytes, client: str = "") -> bytes:
        req = DNSRecord.parse(data)
        name = str(req.q.qname).rstrip(".").lower()
        qtype = req.q.qtype

        if name in BYPASS_CANARIES:
            reply = req.reply()
            reply.header.rcode = RCODE.NXDOMAIN
            return reply.pack()

        if self._blocked(name, client):
            return self._block_reply(req, name, client)

        # The agents' Mac keeps normal YouTube (channel management); search engines are safe for all.
        target = safesearch.target(name, youtube=client not in self.policy_exempt)
        if target and qtype in (QTYPE.A, QTYPE.AAAA):
            upstream = DNSRecord.parse(self._forward(DNSRecord.question(target, QTYPE[qtype]).pack()))
            blocked = self._check_chain(req, upstream, client)
            if blocked is not None:
                return blocked
            reply = req.reply()
            reply.add_answer(RR(req.q.qname, QTYPE.CNAME, rdata=CNAME(target + "."), ttl=300))
            for rr in upstream.rr:
                reply.add_answer(rr)
            return reply.pack()

        return self._cached_forward(req, name, qtype, data, client)

    def _cached_forward(self, req: DNSRecord, name: str, qtype: int, data: bytes, client="") -> bytes:
        key = (name, qtype)
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
        if hit and hit[0] > now:
            cached = DNSRecord.parse(hit[1])
            blocked = self._check_chain(req, cached, client)
            if blocked is not None:
                return blocked
            cached.header.id = req.header.id
            return cached.pack()
        raw = self._forward(data)
        resp = DNSRecord.parse(raw)
        blocked = self._check_chain(req, resp, client)
        if blocked is not None:
            return blocked
        ttl = min([rr.ttl for rr in resp.rr] or [60])
        with self._lock:
            if len(self._cache) > 20_000:
                self._cache.clear()
            self._cache[key] = (now + max(30, min(ttl, 3600)), raw)
        return raw

    def _forward(self, data: bytes) -> bytes:
        last = None
        for server in self.upstreams:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(self.timeout)
                    s.sendto(data, (server, 53))
                    return s.recv(4096)
            except OSError as e:
                last = e
        raise last or OSError("no upstream")


def _servfail(data: bytes) -> bytes:
    try:
        reply = DNSRecord.parse(data).reply()
        reply.header.rcode = RCODE.SERVFAIL
        return reply.pack()
    except Exception:  # noqa: BLE001 - garbage in, nothing out
        return b""


def _fallback(resolver: "Resolver", data: bytes) -> bytes:
    """On an internal error answer straight from upstream rather than break the house."""
    try:
        return resolver._forward(data)
    except Exception:  # noqa: BLE001
        return _servfail(data)


_v6_nets: tuple[float, list] = (0.0, [])


def _local_v6_nets() -> list:
    """The /64s this Mac lives on: only neighbours may use the IPv6 listener."""
    global _v6_nets
    if time.time() - _v6_nets[0] > 60:
        nets = [ipaddress.ip_network("fe80::/10"), ipaddress.ip_network("::1/128")]
        try:
            import subprocess
            out = subprocess.run(["/sbin/ifconfig"], capture_output=True, text=True, timeout=5).stdout
            for m in re.finditer(r"inet6 ([0-9a-f:]+) prefixlen (64|128)", out):
                ip = ipaddress.ip_address(m.group(1))
                if not ip.is_link_local:
                    # /64: neighbours. /128: this Mac's own alias (the taken-over DNS address),
                    # which is the source when the Mac itself probes that address.
                    nets.append(ipaddress.ip_network(f"{ip}/{m.group(2)}", strict=False))
        except Exception:  # noqa: BLE001 - keep the previous list
            nets = _v6_nets[1] or nets
        _v6_nets = (time.time(), nets)
    return _v6_nets[1]


def _client_ok(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%")[0])
    if ip.version == 6:
        if ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        else:
            return any(ip in n for n in _local_v6_nets())
    return any(ip in n for n in ALLOWED_CLIENTS)


DNS_WORKERS = threading.BoundedSemaphore(32)  # shared by IPv4/IPv6, UDP/TCP
TCP_TIMEOUT = 3.0


LOCAL_WORKERS = threading.BoundedSemaphore(16)  # the Mac itself (the proxy's lookups): never starved by the house


def _permits(client_address):
    host = str(client_address[0]) if client_address else ""
    return LOCAL_WORKERS if host in ("127.0.0.1", "::1", "::ffff:127.0.0.1") else DNS_WORKERS


class _BoundedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False

    def process_request(self, request, client_address):
        permits = _permits(client_address)
        if not permits.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            permits.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            _permits(client_address).release()


def _recv_exact(sock, length, deadline):
    out = bytearray()
    while len(out) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("DNS TCP frame deadline")
        sock.settimeout(remaining)
        chunk = sock.recv(length - len(out))
        if not chunk:
            raise OSError("incomplete DNS TCP frame")
        out.extend(chunk)
    return bytes(out)


def make_servers(resolver: Resolver, port: int = 53, *, host="127.0.0.1", host6="::1"):
    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            if not _client_ok(self.client_address[0]):
                return
            try:
                out = resolver.answer(data, self.client_address[0])
            except Exception:  # noqa: BLE001 - one bad query must not stop the house
                out = _fallback(resolver, data)
            if out:
                sock.sendto(out, self.client_address)

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            if not _client_ok(self.client_address[0]):
                return
            try:
                deadline = time.monotonic() + TCP_TIMEOUT
                head = _recv_exact(self.request, 2, deadline)
                data = _recv_exact(self.request, int.from_bytes(head, "big"), deadline)
                try:
                    out = resolver.answer(data, self.client_address[0])
                except Exception:  # noqa: BLE001
                    out = _fallback(resolver, data)
                self.request.settimeout(TCP_TIMEOUT)
                self.request.sendall(len(out).to_bytes(2, "big") + out)
            except OSError:
                return

    class UDP(_BoundedThreads, socketserver.UDPServer):
        allow_reuse_address = True

    class TCP(_BoundedThreads, socketserver.TCPServer):
        allow_reuse_address = True

    class TCP6(TCP):
        address_family = socket.AF_INET6

        def server_bind(self):
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            super().server_bind()

    make_servers.tcp6 = lambda: TCP6((host6, port), TCPHandler)
    return (UDP((host, port), UDPHandler), TCP((host, port), TCPHandler))


def serve_udp6(resolver: Resolver, port: int = 53, sock=None, *, host="::1"):
    """IPv6 UDP listener on the configured local address."""
    if sock is None:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
        sock.bind((host, port))

    def reply(data, anc, addr):
        try:
            try:
                out = resolver.answer(data, addr[0].split("%")[0])
            except Exception:  # noqa: BLE001 - one bad query must not stop the house
                out = _fallback(resolver, data)
            if out:
                try:
                    sock.sendmsg([out], anc, 0, addr)
                except OSError:
                    pass
        finally:
            DNS_WORKERS.release()

    def loop():
        while True:
            try:
                data, anc, _flags, addr = sock.recvmsg(4096, 256)
            except OSError:
                return
            if not _client_ok(addr[0]):
                continue
            # Echo the destination address back as our source; let the kernel pick the interface
            # unless the query came to a link-local address.
            out_anc = []
            for level, typ, cdata in anc:
                if level == socket.IPPROTO_IPV6 and typ == socket.IPV6_PKTINFO and len(cdata) >= 20:
                    dst = cdata[:16]
                    ifx = cdata[16:20] if dst[:2] == b"\xfe\x80" else b"\0\0\0\0"
                    out_anc = [(level, typ, dst + ifx)]
            if DNS_WORKERS.acquire(blocking=False):
                try:
                    threading.Thread(target=reply, args=(data, out_anc, addr), daemon=True).start()
                except BaseException:
                    DNS_WORKERS.release()
                    raise

    threading.Thread(target=loop, daemon=True).start()
    return sock


def main():
    cfg = config.load()
    resolver = Resolver(Store(config.db_path()), cfg.get("dns", "upstreams", ["1.1.1.3", "1.0.0.3"]),
                        policy_exempt=cfg.get("dns", "policy_exempt", ["127.0.0.1"]))
    host = listen_ip(cfg.get("dns", "listen_host", "127.0.0.1"), 4)
    ipv6 = cfg.get("dns", "listen_host_ipv6", "::1")
    host6 = listen_ip(ipv6, 6) if ipv6 != "" else None
    port = cfg.get("dns", "port", 53)
    udp, tcp = make_servers(resolver, port, host=host, host6=host6)
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    if host6:
        try:
            serve_udp6(resolver, port, host=host6)
            threading.Thread(target=make_servers.tcp6().serve_forever, daemon=True).start()
        except OSError as e:
            print("dns filter: no IPv6 listener:", e, flush=True)
    print("dns filter on port", cfg.get("dns", "port", 53), flush=True)
    udp.serve_forever()


if __name__ == "__main__":
    main()
