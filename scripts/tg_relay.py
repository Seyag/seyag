#!/usr/bin/env python3
"""Usage: tg_relay.py [--host 203.0.113.10] [--port 1080] -- Telegram-only SOCKS5 relay over the tailnet.

Lets companion reach Telegram through the home tunnel on networks that block Telegram (e.g. a school filter).
It is not a general proxy: clients must be on the tailnet (100.64.0.0/10), only CONNECT is supported, and the
destination must be an IP inside Telegram's published ranges (core.telegram.org/resources/cidr.txt) on an
allowed port. Domain names are refused (Telegram clients connect by IP), so nothing else can ride through it.
"""
import argparse
import asyncio
import ipaddress
import struct
import sys
import time

TELEGRAM_NETS = [ipaddress.ip_network(n) for n in (
    "91.108.56.0/22", "91.108.4.0/22", "91.108.8.0/22", "91.108.16.0/22", "91.108.12.0/22",
    "149.154.160.0/20", "91.105.192.0/23", "91.108.20.0/22", "185.76.151.0/24",
    "2001:b28:f23d::/48", "2001:b28:f23f::/48", "2001:67c:4e8::/48", "2001:b28:f23c::/48", "2a0a:f280::/32")]
TAILNET = [ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48")]
PORTS = {80, 443, 5222}
MAX_CONN = 256
IDLE = 600
_active = 0


def allowed_client(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in TAILNET) or a.is_loopback


def allowed_dest(ip, port: int) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return port in PORTS and any(a.version == n.version and a in n for n in TELEGRAM_NETS)


def log(msg: str) -> None:
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


async def _pipe(r, w):
    try:
        while data := await asyncio.wait_for(r.read(65536), IDLE):
            w.write(data)
            await w.drain()
    except (asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        w.close()


async def parse_connect(r) -> tuple[int, str | None, int]:
    ver, cmd, _, atyp = await r.readexactly(4)
    if atyp == 1:
        ip = str(ipaddress.IPv4Address(await r.readexactly(4)))
    elif atyp == 4:
        ip = str(ipaddress.IPv6Address(await r.readexactly(16)))
    elif atyp == 3:
        await r.readexactly((await r.readexactly(1))[0])
        await r.readexactly(2)
        return 2, None, 0  # domain names refused: not allowed by ruleset
    else:
        return 8, None, 0
    port = struct.unpack("!H", await r.readexactly(2))[0]
    if ver != 5 or cmd != 1:
        return 7, ip, port
    if not allowed_dest(ip, port):
        return 2, ip, port
    return 0, ip, port


def reply(code: int) -> bytes:
    return bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0])


async def handle(r, w):
    global _active
    peer = (w.get_extra_info("peername") or ("?",))[0]
    if not allowed_client(peer) or _active >= MAX_CONN:
        w.close()
        return
    _active += 1
    try:
        ver, n = await asyncio.wait_for(r.readexactly(2), 15)
        methods = await asyncio.wait_for(r.readexactly(n), 15)
        if ver != 5 or 0 not in methods:
            w.write(b"\x05\xff")
            return
        w.write(b"\x05\x00")
        await w.drain()
        code, ip, port = await asyncio.wait_for(parse_connect(r), 15)
        if code:
            log(f"refused {peer} -> {ip}:{port} code {code}")
            w.write(reply(code))
            return
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(ip, port), 15)
        except (OSError, asyncio.TimeoutError):
            w.write(reply(5))
            return
        w.write(reply(0))
        await w.drain()
        await asyncio.gather(_pipe(r, uw), _pipe(ur, w))
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
        pass
    finally:
        _active -= 1
        w.close()


async def main(host: str, port: int):
    srv = await asyncio.start_server(handle, host, port)
    log(f"telegram relay on {host}:{port}")
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="203.0.113.10")
    ap.add_argument("--port", type=int, default=1080)
    a = ap.parse_args()
    try:
        asyncio.run(main(a.host, a.port))
    except OSError as exc:  # tailnet address not up yet: launchd restarts us
        log(f"cannot listen: {exc}")
        sys.exit(1)
