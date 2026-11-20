import ipaddress
import asyncio
import struct

from scripts import tg_relay as t


def test_clients_tailnet_only():
    assert t.allowed_client(str(ipaddress.ip_network("100.64.0.0/10")[42])) and t.allowed_client("127.0.0.1")
    assert not t.allowed_client(str(ipaddress.ip_network("192.168.0.0/16")[42])) and not t.allowed_client("5.28.189.110")


def test_destinations_telegram_only():
    assert t.allowed_dest("149.154.167.51", 443) and t.allowed_dest("2001:b28:f23d::a", 443)
    assert not t.allowed_dest("149.154.167.51", 22)          # port not allowed
    assert not t.allowed_dest("142.250.75.14", 443)          # Google
    assert not t.allowed_dest("1.1.1.1", 443)
    assert not t.allowed_dest("not-an-ip", 443)


def _connect(atyp, addr: bytes, port: int, cmd=1):
    async def go():
        r = asyncio.StreamReader()
        r.feed_data(bytes([5, cmd, 0, atyp]) + addr + struct.pack("!H", port))
        r.feed_eof()
        return await t.parse_connect(r)
    return asyncio.run(go())


def test_parse_connect_rules():
    assert _connect(1, bytes([149, 154, 167, 51]), 443) == (0, "149.154.167.51", 443)
    assert _connect(1, bytes([8, 8, 8, 8]), 443)[0] == 2
    assert _connect(3, bytes([11]) + b"example.com", 443)[0] == 2   # domains refused
    assert _connect(1, bytes([149, 154, 167, 51]), 443, cmd=3)[0] == 7  # UDP associate refused
