import importlib.util
import ipaddress
import json
import socket
import struct
from pathlib import Path

from aifilter import dns

spec = importlib.util.spec_from_file_location("v6guard", Path(__file__).parents[1] / "home-dhcp" / "v6guard.py")
v6guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v6guard)

HOT = "2001:db8::2"


def test_ra_offers_no_default_route_only_host_routes():
    pkt = v6guard.build_ra([HOT], 180)
    assert pkt[0] == 134 and struct.unpack("!H", pkt[6:8])[0] == 0  # router lifetime 0
    typ, ln, plen, flags, life = struct.unpack("!BBBBI", pkt[16:24])
    assert (typ, ln, plen, flags, life) == (24, 3, 128, 0x08, 180)
    assert ipaddress.IPv6Address(pkt[24:40]) == ipaddress.IPv6Address(HOT)


def test_parse_rdnss_reads_servers_and_skips_expired():
    ra = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0x40, 180, 0, 0)
    live = struct.pack("!BBHI", 25, 3, 0, 180) + ipaddress.IPv6Address(HOT).packed
    dead = struct.pack("!BBHI", 25, 3, 0, 0) + ipaddress.IPv6Address("2001:db8::1").packed
    assert v6guard.parse_rdnss(ra + dead + live) == [HOT]
    assert v6guard.parse_rdnss(b"\x80" * 40) == []
    assert v6guard.parse_rdnss(ra + b"\x19\x00") == []  # zero-length option must not loop


def test_link_local_servers_are_not_taken_over():
    assert v6guard.routable(HOT) and not v6guard.routable("fe80::1")


def test_v6_clients_limited_to_neighbours(monkeypatch):
    monkeypatch.setattr(dns, "_v6_nets", (9e18, [ipaddress.ip_network("fe80::/10"),
                                                  ipaddress.ip_network("2001:db8:1::/64")]))
    assert dns._client_ok("2001:db8:1::99")
    assert dns._client_ok("fe80::1%en1")
    assert not dns._client_ok("2001:4860:4860::8888")
    lan = ipaddress.ip_network("192.168.0.0/16")[42]
    assert dns._client_ok(f"::ffff:{lan}") and not dns._client_ok("::ffff:8.8.8.8")
    assert dns._client_ok(str(lan)) and not dns._client_ok("192.0.2.42")


def test_udp6_answers_from_the_address_that_was_asked(monkeypatch):
    # Validate the actual packet-info contract without opening a live listener.
    # Run task-owned dispatch inline, so no daemon threads survive the test.
    class Thread:
        def __init__(self, target, args=(), **kwargs):
            self.target, self.args = target, args
        def start(self):
            self.target(*self.args)
    class R:
        def answer(self, data, client=""):
            return b"ok:" + data + b"@" + client.encode()
    monkeypatch.setattr(dns.threading, "Thread", Thread)
    monkeypatch.setattr(dns, "_v6_nets", (9e18, [ipaddress.ip_network("::1/128")]))
    for target in ("::1", HOT, "fe80::1"):
        source = ipaddress.IPv6Address(target).packed
        pktinfo = source + struct.pack("I", 4)
        class Sock:
            def __init__(self):
                self.reads, self.sent = 0, []
            def recvmsg(self, *args):
                self.reads += 1
                if self.reads > 1:
                    raise OSError("test socket closed")
                return (b"q", [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, pktinfo)], 0, ("::1", 1234, 0, 0))
            def sendmsg(self, data, anc, flags, addr):
                self.sent.append((data, anc, flags, addr))
        srv = Sock()
        assert dns.serve_udp6(R(), 53, sock=srv) is srv
        expected_if = struct.pack("I", 4) if target.startswith("fe80") else b"\0" * 4
        assert srv.sent == [([b"ok:q@::1"], [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, source + expected_if)],
                             0, ("::1", 1234, 0, 0))]


def test_malformed_rdnss_option_lengths_never_raise_or_learn():
    ra = v6guard.build_ra([], 0)
    for length in (0, 1, 2, 4):
        option = bytes([25, length]) + b'\x00' * max(0, length * 8 - 2)
        assert v6guard.parse_rdnss(ra + option) == []
    assert v6guard.parse_rdnss(ra + b'\x19') == []


def test_router_source_required_and_learned_addresses_bounded_expiring(monkeypatch):
    ra = v6guard.build_ra([], 0)
    option = struct.pack('!BBHI', 25, 3, 0, 180) + ipaddress.IPv6Address(HOT).packed
    learned = {}
    v6guard.learn_ra(learned, ra + option, ('fe80::bad', 0, 0, 4), 4, 'fe80::1', 0)
    assert learned == {}
    v6guard.learn_ra(learned, ra + option, ('fe80::1', 0, 0, 5), 4, 'fe80::1', 0)
    assert learned == {}
    v6guard.learn_ra(learned, ra + option, ('fe80::1', 0, 0, 4), 4, 'fe80::1', 0)
    assert learned == {HOT: 0}
    v6guard.learn(learned, ['not an IP', 'fe80::1'] + ['2001:db8::' + str(i) for i in range(10)], 10)
    assert len(learned) == 4
    v6guard.learn(learned, [HOT], 100)
    v6guard.learn(learned, [], 1810)
    assert learned == {HOT: 100}
    v6guard.learn(learned, [], 1900)
    assert learned == {}


def test_default_router_uses_actual_route_and_interface(monkeypatch):
    from types import SimpleNamespace
    calls = []
    def run(command, **kw):
        calls.append(command)
        return SimpleNamespace(stdout=' gateway: fe80::1%en1\n interface: en1\n')
    monkeypatch.setattr(v6guard.subprocess, 'run', run)
    assert v6guard.default_router('en1') == 'fe80::1'
    assert v6guard.default_router('en2') is None
    assert calls[0] == ['/sbin/route', '-n', 'get', '-inet6', 'default']


def test_main_survives_bad_packet_and_cleans_up_after_unexpected_error(monkeypatch):
    import pytest
    monkeypatch.setattr('sys.argv', ['v6guard.py'])
    monkeypatch.setattr(v6guard.signal, 'signal', lambda *a: None)
    monkeypatch.setattr(v6guard.socket, 'if_nametoindex', lambda *a: 4)
    monkeypatch.setattr(v6guard, 'default_router', lambda *a: 'fe80::1')
    monkeypatch.setattr(v6guard, 'dhcp6_dns', lambda *a: [HOT])
    monkeypatch.setattr(v6guard, 'filter_alive', lambda: True)
    events = []
    class Sock:
        def setsockopt(self, *a):
            pass
        def recvfrom(self, *a):
            raise ValueError('malformed packet')
        def sendto(self, pkt, addr):
            events.append(('announce', struct.unpack('!I', pkt[20:24])[0]))
        def close(self):
            events.append(('close',))
    sock = Sock()
    monkeypatch.setattr(v6guard.socket, 'socket', lambda *a: sock)
    monkeypatch.setattr(v6guard, 'alias', lambda addr, add: events.append(('alias', add)))
    calls = []
    def select(*a):
        calls.append(1)
        if len(calls) == 1:
            return [sock], [], []
        raise RuntimeError('unexpected exit')
    monkeypatch.setattr(v6guard.select, 'select', select)
    monkeypatch.setattr(v6guard, 'write_state', lambda addrs: events.append(('state', set(addrs))))
    with pytest.raises(RuntimeError):
        v6guard.main()
    assert ('alias', True) in events and ('alias', False) in events
    assert ('announce', 0) in events
    assert events[-2:] == [('state', set()), ('close',)]


def test_v6guard_has_python39_compatible_syntax():
    import ast
    source = Path(v6guard.__file__).read_text()
    ast.parse(source, feature_version=(3, 9))


def test_main_rechecks_current_router_for_each_valid_announcement(monkeypatch):
    import pytest
    monkeypatch.setattr('sys.argv', ['v6guard.py'])
    monkeypatch.setattr(v6guard.signal, 'signal', lambda *a: None)
    monkeypatch.setattr(v6guard.socket, 'if_nametoindex', lambda *a: 4)
    routers = iter(['fe80::1', 'fe80::2'])
    checks = []
    def current(*args):
        checks.append(1)
        return next(routers)
    monkeypatch.setattr(v6guard, 'default_router', current)
    monkeypatch.setattr(v6guard, 'dhcp6_dns', lambda *a: [])
    monkeypatch.setattr(v6guard, 'filter_alive', lambda: True)
    learned = {}
    original = v6guard.learn
    def learn(state, addresses, now):
        original(state, addresses, now)
        learned.clear()
        learned.update(state)
    monkeypatch.setattr(v6guard, 'learn', learn)
    class Sock:
        count = 0
        def setsockopt(self, *a):
            pass
        def recvfrom(self, *a):
            self.count += 1
            address = HOT if self.count == 1 else '2001:db8::bad'
            packet = v6guard.build_ra([], 0) + struct.pack('!BBHI', 25, 3, 0, 180) + ipaddress.IPv6Address(address).packed
            return packet, ('fe80::1', 0, 0, 4)
        def sendto(self, *a):
            pass
        def close(self):
            pass
    sock = Sock()
    monkeypatch.setattr(v6guard.socket, 'socket', lambda *a: sock)
    def ready(*a):
        if sock.count >= 2:
            raise RuntimeError('test complete')
        return [sock], [], []
    monkeypatch.setattr(v6guard.select, 'select', ready)
    monkeypatch.setattr(v6guard, 'alias', lambda *a: None)
    monkeypatch.setattr(v6guard, 'write_state', lambda *a: None)
    with pytest.raises(RuntimeError):
        v6guard.main()
    assert len(checks) == 2
    assert set(learned) == {HOT}


def test_cached_dhcp_packet_does_not_keep_old_addresses_alive_forever(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(v6guard, '_dhcp6_packets', {})
    packet = ['transaction-id: 123\n DNS_SERVERS: ' + HOT]
    monkeypatch.setattr(v6guard.subprocess, 'run', lambda *a, **kw: SimpleNamespace(stdout=packet[0]))
    learned = {}
    v6guard.learn(learned, v6guard.dhcp6_dns('en1'), 0)
    assert set(learned) == {HOT}
    v6guard.learn(learned, v6guard.dhcp6_dns('en1'), 1800)
    assert learned == {}
    packet[0] = packet[0].replace('123', '456')
    v6guard.learn(learned, v6guard.dhcp6_dns('en1'), 1810)
    assert learned == {HOT: 1810}
