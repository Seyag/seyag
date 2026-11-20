#!/usr/bin/env python3
"""Usage: sudo python3 home-dhcp/v6guard.py [--iface en1] -- pulls the router's IPv6 name servers to this Mac.

The HOT router announces its own unfiltered IPv6 DNS server and has no switch for it. This daemon
learns those addresses (router announcements + DHCPv6), puts each one on lo0, and announces a
more-specific /128 route for it through this Mac (RFC 4191, router lifetime 0, so the Mac never
becomes anyone's default router). Home devices then reach the filtering DNS when they ask "the
router's" server. If the local DNS filter stops answering, or on exit, the routes are withdrawn.
"""
import argparse
import ipaddress
import json
import os
import re
import select
import signal
import socket
import struct
import subprocess
import time

STATE = "/var/db/home-v6guard.json"
ROUTE_LIFETIME = 180   # seconds a device keeps the route without a refresh
INTERVAL = 30
LEARN_TTL = 30 * 60
MAX_LEARNED = 4
ND_RA, OPT_RIO, OPT_RDNSS = 134, 24, 25
_dhcp6_packets = {}  # ipconfig returns the last packet, not a fresh announcement


def build_ra(addrs, lifetime):
    """Router advertisement that offers no default route, only /128 routes to `addrs`."""
    pkt = struct.pack("!BBHBBHII", ND_RA, 0, 0, 0, 0, 0, 0, 0)
    for a in addrs:
        pkt += struct.pack("!BBBBI", OPT_RIO, 3, 128, 0x08, lifetime) + ipaddress.IPv6Address(a).packed
    return pkt


def parse_rdnss(pkt):
    """IPv6 DNS servers named in a router advertisement."""
    out = []
    if len(pkt) < 16 or pkt[0] != ND_RA or pkt[1] != 0:
        return out
    i = 16
    while i + 2 <= len(pkt):
        typ, ln = pkt[i], pkt[i + 1] * 8
        if ln == 0 or i + ln > len(pkt):
            return []
        if typ == OPT_RDNSS and (ln < 24 or (ln - 8) % 16):
            return []
        if typ == OPT_RDNSS and struct.unpack("!I", pkt[i + 4:i + 8])[0] > 0:
            for j in range(i + 8, i + ln, 16):
                out.append(str(ipaddress.IPv6Address(pkt[j:j + 16])))
        i += ln
    return out if i == len(pkt) else []


def routable(addr):
    ip = ipaddress.IPv6Address(addr)
    return not (ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_unspecified)


def dhcp6_dns(iface):
    try:
        out = subprocess.run(["/usr/sbin/ipconfig", "getv6packet", iface], capture_output=True, text=True, timeout=5).stdout
    except Exception:  # noqa: BLE001
        return []
    if _dhcp6_packets.get(iface) == out:
        return []  # polling the same cached lease must not refresh its addresses forever
    _dhcp6_packets[iface] = out
    m = re.search(r"DNS_SERVERS.*?:\s*(.+)", out)
    return [a.strip() for a in m.group(1).split(",")] if m else []


def default_router(iface):
    try:
        out = subprocess.run(["/sbin/route", "-n", "get", "-inet6", "default"],
                             capture_output=True, text=True, timeout=5).stdout
        gateway = re.search(r"^\s*gateway:\s*(\S+)", out, re.M)
        interface = re.search(r"^\s*interface:\s*(\S+)", out, re.M)
        if not gateway or not interface or interface.group(1) != iface:
            return None
        return str(ipaddress.IPv6Address(gateway.group(1).split("%")[0]))
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def learn(learned, addresses, now):
    for addr in list(learned):
        if now - learned[addr] >= LEARN_TTL:
            del learned[addr]
    for addr in addresses:
        try:
            addr = str(ipaddress.IPv6Address(addr))
            if routable(addr) and (addr in learned or len(learned) < MAX_LEARNED):
                learned[addr] = now
        except ValueError:  # one malformed DHCP address cannot stop the daemon
            continue


def learn_ra(learned, pkt, src, idx, router, now):
    if len(src) > 3 and src[3] == idx and router and src[0].split("%")[0] == router:
        learn(learned, parse_rdnss(pkt), now)


def filter_alive():
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.sendto(q, ("127.0.0.1", 53))
            return len(s.recv(512)) > 12
    except OSError:
        return False


def alias(addr, add):
    if add:
        # A stale host route through en1 (e.g. our own announcement heard back) would
        # make this Mac send its own queries for the address out to the wire.
        subprocess.run(["/sbin/route", "-n", "delete", "-inet6", addr], capture_output=True, timeout=5)
    subprocess.run(["/sbin/ifconfig", "lo0", "inet6", addr, "prefixlen", "128", "alias" if add else "-alias"],
                   capture_output=True, timeout=5)


def write_state(addrs):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"addrs": sorted(addrs), "ts": int(time.time())}, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, STATE)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="en1")
    args = ap.parse_args()
    idx = socket.if_nametoindex(args.iface)
    s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    active, stop, fails = set(), [], 0
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))

    def announce(addrs, lifetime):
        if addrs:
            try:
                s.sendto(build_ra(sorted(addrs), lifetime), ("ff02::1", 0, 0, idx))
            except OSError as e:
                print("send failed:", e, flush=True)

    try:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
        # Never hear our own announcement: the Mac must not route the address to itself over en1.
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        learned, next_send = {}, 0.0
        while not stop:
            try:
                r, _, _ = select.select([s], [], [], 1.0)
                if r:
                    pkt, src = s.recvfrom(2048)
                    if len(src) > 3 and src[3] == idx and parse_rdnss(pkt):
                        # Route changes must take effect immediately, rather than
                        # trusting the previous router until the next announcement.
                        learn_ra(learned, pkt, src, idx, default_router(args.iface), time.monotonic())
            except (OSError, ValueError, struct.error) as exc:
                print("ignored IPv6 packet:", type(exc).__name__, flush=True)
            now = time.monotonic()
            if now < next_send:
                continue
            next_send = now + INTERVAL
            learn(learned, dhcp6_dns(args.iface), now)
            fails = 0 if filter_alive() else fails + 1
            want = set() if fails >= 2 else set(learned)
            changed = want != active
            for a in want - active:
                active.add(a)  # cleanup also covers interruption during alias()
                alias(a, True)
                print("taking over", a, flush=True)
            for a in active - want:
                announce({a}, 0)
                alias(a, False)
                active.remove(a)
                print("released", a, flush=True)
            if changed:
                write_state(active)
            announce(active, ROUTE_LIFETIME)
    finally:
        try:
            announce(active, 0)
            for a in active:
                try:
                    alias(a, False)
                except (OSError, subprocess.SubprocessError):
                    pass  # still clean up every other alias
            write_state(set())
        finally:
            s.close()


if __name__ == "__main__":
    main()
