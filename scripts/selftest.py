#!/usr/bin/env python3
"""Usage: scripts/selftest.py [--notify] [--proxy-port 8118] [--dns-port 53] [--state-file data/selftest.json]

Daily end-to-end proof that the filter still filters: known-bad names and pages must be
blocked, search engines must be on their safe endpoints, and everyday sites must work.
Exit 0 when every case passes. With --notify the owner gets one alert when the set of
failing cases changes and one when everything passes again (never a repeat every day).
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from functools import partial
from pathlib import Path

from dnslib import DNSRecord, QTYPE

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from aifilter import probe  # noqa: E402
from scripts.healthcheck import save_state, send_alert  # noqa: E402

BLOCK_MARK = "/__ai-filter/appeal"
DNS_BLOCKED = ("pornhub.com", "bet365.com")
DNS_SAFE = {"www.google.com": "forcesafesearch.google.com", "www.google.co.il": "forcesafesearch.google.com",
            "www.bing.com": "strict.bing.com", "duckduckgo.com": "safe.duckduckgo.com"}
DNS_OPEN = ("apple.com", "web.whatsapp.com")
PAGE_BLOCKED = ("http://bet365.com/", "http://pornhub.com/")
PAGE_OPEN = ("https://www.google.com/", "https://www.apple.com/", "https://web.whatsapp.com/")
IP_LITERAL = "https://1.1.1.1/"  # reachable, and outside the approved address ranges


def dns_answer(name: str, port: int, timeout: float = 4.0, *, host: str = "127.0.0.1") -> tuple[set, set]:
    """(A addresses, CNAME targets) from the local DNS filter."""
    query = probe.dns_query(name) if name in DNS_BLOCKED else DNSRecord.question(name)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query.pack(), (host, port))
        reply = DNSRecord.parse(sock.recv(4096))
    return ({str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A},
            {str(rr.rdata).rstrip(".").lower() for rr in reply.rr if rr.rtype == QTYPE.CNAME})


def fetch(url: str, port: int, cacert: str, timeout: int = 20, *, host: str = "127.0.0.1") -> tuple[str, str]:
    """(http status, first 64 KiB of body) through the local proxy; status '000' on failure."""
    # Only the deliberately blocked pages carry the marker (curl reads it from stdin, never argv).
    value = probe.token(create=True) if url in PAGE_BLOCKED else b""
    marker = ["-H", "@-"] if value else []
    out = subprocess.run(
        ["/usr/bin/curl", "--noproxy", "", "-s", "-m", str(timeout), "--max-filesize", "4000000", "-H", "Accept: text/html",
         "-A", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
         "-x", f"http://{host}:{port}", "--cacert", cacert, "-w", "\n%{http_code}", *marker, url],
        input=probe.HEADER.encode() + b": " + value + b"\n" if value else None,
        capture_output=True, timeout=timeout + 5)
    text = out.stdout.decode("utf-8", "replace")
    body, _, code = text.rpartition("\n")
    return code.strip() or "000", body[:65536]


def connect_code(url: str, port: int, timeout: int = 10, *, host: str = "127.0.0.1") -> str:
    """The proxy's own answer to CONNECT (curl reports it apart from the page status)."""
    out = subprocess.run(["/usr/bin/curl", "--noproxy", "", "-s", "-o", "/dev/null", "-m", str(timeout),
                          "-x", f"http://{host}:{port}", "-w", "%{http_connect}", url],
                         capture_output=True, timeout=timeout + 5)
    return out.stdout.decode("ascii", "replace").strip() or "000"


def run_cases(proxy_port: int, dns_port: int, cacert: str, *, dns=dns_answer, get=fetch, connect=connect_code) -> list[str]:
    """Names of the failed cases (empty list = everything holds)."""
    failed = []

    def case(name, check):
        try:
            if not check():
                failed.append(name)
        except Exception as exc:  # noqa: BLE001 - a crashed probe is a failed case, never a crashed self-test
            failed.append(f"{name} ({type(exc).__name__})")

    for host in DNS_BLOCKED:
        case(f"dns-block {host}", lambda host=host: dns(host, dns_port)[0] == {"0.0.0.0"})
    for host, safe in DNS_SAFE.items():
        case(f"dns-safe {host}", lambda host=host, safe=safe: safe in dns(host, dns_port)[1])
    for host in DNS_OPEN:
        case(f"dns-open {host}", lambda host=host: bool(dns(host, dns_port)[0] - {"0.0.0.0"}))
    for url in PAGE_BLOCKED:
        def blocked(url=url):
            code, body = get(url, proxy_port, cacert)
            return code == "403" and BLOCK_MARK in body
        case(f"page-block {url}", blocked)
    for url in PAGE_OPEN:
        case(f"page-open {url}", lambda url=url: get(url, proxy_port, cacert)[0] in {"200", "301", "302"})
    case("ip-literal refused", lambda: connect(IP_LITERAL, proxy_port) == "403")
    return failed


def report(failed: list[str], state_file: Path, notify, *, retried: bool) -> None:
    try:
        previous = json.loads(state_file.read_text()).get("failed", [])
    except (OSError, ValueError, AttributeError):
        previous = []
    if failed == previous:
        return
    if notify:
        if failed:
            # Hebrew line, then the technical names on their own lines (never mixed on one line).
            notify("סינון: הבדיקה היומית מצאה " + str(len(failed)) + " בדיקות שנכשלו:\n" + "\n".join(failed))
        else:
            notify("סינון: הבדיקה היומית חזרה לעבור במלואה.")
    save_state(state_file, {"failed": failed, "retried": retried})


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--notify", action="store_true")
    ap.add_argument("--proxy-host", default="127.0.0.1")
    ap.add_argument("--dns-host", default="127.0.0.1")
    ap.add_argument("--proxy-port", type=int, default=8118)
    ap.add_argument("--dns-port", type=int, default=53)
    ap.add_argument("--cacert", default=str(Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"))
    ap.add_argument("--state-file", type=Path, default=ROOT / "data" / "selftest.json")
    args = ap.parse_args(argv)
    probes = {"dns": partial(dns_answer, host=args.dns_host),
              "get": partial(fetch, host=args.proxy_host),
              "connect": partial(connect_code, host=args.proxy_host)}
    failed = run_cases(args.proxy_port, args.dns_port, args.cacert, **probes)
    retried = False
    if failed:  # one retry a minute later: a network blip must not page the owner
        import time
        time.sleep(60)
        failed, retried = run_cases(args.proxy_port, args.dns_port, args.cacert, **probes), True
    report(failed, args.state_file, send_alert if args.notify else None, retried=retried)
    print("selftest:", "all cases pass" if not failed else "FAILED: " + "; ".join(failed), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
