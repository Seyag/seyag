#!/usr/bin/env python3
"""Bounded, launchd-friendly health checks for the local proxy and PAC server."""

from __future__ import annotations

import argparse
import fcntl
import http.client
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

from dnslib import DNSRecord, QTYPE, RCODE


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from aifilter import probe  # noqa: E402
from aifilter.export_settings import bridge_executable  # noqa: E402
DEFAULT_TARGET = "www.apple.com:443"  # Curated passthrough: verify real upstream TLS, no HTTP page fetch.
OUTAGE_SECONDS = 300
MAX_PAC_BYTES = 1024 * 1024
DEFAULT_STATE = ROOT / "data" / "healthcheck.json"
DEFAULT_PAC_FILE = ROOT / "pac" / "proxy.pac"
BLOCK_CANARY = "bet365.com"  # blocked by the installed gambling lists


def parse_target(value: str) -> tuple[str, int]:
    """Parse a host:port CONNECT destination and reject request-line injection."""
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or any(c in host for c in "\r\n /\t"):
        raise argparse.ArgumentTypeError("target must be host:port")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("target port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("target port must be between 1 and 65535")
    return host, port


def probe_tls(sock, host, timeout):
    # Lazy mitmproxy can answer CONNECT 200 before opening an upstream socket.
    # A verified TLS handshake through that tunnel proves the upstream path too.
    context = ssl.create_default_context()
    sock.settimeout(timeout)
    with context.wrap_socket(sock, server_hostname=host.strip('[]')):
        pass


def check_proxy_connect(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8118,
    target: str = DEFAULT_TARGET,
    timeout: float = 5.0,
    *,
    connect: Callable = socket.create_connection,
    tls_probe: Callable = probe_tls,
) -> tuple[bool, str]:
    """Open a real HTTP CONNECT tunnel through the local proxy, with bounded I/O."""
    try:
        host, port = parse_target(target)
        with connect((proxy_host, proxy_port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            request = (
                f"CONNECT {host}:{port} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(request)
            deadline = time.monotonic() + timeout
            response = bytearray()
            while b"\r\n\r\n" not in response and len(response) < 8192:
                sock.settimeout(max(.001, deadline - time.monotonic()))
                if time.monotonic() >= deadline:
                    raise TimeoutError("CONNECT header deadline")
                part = sock.recv(min(1024, 8192 - len(response)))
                if not part:
                    break
                response.extend(part)
            # Validate the HTTP response before starting TLS inside the same tunnel.
            first_line = bytes(response).split(b"\r\n", 1)[0]
            fields = first_line.split()
            if len(fields) < 2 or fields[0].startswith(b"HTTP/") is False:
                return False, "proxy returned an invalid CONNECT response"
            if fields[1] != b"200":
                return False, "proxy CONNECT status was not 200"
            if b"\r\n\r\n" not in response:
                return False, "proxy CONNECT response was incomplete"
            tls_probe(sock, host, timeout)
            return True, "CONNECT and verified upstream TLS succeeded"
    except (OSError, ValueError, UnicodeError, argparse.ArgumentTypeError) as exc:
        return False, f"proxy CONNECT failed: {type(exc).__name__}"


def check_pac(
    expected: bytes,
    pac_host: str = "127.0.0.1",
    pac_port: int = 8119,
    timeout: float = 5.0,
    *,
    connection_factory: Callable = http.client.HTTPConnection,
) -> tuple[bool, str]:
    """GET /proxy.pac and require an exact match with the checked-in PAC file."""
    connection = None
    try:
        if len(expected) > MAX_PAC_BYTES:
            return False, "expected PAC file exceeds size limit"
        connection = connection_factory(pac_host, pac_port, timeout=timeout)
        connection.request("GET", "/proxy.pac", headers={"Connection": "close"})
        response = connection.getresponse()
        if response.status != 200:
            return False, f"PAC HTTP status was {response.status}"
        body = response.read(MAX_PAC_BYTES + 1)
        if len(body) > MAX_PAC_BYTES:
            return False, "served PAC file exceeds size limit"
        if body != expected:
            return False, "served PAC contents differ from the expected file"
        return True, "PAC contents match"
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return False, f"PAC request failed: {type(exc).__name__}"
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass


def check_dns(host: str, port: int, timeout: float, name: str = "apple.com") -> tuple[bool, str]:
    """Require both useful resolution and a positive proof of local blocking."""
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            for target, blocked in ((name, False), (BLOCK_CANARY, True)):
                # The canary carries the probe marker so it stays out of the family report.
                query = probe.dns_query(target) if blocked else DNSRecord.question(target)
                sock.send(query.pack())
                reply = DNSRecord.parse(sock.recv(4096))
                if (reply.header.id != query.header.id or not reply.header.qr or reply.header.tc
                        or reply.header.rcode != RCODE.NOERROR or reply.questions != query.questions):
                    return False, "DNS reply invalid or failed"
                addresses = {str(rr.rdata) for rr in reply.rr if rr.rtype == QTYPE.A}
                if blocked:
                    if addresses != {"0.0.0.0"}:
                        return False, "DNS block canary did not return 0.0.0.0"
                elif not addresses or not all(ipaddress.ip_address(addr).is_global for addr in addresses):
                    return False, "DNS normal name did not resolve to a real address"
    except Exception as exc:  # malformed DNS is an unhealthy probe, never a crashed watchdog
        return False, f"DNS query failed: {type(exc).__name__}"
    return True, "DNS resolution and block canary succeeded"


def check_home_dhcp(plist: Path = Path("/Library/LaunchDaemons/com.example.home-dhcp.plist")) -> tuple[bool, str] | None:
    """The Mac hands out home addresses once enabled; None when the feature is not installed."""
    if not plist.exists():
        return None
    try:
        found = subprocess.run(["/usr/bin/pgrep", "-f", "dnsmasq.*home-dhcp"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot check home DHCP: {type(exc).__name__}"
    return (True, "home DHCP running") if found else (False, "home DHCP service is not running")


def announced_v6_dns(iface: str = "en1") -> list[str]:
    """Global IPv6 DNS servers the network hands this Mac by DHCPv6 (empty when none or unknown)."""
    try:
        out = subprocess.run(["/usr/sbin/ipconfig", "getv6packet", iface], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for token in re.findall(r"[0-9a-fA-F:]{3,39}", " ".join(re.findall(r"DNS_SERVERS.*?:\s*(.+)", out))):
        try:
            ip = ipaddress.IPv6Address(token)
        except ValueError:
            continue
        if ip.is_global:
            found.append(str(ip))
    return found


def check_home_v6(
    plist: Path = Path("/Library/LaunchDaemons/com.example.home-v6guard.plist"),
    state: Path = Path("/var/db/home-v6guard.json"),
    port: int = 53,
    timeout: float = 3.0,
    probe: Callable = check_dns,
) -> tuple[bool, str] | None:
    """The IPv6 guard answers on the router's IPv6 DNS address; None when it is not installed."""
    if not plist.exists():
        return None
    try:
        running = subprocess.run(["/usr/bin/pgrep", "-f", "v6guard.py"], capture_output=True, timeout=5).returncode == 0
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot check IPv6 guard: {type(exc).__name__}"
    if not running:
        return False, "IPv6 guard is not running"
    try:
        addrs = [str(ipaddress.IPv6Address(a)) for a in json.loads(state.read_text())["addrs"]][:4]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return False, f"IPv6 guard state unreadable: {type(exc).__name__}"
    if not addrs:
        announced = announced_v6_dns()
        if announced:
            return False, f"router announces IPv6 DNS {announced[0]} but the guard holds no address"
    for addr in addrs:
        ok, message = probe(addr, port, timeout)
        if not ok:
            return False, f"IPv6 DNS takeover not filtering: {message}"
    return True, f"IPv6 guard running; {len(addrs)} router DNS address(es) filtered"


def _fresh_service_state() -> dict:
    return {
        "failure_since": None,
        "down_attempted": False,
        "down_sent": False,
        "recovery_attempted": False,
    }


def fresh_state() -> dict:
    return {"version": 1, "services": {"proxy": _fresh_service_state(), "pac": _fresh_service_state(), "filter": _fresh_service_state()}}


def load_state(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
        if len(raw) > 64 * 1024:
            return fresh_state()
        state = json.loads(raw)
        if state.get("version") != 1 or not isinstance(state.get("services"), dict):
            return fresh_state()
        for name in ("proxy", "pac", "filter"):
            current = state["services"].get(name)
            if (
                not isinstance(current, dict)
                or (current.get("failure_since") is not None and not isinstance(current.get("failure_since"), (int, float)))
                or any(not isinstance(current.get(key, False), bool) for key in ("down_attempted", "down_sent", "recovery_attempted"))
            ):
                state["services"][name] = _fresh_service_state()
            else:
                defaults = _fresh_service_state()
                defaults.update({key: current.get(key, value) for key, value in defaults.items()})
                state["services"][name] = defaults
        return state
    except (OSError, ValueError, TypeError, AttributeError):
        return fresh_state()


def save_state(path: Path, state: dict) -> bool:
    """Atomically persist small state with owner-only permissions."""
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as stream:
            temporary = Path(stream.name)
            os.fchmod(stream.fileno(), 0o600)
            json.dump(state, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        return True
    except OSError:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return False


def send_alert(message: str, timeout: float = 8.0) -> bool:
    """Use the existing appeal-session mirror hook; never block beyond timeout."""
    command = bridge_executable()
    if command is None:
        return False
    try:
        result = subprocess.run(
            [command, "mirror", "--title", "סינון: בדיקת שירות", "--session", "ai-filter-appeals", "--no-translate"],
            input=message,
            text=True,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _deliver(notifier: Callable[[str], bool], message: str) -> bool:
    """A broken notification adapter must never abort a healthcheck run."""
    try:
        return bool(notifier(message))
    except Exception:
        return False


def update_service(
    state: dict,
    name: str,
    ok: bool,
    detail: str,
    now: float,
    *,
    notify: bool,
    state_path: Path,
    notifier: Callable[[str], bool] = send_alert,
    outage_seconds: int = OUTAGE_SECONDS,
) -> str:
    """Advance one service's persistent alert state and return a short status."""
    service = state["services"][name]
    event = ""
    if ok:
        if service["failure_since"] is not None and service["down_sent"] and notify and not service["recovery_attempted"]:
            service["recovery_attempted"] = True
            if save_state(state_path, state):
                event = "recovery alert sent" if _deliver(notifier, f"סינון: שירות {name} חזר לפעול.") else "recovery alert failed"
            else:
                event = "recovery alert skipped: state could not be saved"
        service["failure_since"] = None
        service["down_attempted"] = False
        service["down_sent"] = False
        if not save_state(state_path, state):
            return f"{name}: healthy; state could not be saved"
        return f"{name}: healthy{'; ' + event if event else ''}"

    if service["failure_since"] is None:
        service["failure_since"] = now
        service["down_attempted"] = False
        service["down_sent"] = False
        service["recovery_attempted"] = False
    elapsed = max(0.0, now - float(service["failure_since"]))
    if elapsed >= outage_seconds and notify and not service["down_attempted"]:
        # Persist the one-shot claim before invoking the external command. This
        # prevents restarts from sending duplicate alerts if delivery is ambiguous.
        service["down_attempted"] = True
        if save_state(state_path, state):
            message = f"סינון: שירות {name} אינו זמין כבר יותר מ-5 דקות. {detail}"
            sent = _deliver(notifier, message)
            service["down_sent"] = sent
            save_state(state_path, state)
            event = "down alert sent" if sent else "down alert failed (one attempt)"
        else:
            service["down_attempted"] = False
            event = "down alert skipped: state could not be saved"
    if not save_state(state_path, state):
        return f"{name}: down for {int(elapsed)}s; state could not be saved"
    return f"{name}: down for {int(elapsed)}s{'; ' + event if event else ''}"


def bounded_timeout(value: str) -> float:
    number = float(value)
    if not 0.1 <= number <= 10:
        raise argparse.ArgumentTypeError("timeout must be between 0.1 and 10 seconds")
    return number


def positive_interval(value: str) -> float:
    number = float(value)
    if not 1 <= number <= 3600:
        raise argparse.ArgumentTypeError("interval must be between 1 and 3600 seconds")
    return number


def _run_once(args: argparse.Namespace, *, now: Callable[[], float] = time.time, notifier: Callable = send_alert) -> list[str]:
    state = load_state(args.state_file)
    try:
        expected = args.pac_file.read_bytes()
        if len(expected) > MAX_PAC_BYTES:
            raise OSError("expected PAC file exceeds size limit")
    except OSError as exc:
        expected = b""
        pac_file_error = type(exc).__name__
    else:
        pac_file_error = ""

    checks = {
        "proxy": check_proxy_connect(args.proxy_host, args.proxy_port, args.connect_target, args.timeout),
        "pac": (False, f"expected PAC file unavailable: {pac_file_error}")
        if pac_file_error
        else check_pac(expected, args.pac_host, args.pac_port, args.timeout),
    }
    if getattr(args, "dns_port", 0):
        checks["dns"] = check_dns(getattr(args, "dns_host", "127.0.0.1"), args.dns_port, args.timeout)
    if getattr(args, "home_dhcp", False):
        dhcp = check_home_dhcp()
        if dhcp is not None:
            checks["home-dhcp"] = dhcp
        v6 = check_home_v6(timeout=args.timeout)
        if v6 is not None:
            checks["home-v6"] = v6
    # One incident, even when proxy and PAC fail together.
    ok = all(result[0] for result in checks.values())
    detail = "; ".join(f"{name}: {message}" for name, (healthy, message) in checks.items() if not healthy)
    status = update_service(state, "filter", ok, detail, now(), notify=args.notify,
                            state_path=args.state_file, notifier=notifier)
    return [status] + [f"{name}: {'healthy' if healthy else 'down'}; {message}"
                       for name, (healthy, message) in checks.items()]


def run_once(args, **kwargs):
    # A launchd one-shot and a manual --watch cannot both claim the same alert.
    try:
        args.state_file.parent.mkdir(parents=True, exist_ok=True)
        with open(args.state_file.with_suffix('.lock'), 'a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return ['healthcheck already running']
            return _run_once(args, **kwargs)
    except OSError as exc:
        return [f'healthcheck state unavailable: {type(exc).__name__}']


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="run one check (the default)")
    parser.add_argument("--watch", action="store_true", help="repeat until interrupted")
    parser.add_argument("--interval", type=positive_interval, default=120, help="watch interval in seconds (default: 120)")
    parser.add_argument("--notify", action="store_true", help="send down/recovery alerts to the appeal session")
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--pac-file", type=Path, default=DEFAULT_PAC_FILE)
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8118)
    parser.add_argument("--connect-target", type=str, default=DEFAULT_TARGET)
    parser.add_argument("--pac-host", default="127.0.0.1")
    parser.add_argument("--pac-port", type=int, default=8119)
    parser.add_argument("--timeout", type=bounded_timeout, default=5.0)
    parser.add_argument("--dns-port", type=int, default=0, help="also check the home DNS filter on this port (0 = skip)")
    parser.add_argument("--dns-host", default="127.0.0.1")
    parser.add_argument("--home-dhcp", action="store_true", help="also check the home DHCP service when installed")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = make_parser().parse_args(argv)
    if args.watch:
        while True:
            started = time.monotonic()
            for result in run_once(args):
                print(result, flush=True)
            time.sleep(max(0.0, args.interval - (time.monotonic() - started)))
    for result in run_once(args):
        print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
