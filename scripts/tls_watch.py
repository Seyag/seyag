"""Usage: .venv/bin/python scripts/tls_watch.py [--dry-run]  -- finds apps the filter breaks (TLS failures) before the owner does.

Run every 15 minutes by launchd (deploy/com.example.ai-filter-tlswatch.plist). For each host that failed
inspection since the last run and is not already passed through:
  * Apple-only service (its domain's name servers are all Apple's, or every address is in Apple's 17.0.0.0/8):
    added to the passthrough table automatically, logged as an "auto-passthrough" event.
  * anything else that failed at least MIN_FAILS times: reported once to the owner ledger for a committee decision
    (never passed through automatically: default deny).
"""
from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from aifilter import config  # noqa: E402
from aifilter.schedules import host_listed  # noqa: E402
from aifilter.store import Store  # noqa: E402
from aifilter.suffixes import registrable  # noqa: E402

APPLE_NET = ipaddress.ip_network("17.0.0.0/8")
MIN_FAILS = 3
LEDGER = None


def _dig(name: str, rtype: str) -> list[str]:
    try:
        out = subprocess.run(["dig", "+short", "+time=3", "+tries=1", "@1.1.1.1", name, rtype],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [line.strip().rstrip(".").lower() for line in out.splitlines() if line.strip()]


def apple_scope(host: str, dig=_dig) -> str | None:
    """The name to pass through when host is an Apple-only service: its whole domain when Apple runs the
    domain's name servers, only the host when merely its addresses are Apple's; None otherwise."""
    ns = dig(registrable(host), "NS")
    if ns and all(n == "apple.com" or n.endswith(".apple.com") for n in ns):
        return registrable(host)
    ips = []
    for ans in dig(host, "A"):
        try:
            ips.append(ipaddress.ip_address(ans))
        except ValueError:
            pass  # CNAME step
    return host if ips and all(ip in APPLE_NET for ip in ips) else None


def static_passthrough() -> list[str]:
    return config.load(ROOT / "config.toml").get("passthrough", "hosts", [])


def inspect_hosts() -> list[str]:
    return config.load(ROOT / "config.toml").get("passthrough", "inspect_hosts", [])


def covered(host: str, suffixes) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def run(store: Store, state_file: Path, dig=_dig, report=None, dry=False) -> dict:
    state = json.loads(state_file.read_text()) if state_file.exists() else {"since": 0, "reported": []}
    suffixes = list(static_passthrough()) + list(store.passthrough_hosts())
    carved = inspect_hosts()
    result = {"auto": [], "reported": []}
    for host, count, last in store.tls_failures():
        inspected = host_listed(host, carved)  # deliberately decrypted under a pinned parent: report, never auto-pass
        if last <= state["since"] or (covered(host, suffixes) and not inspected):
            continue
        target = None if inspected else apple_scope(host, dig)
        if target:
            if not dry:
                store.add_passthrough(target, "auto: Apple-only service failed inspection")
            suffixes.append(target)
            result["auto"].append(target)
        elif count >= MIN_FAILS and registrable(host) not in state["reported"]:
            result["reported"].append(host)
            if not dry:
                state["reported"].append(registrable(host))
                (report or _ledger)(host, count)
    counts = state.get("connect_counts", {})
    reported = state.get("connect_reported", [])
    current = {}
    for host, count, last, detail in store.connect_failures():
        current[host] = count
        previous = counts.get(host, 0)
        new_count = count - previous if count >= previous else count
        if new_count >= MIN_FAILS and host not in reported:
            result["reported"].append(host)
            if not dry:
                (report or _ledger)(host, new_count, detail)
                reported.append(host)
    # Proxy-level errors that freeze browsing for everyone (2026-11-12: open-files limit hit).
    log = config.db_path().parent / "proxy.log"
    size = log.stat().st_size if log.exists() else 0
    offset = state.get("proxy_log_offset", 0) if state.get("proxy_log_offset", 0) <= size else 0
    if log.exists():
        with log.open("rb") as fh:
            fh.seek(offset)
            fresh = fh.read().decode("utf-8", "replace")
        for marker, label in (("Too many open files", "proxy ran out of open files"),
                              ("MemoryError", "proxy ran out of memory")):
            n = fresh.count(marker)
            if n:
                result["reported"].append(label)
                if not dry:
                    (report or _ledger)("ai-filter proxy", n, label)
    if not dry:
        state["proxy_log_offset"] = size
        state["connect_counts"] = current
        state["connect_reported"] = reported
        state["since"] = time.time()
        state_file.write_text(json.dumps(state))
    return result


def _ledger(host: str, count: int, detail: str | None = None):
    if LEDGER is not None and LEDGER.exists():
        message = (f"cannot reach {host} ({count}x): {detail}" if detail is not None else
                   f"tls-watch: an app on a filtered device fails through the filter at {host} ({count}x). "
                   "Committee: allow untouched (passthrough) or block cleanly")
        subprocess.run([str(LEDGER), "ai-filter", "add",
                        message], capture_output=True, timeout=20)


if __name__ == "__main__":
    out = run(Store(config.db_path()), config.db_path().parent / "tls-watch.json", dry="--dry-run" in sys.argv)
    print(time.strftime("%F %T"), json.dumps(out))
    if "--dry-run" not in sys.argv:
        try:
            from scripts import browse_probe
            browse_probe.run(config.db_path().parent)
        except Exception as exc:
            print(f"browse check failed: {exc}", file=sys.stderr)
