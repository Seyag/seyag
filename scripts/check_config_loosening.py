#!/usr/bin/env python3
"""Reject known config loosening unless the commit records a confirmed request.

Usage: check_config_loosening.py <base> [head].  CI should compare the PR base
with its head; the confirmation trailer is deliberately explicit and auditable:
``Confirmed-Loosening-Request: <request-id>``.
"""
import subprocess
import sys
import tomllib


SCALARS = (("youtube", "ai_check"), ("youtube", "music_without_approval"),
           ("x", "enabled"), ("apps", "ai_judge"))
LISTS = (("schedule", "night_allow"), ("passthrough", "hosts"), ("appapi", "owners"))
# Carve-out lists: removing an entry re-opens a host under a broader allow/passthrough parent.
CARVE_OUTS = (("passthrough", "inspect_hosts"), ("schedule", "night_except"))


def git(*args: str) -> str:
    return subprocess.run(("git", *args), check=True, capture_output=True, text=True).stdout


def config_at(rev: str) -> dict:
    return tomllib.loads(git("show", f"{rev}:config.toml"))


def loosenings(old: dict, new: dict) -> list[str]:
    out = []
    if (old.get("youtube", {}).get("modesty_mode", "strict") != "calibrated"
            and new.get("youtube", {}).get("modesty_mode", "strict") == "calibrated"):
        out.append("youtube.modesty_mode=calibrated")
    for section, key in SCALARS:
        before, after = old.get(section, {}).get(key), new.get(section, {}).get(key)
        if before is not True and after is True:
            out.append(f"{section}.{key}")
    for section, key in LISTS:
        before = set(old.get(section, {}).get(key, []))
        added = set(new.get(section, {}).get(key, [])) - before
        out.extend(f"{section}.{key}+={item}" for item in sorted(added))
    for section, key in CARVE_OUTS:
        removed = set(old.get(section, {}).get(key, [])) - set(new.get(section, {}).get(key, []))
        out.extend(f"{section}.{key}-={item}" for item in sorted(removed))
    before = set(old.get("schedule", {}).get("work", {}).get("exempt_devices", []) or [])
    after = set(new.get("schedule", {}).get("work", {}).get("exempt_devices", []) or [])
    out.extend(f"schedule.work.exempt_devices+={item}" for item in sorted(after - before))
    return out


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not 1 <= len(argv) <= 2:
        print("usage: check_config_loosening.py BASE [HEAD]", file=sys.stderr)
        return 2
    base, head = argv[0], argv[1] if len(argv) == 2 else "HEAD"
    loose = loosenings(config_at(base), config_at(head))
    if not loose:
        return 0
    messages = git("log", "--format=%B", f"{base}..{head}")
    if not any(line.startswith("Confirmed-Loosening-Request: ") and line.split(":", 1)[1].strip()
               for line in messages.splitlines()):
        print("config loosening lacks Confirmed-Loosening-Request trailer: " + ", ".join(loose),
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
