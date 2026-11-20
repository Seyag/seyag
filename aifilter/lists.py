"""Download the community blocklists into the store.

Run:  .venv/bin/python -m aifilter.lists
Lists are plain text, one domain per line (a listed domain covers its subdomains).
"""

import re
import sys
import urllib.request

from aifilter import config
from aifilter.store import Store

_DOMAIN = re.compile(r"^(?:\*\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)$")


def parse(lines, name):
    for line in lines:
        line = line.strip().lower()
        if not line or line.startswith(("#", "!")):
            continue
        m = _DOMAIN.match(line)
        if m:
            yield m.group(1), name


def fetch(url: str) -> list[str]:
    req = urllib.request.Request(url, headers={"user-agent": "ai-filter/0.1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", "replace").splitlines()


def update(store: Store, lists: dict[str, str]) -> int:
    entries = []
    for name, url in lists.items():
        lines = fetch(url)  # raises on failure: never replace good lists with nothing
        before = len(entries)
        entries.extend(parse(lines, name))
        if len(entries) - before < 1000:
            raise RuntimeError(f"list {name} looks broken ({len(entries) - before} domains)")
    count = store.replace_blocklists(entries)
    store.log("blocklists", "", f"{count} domains from {', '.join(lists)}")
    return count


if __name__ == "__main__":
    cfg = config.load()
    n = update(Store(config.db_path()), cfg.get("blocklists", "urls", {}))
    print(f"{n} domains loaded", file=sys.stderr)
