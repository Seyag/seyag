#!/usr/bin/env python3
"""Usage: .venv/bin/python scripts/yt_channels.py list | add <UC id, channel link, @handle or video link> [--name N] | remove <UC id>

The committee's list of YouTube channels whose videos may play (aifilter/ytgate.py). Every other YouTube video
stays blocked. Edits data/youtube-channels.json atomically; the running filter picks it up by itself.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aifilter.ytgate import CHANNELS_FILE  # noqa: E402

UC = re.compile(r"UC[A-Za-z0-9_-]{22}")
_PAGE_ID = [re.compile(r'<link rel="canonical" href="https://www\.youtube\.com/channel/(UC[A-Za-z0-9_-]{22})"'),
            re.compile(r'"externalId":"(UC[A-Za-z0-9_-]{22})"'),
            re.compile(r'itemprop="channelId" content="(UC[A-Za-z0-9_-]{22})"'),
            re.compile(r'"channelId":"(UC[A-Za-z0-9_-]{22})"')]
_TITLE = re.compile(r'<meta property="og:title" content="([^"]{1,120})"')


def load(path: Path = CHANNELS_FILE) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save(data: dict, path: Path = CHANNELS_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)


_YT_HOSTS = ("youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be")


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "he,en"})
    with urllib.request.urlopen(req, timeout=20) as r:
        final = urllib.parse.urlsplit(r.geturl())
        if final.scheme != "https" or (final.hostname or "").lower() not in _YT_HOSTS:
            raise ValueError("redirected away from youtube.com")
        return r.read(3_000_000).decode("utf-8", "ignore")


def resolve(ref: str, fetch=_fetch) -> tuple[str, str]:
    """(channel id, channel name) for a UC id, channel link, @handle or video link."""
    ref = ref.strip()
    if UC.fullmatch(ref):
        return ref, ""
    if ref.startswith("@"):
        ref = "https://www.youtube.com/" + urllib.parse.quote(ref)
    parts = urllib.parse.urlsplit(ref)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in _YT_HOSTS:
        raise ValueError("give a UC channel id, an @handle or a youtube.com / youtu.be link")
    page = fetch(ref)
    for rx in _PAGE_ID:
        if m := rx.search(page):
            t = _TITLE.search(page)
            return m.group(1), (t.group(1) if t else "")
    raise ValueError("no channel id found on that page")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    a = sub.add_parser("add"); a.add_argument("ref"); a.add_argument("--name", default="")
    r = sub.add_parser("remove"); r.add_argument("channel")
    args = ap.parse_args(argv)
    data = load()
    if args.cmd == "add":
        try:
            cid, name = resolve(args.ref)
        except (OSError, ValueError) as exc:
            print(json.dumps({"error": str(exc)[:200]}, ensure_ascii=False))
            return 1
        data[cid] = (args.name or name or cid)[:120]
        save(data)
        print(json.dumps({"added": cid, "name": data[cid], "count": len(data)}, ensure_ascii=False))
    elif args.cmd == "remove":
        gone = data.pop(args.channel, None)
        save(data)
        print(json.dumps({"removed": args.channel if gone is not None else None, "count": len(data)}))
    else:
        print(json.dumps(data, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
