#!/usr/bin/env python3
"""Issue or revoke a Telegram media-verdict bearer token."""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aifilter import config  # noqa: E402
from aifilter.media_verdict import MediaStore  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("issue", "revoke"):
        command = sub.add_parser(action)
        command.add_argument("device", help="stable device name")
    args = parser.parse_args()
    store = MediaStore(config.db_path())
    if args.action == "issue":
        print(store.issue(args.device))  # the only time the plaintext token exists in output
    elif not store.revoke(args.device):
        parser.error(f"no token found for device {args.device!r}")


if __name__ == "__main__":
    main()
