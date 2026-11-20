"""Usage: committee_decide.py <id> <approved|declined|waiting> --note <text> [--earliest <ISO>]"""
from __future__ import annotations

import argparse
from datetime import datetime

from aifilter import config
from aifilter.store import Store


def iso_timestamp(value: str) -> str:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an ISO timestamp") from exc
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(usage=__doc__)
    parser.add_argument("id", type=int)
    parser.add_argument("status", choices=("approved", "declined", "waiting"))
    parser.add_argument("--note", required=True)
    parser.add_argument("--earliest", type=iso_timestamp)
    args = parser.parse_args(argv)
    store = Store(config.db_path())
    try:
        found = store.decide_committee_request(args.id, args.status, args.note, args.earliest)
    except ValueError as exc:
        parser.error(str(exc))
    if not found:
        parser.error(f"committee request {args.id} does not exist")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
