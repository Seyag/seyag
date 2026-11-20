"""Daily housekeeping, run by run.sh at startup and once a day.

  - prune events and cached image verdicts older than 60 days, expired strikes
    and temporary approvals that ended more than 60 days ago;
  - rotate data/*.log files over 5 MB (copy to .log.1, then truncate in place,
    so writers that keep the file open in append mode continue cleanly).

Run:  .venv/bin/python -m aifilter.maintenance
"""

import shutil
import sys
import time
from pathlib import Path

from aifilter import config
from aifilter.store import Store

KEEP_DAYS = 60
MAX_LOG_BYTES = 5_000_000


def prune(store: Store, keep_days: float = KEEP_DAYS, strike_days: float = 7) -> dict[str, int]:
    now = time.time()
    cut = now - keep_days * 86400
    counts = {}
    for name, sql, args in (
        ("events", "DELETE FROM events WHERE ts < ?", (cut,)),
        ("images", "DELETE FROM images WHERE updated < ?", (cut,)),
        ("strikes", "DELETE FROM bad_image_strikes WHERE ts < ?", (now - strike_days * 86400,)),
        ("overrides", "DELETE FROM overrides WHERE expires < ?", (cut,)),
    ):
        with store._lock:
            counts[name] = store._db.execute(sql, args).rowcount
    return counts


def rotate_logs(folder: Path, max_bytes: int = MAX_LOG_BYTES) -> list[str]:
    rotated = []
    for log in sorted(folder.glob("*.log")):
        try:
            if log.stat().st_size <= max_bytes:
                continue
            shutil.copyfile(log, log.with_suffix(".log.1"))
            with open(log, "r+b") as f:
                f.truncate(0)
            rotated.append(log.name)
        except OSError as e:
            print(f"maintenance: cannot rotate {log.name}: {e}", file=sys.stderr)
    return rotated


def main() -> int:
    cfg = config.load()
    store = Store(config.db_path())
    counts = prune(store, strike_days=cfg.get("policy", "strike_days", 7))
    rotated = rotate_logs(config.ROOT / "data")
    print(time.strftime("%F %T"), "pruned", counts, "rotated", rotated or "-", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
