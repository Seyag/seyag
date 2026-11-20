"""Weekly accountability report: what the filter and the committee did (to WhatsApp).

  report.py            print this week's report
  report.py --send     send it to a configured WhatsApp chat
  report.py --if-due   send only when the last report is older than report.every_days
"""

import argparse
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from aifilter import config  # noqa: E402
from aifilter.export_settings import bridge_executable  # noqa: E402
from aifilter.store import Store  # noqa: E402

STAMP = ROOT / "data" / "report.stamp"


def build(store: Store, days: float = 7) -> str:
    since = time.time() - days * 86400
    events = [e for e in store.events(200_000) if e[0] >= since]
    kinds = Counter(k for _t, k, _h, _d in events)
    blocked_hosts = Counter(h for _t, k, h, _d in events if k in ("page-blocked", "dns-blocked") and h)
    committee = [(h, d) for _t, k, h, d in events if k == "verdict" and "committee:" in (d or "")]
    appeals = [h for _t, k, h, _d in events if k == "appeal"]

    lines = [f"דוח סינון שבועי ({time.strftime('%d.%m', time.localtime(since))}-{time.strftime('%d.%m')})", ""]
    lines.append(f"תמונות שהוסתרו: {kinds['image-blocked']}")
    lines.append(f"אתרים שנחסמו בכניסה: {kinds['page-blocked'] + kinds['dns-blocked']}")
    lines.append(f"סרטונים שנחסמו: {kinds['video-blocked']}")
    lines.append(f"בקשות לפתיחת אתר: {len(appeals)}")
    if committee:
        lines += ["", "החלטות הוועדה:"]
        for host, det in committee[:15]:
            verdict = "נפתח" if det.startswith("allow") else "נדחה"
            lines.append(f"- {host}: {verdict} ({det.split('committee:', 1)[1].strip()[:80]})")
    if blocked_hosts:
        lines += ["", "האתרים שנחסמו הכי הרבה:"]
        lines += [f"- {h} ({n})" for h, n in blocked_hosts.most_common(5)]
    return "\n".join(lines)


def send(text: str) -> bool:
    """Deliver only through an explicitly configured notification adapter."""
    command = bridge_executable()
    if command is None:
        return False
    try:
        out = subprocess.run(
            [command, "mirror", "--title", "סינון: דוח שבועי", "--session", "ai-filter-weekly-report", "--no-translate"],
            input=text, capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"report: telegram fallback failed: {e}", file=sys.stderr)
        return False
    if out.returncode != 0:
        print(f"report: telegram fallback rc={out.returncode}: {out.stderr[-300:]}", file=sys.stderr)
    return out.returncode == 0


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--send", action="store_true")
    ap.add_argument("--if-due", action="store_true")
    args = ap.parse_args(argv)
    cfg = config.load()
    every = cfg.get("report", "every_days", 7)
    store = Store(config.db_path())
    if args.if_due and STAMP.exists() and time.time() - STAMP.stat().st_mtime < every * 86400:
        return
    text = build(store, every)
    if args.send or args.if_due:
        if send(text):
            STAMP.touch()
            store.prune_events(60)
    else:
        print(text)


if __name__ == "__main__":
    main()
