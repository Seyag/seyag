"""The committee's tool: decisions are recorded here, after the review in chat.

  committee.py status <host>                 what applies to a site and why
  committee.py requests                      pending appeals
  committee.py approve <host> --days N --reason "..." [--domain]
  committee.py deny <host> --reason "..."
  committee.py history [N]                   recent committee decisions
"""

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aifilter import config  # noqa: E402
from aifilter.export_settings import optional_path  # noqa: E402
from aifilter.store import ALLOW, BLOCK, MAX_OVERRIDE_DAYS, Store  # noqa: E402

MIN_DAYS, MAX_DAYS = 1, MAX_OVERRIDE_DAYS  # no approval is permanent


def _days(value: str) -> float:
    try:
        days = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("days must be a number") from None
    if not MIN_DAYS <= days <= MAX_DAYS:  # also rejects nan and inf
        raise argparse.ArgumentTypeError(f"days must be between {MIN_DAYS} and {MAX_DAYS}")
    return days


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status"); s.add_argument("host")
    sub.add_parser("requests")
    a = sub.add_parser("approve"); a.add_argument("host"); a.add_argument("--days", type=_days, required=True)
    a.add_argument("--reason", required=True)
    a.add_argument("--domain", action="store_true",
                   help="intentionally apply to this host and its subdomains")
    d = sub.add_parser("deny"); d.add_argument("host"); d.add_argument("--reason", required=True)
    v = sub.add_parser("video-approve"); v.add_argument("host"); v.add_argument("--path", required=True)
    v.add_argument("--days", type=_days, required=True); v.add_argument("--reason", required=True)
    r = sub.add_parser("video-revoke"); r.add_argument("host"); r.add_argument("--path", required=True)
    h = sub.add_parser("history"); h.add_argument("n", nargs="?", type=int, default=20)
    sub.add_parser("public-key")  # companion app lock: the committee's Ed25519 public key (base64, raw 32 bytes)
    sp = sub.add_parser("sign-policy"); sp.add_argument("payload_file"); sp.add_argument("--request", default="")
    pr = sub.add_parser("policy-request"); pr.add_argument("text"); pr.add_argument("--loosen", nargs="+", required=True)
    pc = sub.add_parser("policy-confirm"); pc.add_argument("request_id"); pc.add_argument("--decision", required=True)
    args = ap.parse_args(argv)
    if args.cmd in ("public-key", "sign-policy", "policy-request", "policy-confirm"):
        return _policy(args)
    store = Store(config.db_path())

    if args.cmd == "status":
        print(f"verdict={store.verdict(args.host)} list={store.listed(args.host)} "
              f"house_blocked={store.network_blocked(args.host)}")
        for t, k, host, det in store.events(500):
            if host and args.host.endswith(host) and k in ("verdict", "appeal"):
                print(time.strftime("%Y-%m-%d %H:%M", time.localtime(t)), k, host, det)
    elif args.cmd == "requests":
        for i, host, url, note, c in store.appeals():
            print(i, host, url, note, time.strftime("%Y-%m-%d %H:%M", time.localtime(c)))
    elif args.cmd == "approve":
        days = args.days
        try:
            store.loosen(args.host, ALLOW, "admin", f"committee: {args.reason}", days=days,
                         domain=args.domain)
        except ValueError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1
        _close_appeals(store, args.host, True)
        print(f"approved {args.host} for {days} days")
    elif args.cmd == "deny":
        store.set_verdict(args.host, BLOCK, "admin", f"committee: {args.reason}")
        _close_appeals(store, args.host, False)
        print(f"denied {args.host}")
    elif args.cmd == "video-approve":
        store.grant_video(args.host, args.path, args.days, f"committee: {args.reason}")
        print(f"video approved {args.host}{args.path} for {args.days} days (image review unchanged)")
    elif args.cmd == "video-revoke":
        store.revoke_video(args.host, args.path)
        print(f"video revoked {args.host}{args.path}")
    elif args.cmd == "history":
        rows = [r for r in store.events(1000) if r[1] == "verdict" and "committee:" in (r[3] or "")]
        for t, _k, host, det in rows[: args.n]:
            print(time.strftime("%Y-%m-%d %H:%M", time.localtime(t)), host, det)


def _policy(args) -> int:
    import json

    from aifilter import policysign as ps

    state = config.db_path().parent / "committee-policy.json"
    try:
        if args.cmd == "public-key":
            print(ps.public_key(ps.KeychainKey()))
        elif args.cmd == "policy-request":
            print(json.dumps(ps.request(state, args.text, args.loosen)))
        elif args.cmd == "policy-confirm":
            panel = optional_path("AIFILTER_DECISIONS_FILE")
            if panel is None:
                raise ps.PolicyError("signed decisions file is not configured")
            rec = json.loads(panel.read_text()).get(args.decision) or {}
            cfg = config.load()
            answer = ps.verified_answer(rec, cfg.get("committee", "bridge_decision_key", ""),
                                        cfg.get("committee", "owner_telegram_id", 0))
            if answer["id"] != args.decision:
                raise ps.PolicyError("the signed answer belongs to another decision")
            print(json.dumps(ps.confirm(state, args.request_id, answer)))
        else:
            payload = json.loads(Path(args.payload_file).read_text())
            print(json.dumps(ps.sign(state, payload, ps.KeychainKey(), args.request)))
    except (ps.PolicyError, ValueError, OSError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


def _close_appeals(store, host, approved):
    for i, h, *_ in store.appeals():
        if host.endswith(h):
            store._q("UPDATE appeals SET status=? WHERE id=?", ("approved" if approved else "denied", i))


if __name__ == "__main__":
    main()
