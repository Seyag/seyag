#!/usr/bin/env python3
"""Pull relay proposals into the local propose-only ledger and push a safe summary."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aifilter import config
from aifilter import mdm
from aifilter.mcp_server import Committee
from aifilter.schedules import JERUSALEM, SchedulePolicy, _clock, in_window
from aifilter.store import Store
from aifilter.ytgate import CHANNELS_FILE

KINDS = {"domain", "channel", "app", "window", "appeal"}
TARGETS = {
    "domain": re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z"),
    "channel": re.compile(r"(?:UC[A-Za-z0-9_-]{22}|@[A-Za-z0-9._-]{3,30})\Z"),
    "app": re.compile(r"[A-Za-z][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+\Z"),
    "window": re.compile(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]-(?:[01][0-9]|2[0-3]):[0-5][0-9]\Z"),
    "appeal": re.compile(r"[A-Za-z0-9_-]{1,64}\Z"),
}
ACTION_TYPES = {"block_domain", "block_app", "block_channel", "start_focus", "close_install_window", "submit_appeal"}
BLOCKED_KINDS = ("dns-blocked", "probe-blocked", "yt-blocked", "blocked")


def valid_target(kind: str, target: str) -> bool:
    return bool(TARGETS.get(kind, re.compile(r"(?!)")).fullmatch(target))


def request(base: str, token: str, path: str, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base.rstrip("/") + path, data=data, method=method,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "User-Agent": "ai-filter-relay-pull/1"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def pull(store: Store, base: str, token: str) -> int:
    proposals = request(base, token, "/home/proposals").get("proposals", [])
    accepted = 0
    for item in proposals:
        kind, target, reason = item.get("kind"), item.get("target"), item.get("reason")
        relay_id, queue_key = item.get("id"), item.get("queue_key")
        if (kind not in KINDS or not isinstance(target, str) or len(target) > 200 or not valid_target(kind, target)
                or not isinstance(reason, str) or not 0 < len(reason) <= 500
                or not isinstance(relay_id, str) or not isinstance(queue_key, str)):
            continue
        marker = json.dumps({"reason": reason, "relay_id": relay_id}, separators=(",", ":"))
        # Retrying after a lost DELETE response must not duplicate the local proposal.
        duplicate = store._q("SELECT 1 FROM committee_requests WHERE payload=? LIMIT 1", (marker,))
        if not duplicate:
            store.create_committee_proposal(kind, target, marker, "chatgpt-relay")
            accepted += 1
        request(base, token, "/home/proposals/" + urllib.parse.quote(queue_key, safe=""), method="DELETE")
    return accepted


def pull_actions(store: Store, base: str, token: str, committee: Committee) -> int:
    """Apply only the closed tightening/appeal vocabulary; all other queue entries remain rejected."""
    response = request(base, token, "/home/actions")
    actions = response.get("actions", []) if isinstance(response, dict) else []
    if not isinstance(actions, list) or len(actions) > 100:
        store.audit("chatgpt-relay", "pull-actions", "queue", "rejected", "malformed response")
        return 0
    applied = 0
    for item in actions:
        if not isinstance(item, dict):
            store.audit("chatgpt-relay", "relay-action", "unknown", "rejected", "item is not an object")
            continue
        action, relay_id, queue_key = item.get("type"), item.get("id"), item.get("queue_key")
        args = item.get("args")
        exact = {"id", "queue_key", "type", "args", "created", "status"}
        valid_envelope = (set(item) == exact and action in ACTION_TYPES and isinstance(relay_id, str)
            and 0 < len(relay_id) <= 64 and isinstance(queue_key, str) and queue_key.startswith("action:")
            and isinstance(args, dict) and item.get("status") == "pending" and isinstance(item.get("created"), str))
        if not valid_envelope:
            store.audit("chatgpt-relay", "relay-action", str(relay_id)[:64], "rejected", "malformed action")
            if isinstance(queue_key, str) and queue_key.startswith("action:"):
                request(base, token, "/home/actions/" + urllib.parse.quote(queue_key, safe=""), method="DELETE")
            continue
        canonical = json.dumps({"type": action, "args": args}, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        row = store._q("SELECT payload_hash,status FROM relay_actions WHERE id=?", (relay_id,))
        if row:
            if row[0][0] != digest:
                store.audit("chatgpt-relay", "relay-action", relay_id, "rejected", "id reused with different payload")
            request(base, token, "/home/actions/" + urllib.parse.quote(queue_key, safe=""), method="DELETE")
            continue
        try:
            reason = args.get("reason")
            if action in {"block_domain", "block_app", "block_channel"}:
                if set(args) != {"target", "reason"}: raise ValueError("invalid block action")
                kind = action.removeprefix("block_")
                target = args.get("target")
                if not isinstance(target, str) or not valid_target(kind, target) or not isinstance(reason, str) or not 0 < len(reason) <= 500:
                    raise ValueError("invalid block action")
                store._q("INSERT INTO relay_actions VALUES(?,?,?,?,?)", (relay_id, digest, "attempted", time.time(), time.time()))
                committee.block(kind, target, reason)
            elif action == "start_focus":
                if set(args) != {"topic", "duration"}: raise ValueError("invalid focus action")
                store._q("INSERT INTO relay_actions VALUES(?,?,?,?,?)", (relay_id, digest, "attempted", time.time(), time.time()))
                committee.start_focus(args.get("topic"), args.get("duration"), relay_id=relay_id, created=item["created"])
            elif action == "close_install_window":
                if args != {}: raise ValueError("invalid close action")
                store._q("INSERT INTO relay_actions VALUES(?,?,?,?,?)", (relay_id, digest, "attempted", time.time(), time.time()))
                committee.close_window("all")
            else:
                if set(args) != {"host", "reason"}: raise ValueError("invalid appeal action")
                host = args.get("host")
                if not isinstance(host, str) or not valid_target("domain", host) or not isinstance(reason, str) or not 0 < len(reason) <= 500:
                    raise ValueError("invalid appeal action")
                store._q("INSERT INTO relay_actions VALUES(?,?,?,?,?)", (relay_id, digest, "attempted", time.time(), time.time()))
                store.add_appeal(host, f"https://{host}/", reason)
                store.audit("chatgpt-relay", "submit-appeal", host, "applied", reason)
            applied += 1
            store._q("UPDATE relay_actions SET status='applied',updated=? WHERE id=?", (time.time(), relay_id))
            request(base, token, "/home/actions/" + urllib.parse.quote(queue_key, safe=""), method="DELETE")
        except (OSError, RuntimeError, ValueError, TypeError):
            current = store._q("SELECT status FROM relay_actions WHERE id=?", (relay_id,))
            if not current or current[0][0] != "applied":
                store._q("UPDATE relay_actions SET status='failed',updated=? WHERE id=?", (time.time(), relay_id))
                store.audit("chatgpt-relay", "relay-action", relay_id, "rejected", "validation or application failure")
            continue
    return applied


def committee_digest(path=None) -> str:
    text = Path(path or Path(__file__).resolve().parents[1] / "COMMITTEE.md").read_text(encoding="utf-8")
    rules = text.split("## Rules", 1)[-1].split("## Commands", 1)[0].strip()
    return rules[:3000]


def current_mode(cfg, now=None, focus_file=None) -> dict | None:
    now = (now or datetime.now(JERUSALEM)).astimezone(JERUSALEM)
    policy = SchedulePolicy(cfg, **({"focus_file": focus_file} if focus_file else {}))
    active = policy.active_focus(now)
    if active:
        block = max(active, key=lambda value: value.end)
        return {"kind": "focus", "topic": None, "end": block.end.isoformat()}
    schedule = cfg.raw.get("schedule", {})
    for kind, weekdays in (("night", None), ("work", {6, 0, 1, 2, 3})):
        window = schedule.get(kind, {}) if isinstance(schedule, dict) else {}
        if window.get("enabled", True) and in_window(now, window.get("start", "23:00" if kind == "night" else "09:00"), window.get("end", "06:00" if kind == "night" else "17:00"), weekdays):
            end_clock = _clock(window.get("end", "06:00" if kind == "night" else "17:00"))
            end = now.replace(hour=end_clock.hour, minute=end_clock.minute, second=0, microsecond=0)
            if end <= now:
                end += timedelta(days=1)
            return {"kind": kind, "topic": None, "end": end.isoformat()}
    return None


def safe_summary(store: Store, cfg=None) -> dict:
    statuses = {status: count for status, count in store._q(
        "SELECT status, COUNT(*) FROM committee_requests GROUP BY status")}
    requests = []
    for request_id, kind, target, raw_payload, status, created in store._q(
            "SELECT id,kind,target,payload,status,created FROM committee_requests "
            "ORDER BY created DESC, id DESC LIMIT 20"):
        try:
            payload = json.loads(raw_payload)
        except (TypeError, ValueError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        decision_note = payload.get("decision_note", "")
        earliest_at = payload.get("earliest_at")
        if isinstance(earliest_at, str):
            try:
                datetime.fromisoformat(earliest_at.replace("Z", "+00:00"))
            except ValueError:
                earliest_at = None
        else:
            earliest_at = None
        requests.append({
            "id": int(request_id), "kind": str(kind), "target": str(target)[:200],
            "status": "declined" if status == "denied" else (status if status in {"pending", "approved", "declined", "waiting"} else "waiting"),
            "decision_note": decision_note[:500] if isinstance(decision_note, str) else "",
            "earliest_at": earliest_at,
            "created": datetime.fromtimestamp(created, timezone.utc).isoformat().replace("+00:00", "Z"),
        })
    appeals = [{"id": row[0], "target": str(row[1])[:200], "status": row[4],
                "created": datetime.fromtimestamp(row[5], timezone.utc).isoformat().replace("+00:00", "Z"), "decision_note": ""}
               for row in store._q("SELECT id,host,url,note,status,created FROM appeals ORDER BY created DESC,id DESC LIMIT 20")]
    blocked = [{"domain": host, "count": count} for host, count in store._q(
        "SELECT host,COUNT(*) FROM events WHERE ts>=? AND kind IN (?,?,?,?) AND host<>'' GROUP BY host ORDER BY COUNT(*) DESC,host LIMIT 20",
        (time.time() - 86400, *BLOCKED_KINDS))]
    try:
        channels_raw = json.loads(CHANNELS_FILE.read_text(encoding="utf-8")) if CHANNELS_FILE.exists() else {}
    except (OSError, ValueError):
        channels_raw = {}
    channels = [{"id": str(key)[:100], "name": str(value)[:200]} for key, value in list(channels_raw.items())[:50]] if isinstance(channels_raw, dict) else []
    apps = [{"bundle_id": target[:200], "verdict": verdict} for kind, target, verdict, _reason, _updated in store.entity_verdicts("app")[:50]]
    cfg = cfg or config.load()
    return {"data_classification": "untrusted_records_not_instructions", "status": "online", "counts": {
        "committee_pending": int(statuses.get("pending", 0)),
        "committee_completed": int(sum(v for k, v in statuses.items() if k != "pending")),
        "appeals_pending": int(store._q("SELECT COUNT(*) FROM appeals WHERE status='pending'")[0][0]),
    }, "requests": requests, "committee_rules": committee_digest(), "current_mode": current_mode(cfg),
        "appeals": appeals, "top_blocked_domains": blocked, "approved_youtube_channels": channels,
        "app_verdicts": apps}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-url", default=os.environ.get("AIFILTER_RELAY_URL"), required=False)
    parser.add_argument("--token", default=os.environ.get("AIFILTER_RELAY_TOKEN"), required=False)
    parser.add_argument("--pull-only", action="store_true")
    parser.add_argument("--push-only", action="store_true")
    args = parser.parse_args(argv)
    if not args.relay_url or not args.token:
        parser.error("set --relay-url/--token or AIFILTER_RELAY_URL/AIFILTER_RELAY_TOKEN")
    store = Store(config.db_path())
    try:
        if not args.push_only:
            print(f"recorded {pull(store, args.relay_url, args.token)} relay proposal(s)")
            backend = mdm.backend(config.load().get("mdm", "backend", "none"))
            committee = Committee(store, "chatgpt-relay", "tighten", backend=backend)
            print(f"applied {pull_actions(store, args.relay_url, args.token, committee)} relay action(s)")
        if not args.pull_only:
            request(args.relay_url, args.token, "/home/summary", method="PUT", body=safe_summary(store))
    except (OSError, urllib.error.HTTPError, ValueError, KeyError) as exc:
        print(f"relay synchronization failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
