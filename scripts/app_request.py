"""Usage: .venv/bin/python scripts/app_request.py <app store link, numeric id or app name> [--device iphone|ipad|id] [--note "why"] [--dry-run] | --tick | --status

Backend of the owner's "request an app" button. App Store installs on each managed device are locked through the MDM.
One request: look the app up in Apple's public lookup API, decide (COMMITTEE.md, default deny):
  approved  -> scan first, then unlock installs for 15 minutes on fresh contact  exit 0
  denied    -> recorded; the same app is not re-reviewed for 7 days            exit 2
  review    -> one local review log line for the committee (the lead session)      exit 3
  approved but no MDM backend yet -> recorded + local review log line              exit 4
  bad input or error                                                            exit 1
`--tick` (launchd, every 2 minutes): obtains the pre-unlock inventory, locks installs at expiry, then checks fresh inventory for extra apps. `--status`: install window and recent requests.
Prints exactly one JSON line {"status","app","bundle","reason","until"}. --dry-run decides only (no state,
no MDM, no ledger) and exits with the decision's code.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from contextlib import nullcontext
from datetime import datetime
from math import ceil, isfinite
from pathlib import Path
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from aifilter import appjudge, config, mdm, mdmwatch  # noqa: E402
from deploy.set_restrictions import BLOCKED_APPS  # noqa: E402

LEDGER = None
LOOKUP = "https://itunes.apple.com/lookup?id={id}&country={country}"
SEARCH = "https://itunes.apple.com/search?term={term}&entity=software&country={country}&limit=1"
WINDOW_MINUTES = 15
PENDING_MAX = 2 * 3600
READ_GRACE = 30 * 60  # report a stalled close after this long; installs stay locked
CLOSING_SKIP_MIN_AGE = 24 * 3600
SCAN_INTERVAL = 120
CLOSING_SCAN_MAX_INTERVAL = 60 * 60
CONTACT_MARGIN = 60  # clocks can disagree between the local host and MDM
REPORT_INTERVAL = 24 * 3600
PENDING_REASON = "waiting for the device to receive the unlock"
DENY_MEMORY_DAYS = 7
ISRAEL = ZoneInfo("Asia/Jerusalem")
WINDOWS_PER_DAY = 3
NIGHTLY_START = (2, 0)
NIGHTLY_END = (2, 30)
NIGHTLY_LABEL = "nightly updates"
NIGHTLY_BUNDLE = "com.example.companion"
NIGHT_REVIEW = "night request (23:00-06:00): waits for the committee in the morning"
EXIT = {"approved": 0, "already_installed": 0, "denied": 2, "review": 3,
        "approved_waiting_mdm": 4, "error": 1}

SAFE_GENRES = {"Education", "Books", "Book",  # Apple returns both spellings
                "Reference", "Productivity", "Utilities", "Finance", "Navigation", "Weather",
               "Health & Fitness", "Medical", "Business", "Travel", "Food & Drink"}
DENY_GENRES = {"Social Networking", "Dating", "Casino"}
REVIEW_GENRES = {"Entertainment", "Photo & Video", "Games", "News", "Shopping"}
NIGHT_OK_GENRES = {"Medical", "Health & Fitness", "Finance"}
# Apple's TestFlight installs our own builds (companion); any other new app is still blocked at window close.
TRUSTED_INSTALLERS = {"com.apple.testflight"}
# Committee decisions (COMMITTEE.md) for apps the rules send to review: bundle -> reason. Deny rules still win.
COMMITTEE_APPROVED = {}
SAFE_RATINGS = {"4+", "9+", "12+"}
DENY_RATINGS = {"18+"}  # 17+ often means only "unrestricted web access" (e.g. Waze): the committee decides
DENY_WORDS = re.compile(r"\b(vpns?|prox(?:y|ies)|browsers?|tor|dating|casinos?|anonymous chats?|"
                        r"live[ -]?stream(?:s|ing)?)\b", re.I)
CHAT_NAME = re.compile(r"\b(chats?|messengers?|messag(?:e|es|ing)|talk|calls?)\b", re.I)
CHAT_TEXT = re.compile(r"\b(messenger|messaging app|instant messag\w*|group chats?)\b", re.I)

_LINK = re.compile(r"https://apps\.apple\.com/(?:[a-z]{2}(?:-[a-z]{2,4})?/)?app/(?:[A-Za-z0-9%._~-]{1,200}/)?"
                   r"id([0-9]{6,12})(?:\?[A-Za-z0-9=&%._~-]{0,200})?")
_BARE = re.compile(r"(?:id)?([0-9]{6,12})")


def parse_app_id(text: str) -> str | None:
    """The numeric App Store id from an apps.apple.com link or a bare id; None for anything else."""
    if not isinstance(text, str) or len(text) > 500:
        return None
    text = text.strip()
    m = _LINK.fullmatch(text) or _BARE.fullmatch(text)
    return m.group(1) if m else None


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=15) as r:  # noqa: S310 - fixed https URL, digits-only id
        return r.read(2_000_000)


def lookup(app_id: str, fetch=_fetch) -> dict | None:
    if not re.fullmatch(r"[0-9]{6,12}", app_id):
        raise ValueError("bad app id")
    for country in ("il", "us"):
        data = json.loads(fetch(LOOKUP.format(id=app_id, country=country)))
        for item in data.get("results", []):
            if item.get("bundleId") and str(item.get("trackId")) == app_id:
                return item
    return None


def _israel_night(now: float) -> bool:
    h = datetime.fromtimestamp(now, ISRAEL).hour
    return h >= 23 or h < 6


def _requires_night_review(app: dict, now: float) -> bool:
    return _israel_night(now) and app.get("primaryGenreName") not in NIGHT_OK_GENRES


def decide(app: dict, now: float, history: list) -> tuple[str, str]:
    """('approved' | 'denied' | 'review', one-line reason). Pure: app is an Apple lookup result."""
    bundle = (app.get("bundleId") or "").lower()
    # MCP committee verdicts share the main store; fixed deny rules below still take precedence over allows.
    dynamic = None
    try:
        from aifilter.store import Store
        dynamic = Store(config.db_path()).entity_verdict("app", bundle)
    except Exception:
        pass  # unreadable committee state never grants an allow
    genres = {app.get("primaryGenreName") or ""} | set(app.get("genres") or [])
    genres.discard("")
    rating = app.get("contentAdvisoryRating") or app.get("trackContentRating") or ""
    name, text = app.get("trackName") or "", f"{app.get('trackName') or ''}\n{app.get('description') or ''}"
    if any(bundle == b.lower() or bundle.startswith(b.lower() + ".") for b in BLOCKED_APPS):
        return "denied", "this app is on the iPhone's blocked apps list"
    if rating in DENY_RATINGS:
        return "denied", f"rated {rating} (adult content)"
    if genres & DENY_GENRES:
        return "denied", f"{', '.join(sorted(genres & DENY_GENRES))} apps are never approved"
    if m := DENY_WORDS.search(name):
        return "denied", f"the app's name says '{m.group(0)}' (VPN, proxy, browser, dating, casino or live video)"
    if dynamic and dynamic[0] == "block":
        return "denied", f"committee blocked: {dynamic[1]}"
    for h in history:
        if h.get("bundle", "").lower() == bundle and h.get("status") == "denied" \
                and now - h.get("t", 0) < DENY_MEMORY_DAYS * 86400:
            return "denied", "denied less than 7 days ago; not reviewed again yet"
    # This gate precedes every allow path.  In particular, trusted installers and
    # committee decisions must not silently bypass the overnight review rule.
    if _requires_night_review(app, now):
        return "review", NIGHT_REVIEW
    if dynamic and dynamic[0] == "allow":
        return "approved", f"committee approved: {dynamic[1]}"
    if bundle in TRUSTED_INSTALLERS:
        return "approved", "TestFlight: installs our own app builds; anything new is blocked when the window closes"
    if bundle in COMMITTEE_APPROVED:
        return "approved", f"committee approved: {COMMITTEE_APPROVED[bundle]}"
    if m := DENY_WORDS.search(text):  # only the description: harmless apps say "open in your browser"
        return "review", f"the description mentions '{m.group(0)}': the committee decides"
    if CHAT_NAME.search(name) or CHAT_TEXT.search(text):
        return "review", "messaging or chat app: the committee decides"
    if genres & REVIEW_GENRES:
        return "review", f"{', '.join(sorted(genres & REVIEW_GENRES))} app: the committee decides"
    if not genres or not genres <= SAFE_GENRES:
        return "review", f"category {', '.join(sorted(genres - SAFE_GENRES)) or 'unknown'} is not on the safe list"
    if rating not in SAFE_RATINGS:
        return "review", f"age rating {rating or 'unknown'} is not on the safe list"
    return "approved", f"{app.get('primaryGenreName')} app rated {rating}"


def _clean(s, n=120) -> str:
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(s or "")).strip()[:n]


def _ledger(line: str, *, required=False):
    if LEDGER is None or not LEDGER.exists():
        if required:
            raise RuntimeError("owner ledger unavailable")
        return False
    result = subprocess.run([str(LEDGER), "ai-filter", "add", line], capture_output=True, timeout=20)
    if required and result.returncode:
        raise RuntimeError("owner ledger write failed")
    return result.returncode == 0


class DeviceState(dict):
    """A device-scoped record; _save merges only this device into the shared state file."""


def _load(state_file: Path, backend=None) -> dict:
    if backend is None:
        raw = json.loads(state_file.read_text()) if state_file.exists() else {}
        ids = tuple(raw.get("devices", {})) or (mdm.IPHONE,)
        did = mdm.primary_device(ids)
    else:
        ids = mdm.device_ids(backend)
        did = str(getattr(backend, "device_id", mdm.primary_device(ids)))
    legacy = mdm.legacy_device(ids)
    record = mdm.read_state(state_file, legacy)["devices"].get(did, {})
    if not isinstance(record, dict):
        raise ValueError("invalid app-request state")
    history = record.get("history", [])
    if not isinstance(history, list) or not all(isinstance(item, dict) for item in history):
        raise ValueError("invalid app-request history")
    window = record.get("window")
    if window is not None:
        if (not isinstance(window, dict) or not isinstance(window.get("bundles"), list)
                or not all(isinstance(bundle, str) for bundle in window["bundles"])
                or not isinstance(window.get("until"), (int, float)) or not isfinite(window["until"])):
            raise ValueError("invalid install window")
        closing = window.get("closing")
        if closing is not None and (not isinstance(closing, dict)
                                    or not isinstance(closing.get("locked_at"), (int, float))
                                    or not isfinite(closing["locked_at"]) or not _trusted_baseline(window)):
            raise ValueError("invalid closing install window")
    state = DeviceState(record)
    state.device_id, state.legacy_device = did, legacy
    state.setdefault("history", [])
    state.setdefault("window", None)
    return state


def _save(state_file: Path, state: dict):
    mdm.save_device_state(state_file, state.device_id, state, state.legacy_device)


def _trusted_baseline(window):
    snapshot = window.get("snapshot")
    return (not window.get("inventory_untrusted") and isinstance(snapshot, list) and bool(snapshot)
            and all(isinstance(bundle, str) for bundle in snapshot))


def _state_failed(state_file, backend, report, now):
    try:
        if backend.available:
            backend.lock()
    finally:
        # The damaged file cannot store its own rate limit. Use a separate stamp
        # under the same transaction lock, even across cron invocations and devices.
        stamp = state_file.with_suffix(state_file.suffix + ".state-error")
        try:
            last = float(stamp.read_text()) if stamp.exists() else None
        except (OSError, ValueError):
            last = None
        if last is None or not isfinite(last) or now - last >= REPORT_INTERVAL:
            try:
                stamp.write_text(str(now))
            except OSError:
                pass  # a reporting failure must not mask the invalid state or lock failure
            else:
                report("app-request: corrupt or unreadable install-window state; requests are disabled until repaired")


def _request_state(state_file, backend, report, now, dry):
    try:
        return _load(state_file, backend)
    except (OSError, ValueError):
        if not dry:
            _state_failed(state_file, backend, report, now)
        raise


def _device_contact(backend, now):
    try:
        device = next((d for d in backend.devices() if str(d.get("device_id")) == str(backend.device_id)), None)
        if device is None:
            return None, "device data missing"
        contact = mdmwatch._ms(device.get("last_contact_time"))
        if contact is None or contact > now or str(device.get("managed_status")) != mdmwatch.MANAGED:
            return None, "device data unreadable"
    except Exception as exc:  # noqa: BLE001 - a transient MDM read is retried on the next tick
        return None, f"device data unreadable: {_clean(exc, 80)}"
    return contact, None


def _scan(backend, phase, clock):
    phase["scan_at"] = clock()
    try:
        backend.scan()
    except Exception as exc:  # noqa: BLE001 - the phase stays locked if the scan fails
        return f"MDM scan failed: {_clean(exc, 80)}"
    if phase.get("scan_confirmed_at") is None:
        phase["scan_confirmed_at"] = phase["scan_at"]
    return None


def _queue_window(state_file, state, backend, bundles, names, now, until, clock, **fields):
    try:
        backend.lock()
    except Exception as exc:  # noqa: BLE001 - never queue a scan or baseline without a confirmed lock
        state["locked"] = False
        return f"MDM lock failed before scan: {_clean(exc, 80)}"
    # Persist the intent before the scan, and record that it was accepted before tick can unlock.
    window = dict(bundles=bundles, names=names, until=until, snapshot=None, sent_at=None,
                  delivered_at=None, scan_requested_at=now, scan_at=now, scan_confirmed_at=None, **fields)
    state.update(window=window, locked=True)
    _save(state_file, state)
    error = _scan(backend, window, clock)
    if error:
        window.update(unlock_failed=True, until=now)
    return error


def _target_callbacks(backend, report, notify):
    did = str(getattr(backend, "device_id", "default"))
    if did in (mdm.IPHONE, mdm.IPAD):
        label = mdm.device_label(did)
        original_report, original_notify = report, notify
        report = lambda text: original_report(f"device {did}: " + text)
        notify = lambda text: original_notify(f"{label}: " + text.replace("האייפון", label))
    return report, notify


def _out(status, app=None, bundle=None, reason="", until=None, **extra) -> dict:
    return {"status": status, "app": app, "bundle": bundle, "reason": reason, "until": until, **extra}


def search_app_id(text: str, fetch=_fetch) -> str | None:
    """The owner may send just the app's name (the App Store is hidden while locked): best App Store match."""
    term = text.strip() if isinstance(text, str) else ""
    if not 2 <= len(term) <= 60 or not re.fullmatch(r"[\w .&'+:!-]+", term) or not re.search(r"[^\W\d_]", term):
        return None
    for country in ("il", "us"):
        data = json.loads(fetch(SEARCH.format(term=urllib.parse.quote(term), country=country)))
        for item in data.get("results", []):
            if re.fullmatch(r"[0-9]{6,12}", str(item.get("trackId", ""))):
                return str(item["trackId"])
    return None


def request(link: str, state_file: Path, backend, note: str = "", dry=False, fetch=_fetch, report=_ledger,
            now: float | None = None, ai_model: str = "", ai_second: str = "", notify=None, device=None) -> dict:
    clock = time.time if now is None else lambda: now
    at = clock()
    notify = mdmwatch.send if notify is None else notify
    backend = mdm.for_device(backend, mdm.resolve_device(backend, device))
    report, notify = _target_callbacks(backend, report, notify)
    app_id = parse_app_id(link)
    if not app_id:
        try:
            app_id = search_app_id(link, fetch)
        except (OSError, ValueError) as exc:
            return _out("error", reason=f"App Store search failed: {_clean(exc, 80)}")
    if not app_id:
        return _out("error", reason="no App Store app found for that link or name")
    try:
        app = lookup(app_id, fetch)
    except (OSError, ValueError) as exc:
        return _out("error", reason=f"App Store lookup failed: {_clean(exc, 80)}")
    if not app:
        return _out("error", reason=f"no App Store app with id {app_id}")
    name, bundle = _clean(app.get("trackName")), _clean(app.get("bundleId"), 200)
    ai_decision = None
    if ai_model:
        with nullcontext() if dry else mdm.state_lock(state_file):
            history = _request_state(state_file, backend, report, at, dry)["history"]
        status, reason = decide(app, at, history)
        if status == "review" and not _requires_night_review(app, at):
            # Judging includes image downloads: never delay expiry locks for this work.
            ai_decision = appjudge.judge(app, reason, _israel_night(at), ai_model, second_model=ai_second)
    with nullcontext() if dry else mdm.state_lock(state_file):
        at = clock()
        state = _request_state(state_file, backend, report, at, dry)
        status, reason = decide(app, at, state["history"])
        if status == "review" and ai_decision is not None and not _requires_night_review(app, at):
            status, reason = ai_decision  # fresh denials override the earlier AI result
        if dry:
            return _out(status, name, bundle, f"dry run: {reason}")
        if status == "approved" and state["window"]:
            status, reason = "review", "another install window is already pending, open, or closing"
        if status == "approved" and not backend.available:
            status, reason = "approved_waiting_mdm", f"{reason}; no MDM connection yet, the committee installs it"
        elif status == "approved":
            # This cached read can only avoid a window. The baseline is taken by tick after lock and scan.
            try:
                installed = {b.lower() for b in backend.installed_apps()}
            except Exception as exc:  # noqa: BLE001 - any backend failure fails closed (nothing unlocked)
                try:
                    backend.lock()
                except Exception:  # tick retries the lock
                    pass
                state["locked"] = False  # retry tightening on the next tick even if this lock failed
                installed = None  # approved but not opened: exit 4, the ledger line tells the committee to open it
                status, reason = "approved_waiting_mdm", f"{reason}; MDM failed before unlock: {_clean(exc, 80)}"
            if installed is not None and bundle.lower() in installed:
                status, reason = "already_installed", "the requested app is already installed; no window opened"
        if status == "approved":
            requested = state.get("window_requests")
            if requested is None:
                requested = [h.get("t", 0) for h in state["history"] if h.get("status") == "approved"]
            recent_windows = [t for t in requested if t > at - 86400]
            if len(recent_windows) >= WINDOWS_PER_DAY:
                status, reason = "denied", "three install windows were already requested for this device in 24 hours"
        if status == "approved":
            scan_at = clock()
            error = _queue_window(state_file, state, backend, [bundle], {bundle: name or bundle},
                                  scan_at, scan_at + PENDING_MAX, clock)
            if error:
                status, reason = "error", error
            else:
                state["window_requests"] = recent_windows + [scan_at]
                reason = f"{reason}; {PENDING_REASON}"  # status stays "approved" (stable for the app); delivered=False
        state["history"].append({"t": at, "id": app_id, "bundle": bundle, "app": name, "status": status,
                                 "reason": reason, "note": _clean(note, 200)})
        state["history"] = state["history"][-500:]
        _save(state_file, state)
        if status in ("review", "approved_waiting_mdm"):
            what = "review" if status == "review" else "approved, not opened yet (MDM step failed or missing)"
            report(f"app-request {what}: {name} ({bundle}, {_clean(app.get('primaryGenreName'), 40)}, "
                   f"{_clean(app.get('contentAdvisoryRating'), 8)}) https://apps.apple.com/app/id{app_id} - {reason}"
                   + (f"; owner note: {_clean(note, 200)}" if note else "")
                   + ("; committee: approve or deny" if status == "review" else ""))
        extra = {"delivered": False} if status == "approved" or (status == "error" and state["window"]) else {}
        return _out(status, name, bundle, reason, **extra)


def tick(state_file: Path, backend, report=_ledger, now: float | None = None, notify=None) -> dict:
    ids = mdm.device_ids(backend)
    results = {}
    for did in ids:
        target = mdm.for_device(backend, did)
        try:
            with mdm.state_lock(state_file):
                results[did] = _tick(state_file, target, report, now, notify)
        except Exception as exc:  # include lock acquisition; still tighten every device
            reason = f"device tick failed: {_clean(exc, 80)}"
            try:
                target.lock()
            except Exception as lock_exc:
                reason += f"; MDM lock failed: {_clean(lock_exc, 80)}"
            results[did] = _out("error", reason=reason)
    if len(ids) == 1:
        return results[ids[0]]
    out = dict(results[mdm.primary_device(ids)])
    out["devices"] = results
    if any(r["status"] == "error" for r in results.values()):
        out["status"] = "error"
    return out


def _closing_out(window, reason):
    return _out("closing", bundle=",".join(window["bundles"]), reason=reason, until=window["until"], delivered=False)


def _finish_close(state_file, state, backend, report, clock, now):
    window = state["window"]
    closing = window["closing"]
    contact, error = (_device_contact(backend, now) if backend.available else (None, "MDM backend unavailable"))
    new_contact = contact is not None and contact > closing.get("last_contact_at", closing["locked_at"])
    if new_contact:
        closing.update(last_contact_at=contact, scan_retry_interval=SCAN_INTERVAL)
    scanned = closing.get("scan_confirmed_at")
    installed = None
    if contact is not None and scanned is not None and contact > max(closing["locked_at"], scanned) + CONTACT_MARGIN:
        try:
            installed = backend.installed_apps()
        except Exception as exc:  # noqa: BLE001 - keep the frozen baseline and retry while locked
            error = f"installed-app inventory unreadable: {_clean(exc, 80)}"
    if installed is None:
        last_scan = closing.get("scan_at")
        interval = closing.get("scan_retry_interval", SCAN_INTERVAL)
        scan_due = backend.available and (last_scan is None or now - last_scan >= interval)
        if scan_due:
            scan_error = _scan(backend, closing, clock)
            error = error or scan_error
            if not new_contact and last_scan is not None:
                closing["scan_retry_interval"] = min(2 * interval, CLOSING_SCAN_MAX_INTERVAL)

        reason = error or "waiting for a fresh post-lock inventory"
        first_report_at = closing["locked_at"] + READ_GRACE
        last_report_at = closing.get("read_failure_reported_at")
        if last_report_at is None and closing.get("read_failure_reported"):
            last_report_at = first_report_at  # Older records kept only a boolean.
        report_due = now >= first_report_at and (last_report_at is None or now - last_report_at >= REPORT_INTERVAL)
        if scan_due or new_contact:
            _save(state_file, state)
        if report_due:
            reported = report(f"app-request: could not verify installed apps after the window closed ({reason}); "
                              "the store stays locked and the inventory check will retry")
            if reported is not False:
                closing["read_failure_reported_at"] = now
                _save(state_file, state)
        return _closing_out(window, reason)
    if new_contact:
        _save(state_file, state)  # Preserve evidence of contact even if applying the app blocks fails.
    spared = set(COMMITTEE_APPROVED) | {bundle.lower() for bundle in window["bundles"] + window["snapshot"]}
    extra = sorted(bundle for bundle in installed if bundle.lower() not in spared)
    try:
        blocked = [bundle for bundle in extra if backend.block_app(bundle) is not False]
    except Exception as exc:  # noqa: BLE001 - block_app is idempotent and the closing record survives
        return _out("error", reason=f"MDM extra-app block failed: {_clean(exc, 80)}", until=window["until"])
    state["window"] = None
    _save(state_file, state)
    if blocked:
        report(f"app-request: apps installed in the window besides {', '.join(window['bundles'])} were "
               f"blocked: {', '.join(_clean(b, 200) for b in blocked)}")
    return _out("locked", bundle=",".join(window["bundles"]), reason="install window closed", until=window["until"],
                blocked=blocked, delivered=True)


def _skip_closing_check(state_file: Path, target, clock, audit):
    """Called through the authenticated committee path with one configured target."""
    with mdm.state_lock(state_file):
        state = _load(state_file, target)
        window = state["window"]
        if not window or window.get("closing") is None:
            raise ValueError("device has no install window waiting for the post-lock check")

        closing = window["closing"]
        locked_at = closing["locked_at"]
        now = clock()
        if isinstance(locked_at, bool) or not isfinite(now) or now - locked_at < CLOSING_SKIP_MIN_AGE:
            raise ValueError("device must have been locked for at least 24 hours")
        contact = closing.get("last_contact_at", locked_at)
        if type(contact) not in (int, float) or not isfinite(contact) or contact > locked_at:
            raise ValueError("device has newer contact or invalid contact data")
        reported_at = closing.get("read_failure_reported_at")
        if type(reported_at) not in (int, float) or not locked_at <= reported_at <= now:
            raise ValueError("the stalled check must already have been reported")

        if not target.available:
            raise RuntimeError("MDM unavailable")
        live, _ = _device_contact(target, now)  # an unreadable device is exactly the stuck case
        if live is not None and live > locked_at:
            raise ValueError("device has contacted MDM since the lock; let the normal close finish")
        target.lock()
        record = {key: window.get(key) for key in
                  ("bundles", "snapshot", "scan_requested_at", "sent_at", "delivered_at", "until")}
        record.update(device_id=state.device_id, locked_at=locked_at, skipped_at=now)
        state.setdefault("closing_skips", []).append(record)
        # Keep the closing record if either the provider lock or a required audit write fails.
        audit(record)
        _ledger("app-request: committee authorized skipping the extra-app check; store lock accepted; "
                + json.dumps(record, ensure_ascii=True), required=True)
        state.update(window=None, locked=True)
        _save(state_file, state)
    return _out("locked", reason="extra-app check skipped after MDM accepted the store lock",
                applied=True, extra_app_check_skipped=True)


def _tick(state_file: Path, backend, report=_ledger, now: float | None = None, notify=None) -> dict:
    clock = time.time if now is None else lambda: now
    now = clock()
    notify = mdmwatch.send if notify is None else notify
    report, notify = _target_callbacks(backend, report, notify)
    try:
        state = _load(state_file, backend)
    except (OSError, ValueError) as exc:
        _state_failed(state_file, backend, report, now)
        return _out("error", reason=f"invalid app-request state: {_clean(exc, 80)}")
    window = state["window"]
    if not window:
        local = datetime.fromtimestamp(now, ISRAEL)
        day = local.date().isoformat()
        if (not backend.available or state.get("nightly_day") == day
                or not NIGHTLY_START <= (local.hour, local.minute) < NIGHTLY_END):
            if backend.available and not state.get("locked"):
                try:
                    backend.lock()
                    state["locked"] = True
                    _save(state_file, state)
                except Exception as exc:
                    return _out("error", reason=f"MDM lock failed: {_clean(exc, 80)}")
            return _out("idle", reason="no install window open")
        end = local.replace(hour=NIGHTLY_END[0], minute=NIGHTLY_END[1], second=0, microsecond=0).timestamp()
        state["nightly_day"] = day
        error = _queue_window(state_file, state, backend, [NIGHTLY_BUNDLE], {NIGHTLY_BUNDLE: "companion"},
                              now, end, clock, label=NIGHTLY_LABEL)
        _save(state_file, state)
        if error:
            return _out("error", reason=error)
        return _out("pending_device", bundle=NIGHTLY_BUNDLE, reason=PENDING_REASON, until=end, delivered=False)
    if window.get("closing") is not None:
        return _finish_close(state_file, state, backend, report, clock, now)
    nightly = window.get("label") == NIGHTLY_LABEL
    # A new window can only take its baseline in the scan phase, before any unlock is sent.
    if "scan_requested_at" in window and window.get("sent_at") is None and not window.get("unlock_failed"):
        asked = window["scan_requested_at"]
        if now >= window["until"]:  # a late contact never opens an overdue window
            window["inventory_untrusted"] = True
            window["unlock_failed"] = True
            window["never_opened"] = True  # nothing was ever unlocked: close and tell the owner
            window["until"] = now
        else:
            if not state.get("locked"):
                # A pending scan persisted before the lock-first change cannot establish the baseline.
                try:
                    backend.lock()
                except Exception as exc:  # noqa: BLE001 - retry on the next tick, before any inventory read
                    return _out("error", reason=f"MDM lock failed before scan: {_clean(exc, 80)}")
                state["locked"] = True
                window["scan_confirmed_at"] = None
                window.pop("scan_at", None)
                _save(state_file, state)
                _scan(backend, window, clock)
                _save(state_file, state)
            scanned = window.get("scan_confirmed_at")
            contact, read_error = _device_contact(backend, now)
            snapshot = None
            if contact is not None and scanned is not None and contact > scanned + CONTACT_MARGIN:
                try:
                    snapshot = sorted(backend.installed_apps())
                except Exception as exc:  # noqa: BLE001 - nothing is unlocked yet: wait and retry
                    read_error = f"installed-app inventory unreadable: {_clean(exc, 80)}"
            if snapshot is None:
                if read_error and not window.get("read_failure_reported"):
                    window["read_failure_reported"] = True
                    report(f"app-request: {read_error}; the store stays locked and the request will retry")
                last_scan = window.get("scan_at")
                if last_scan is None or now - last_scan >= SCAN_INTERVAL:
                    _scan(backend, window, clock)
                if not nightly and now - asked >= 600 and not window.get("delay_notified"):
                    window["delay_notified"] = True
                    _save(state_file, state)
                    try:
                        notify("סינון: האייפון עדיין לא קיבל את פתיחת החנות. אפשר להפעיל מצב טיסה ל-10 שניות ולכבות - זה מזרז.")
                    except Exception:  # noqa: BLE001
                        pass
                _save(state_file, state)
                return _out("pending_device", None, ",".join(window["bundles"]),
                            "waiting for a fresh pre-unlock inventory", window["until"] if nightly else None,
                            delivered=False)
            installed = {bundle.lower() for bundle in snapshot}
            now = clock()
            if now >= window["until"]:
                window.update(unlock_failed=True, never_opened=True, until=now)
            elif not nightly and all(bundle.lower() in installed for bundle in window["bundles"]):
                window.update(already_installed=True, unlock_failed=True, until=now)
            else:
                # Record the immutable baseline before the unlock so retries can close safely.
                until = now + WINDOW_MINUTES * 60
                if nightly:
                    until = min(until, window["until"])
                window.update(snapshot=snapshot, sent_at=now, delivered_at=contact, until=until)
                state["locked"] = False
                _save(state_file, state)
                try:
                    backend.unlock(minutes=ceil((until - now) / 60))
                except Exception as exc:  # noqa: BLE001 - close at once; retain the pre-unlock snapshot
                    window.update(unlock_failed=True, until=now)
                    try:
                        backend.lock()
                    except Exception:  # noqa: BLE001 - the next tick retries
                        pass
                    _save(state_file, state)
                    return _out("error", reason=f"MDM unlock failed: {_clean(exc, 80)}")
                if not nightly:
                    names = window.get("names", {})
                    text = ", ".join(names.get(b) or b for b in window["bundles"])
                    try:
                        notify(f"סינון: חנות האפליקציות פתוחה עכשיו ל-15 דקות להתקנת {text}.")
                    except Exception:  # noqa: BLE001
                        pass
                return _out("open", None, ",".join(window["bundles"]), "install window open", until, delivered=True)
    # Windows created by older versions keep their original expiry behavior.
    tracked = window.get("sent_at") is not None and not window.get("unlock_failed")
    pending = tracked and window.get("delivered_at") is None
    overdue = pending and not nightly and now - window["sent_at"] >= PENDING_MAX
    unknown = pending or not _trusted_baseline(window)
    if pending and not overdue and now < window["until"]:
        contact, read_error = _device_contact(backend, now)
        if read_error:
            if not window.get("read_failure_reported"):
                window["read_failure_reported"] = True
                report(f"app-request: {read_error}; install window kept open and will retry")
            _save(state_file, state)
            return _out("pending_device", None, ",".join(window["bundles"]),
                        "waiting for readable MDM device data", window["until"], delivered=False)
        elif contact is not None and window["sent_at"] <= contact:
            # An older pending window never proved its baseline was fresh before unlock.
            # Preserve its delivery deadline, but do not use post-unlock inventory as a baseline.
            window["delivered_at"] = contact
            pending = False
            window["inventory_untrusted"] = True
            if not nightly:
                window["until"] = max(window["until"], contact + WINDOW_MINUTES * 60)
                names = window.get("names", {})
                text = ", ".join(names.get(b) or b for b in window["bundles"])
                window["delivery_notified"] = True
                _save(state_file, state)
                try:
                    notify(f"סינון: חנות האפליקציות פתוחה עכשיו ל-15 דקות להתקנת {text}.")
                except Exception:  # noqa: BLE001
                    pass
        else:
            if now - window.get("scan_at", window["sent_at"]) >= SCAN_INTERVAL:
                window["scan_at"] = now
                _save(state_file, state)
                try:
                    backend.scan()
                except Exception:  # noqa: BLE001
                    pass
            if not nightly and now - window["sent_at"] >= 600 and not window.get("delay_notified"):
                window["delay_notified"] = True
                _save(state_file, state)
                try:
                    notify("סינון: האייפון עדיין לא קיבל את פתיחת החנות. אפשר להפעיל מצב טיסה ל-10 שניות ולכבות - זה מזרז.")
                except Exception:  # noqa: BLE001
                    pass
            _save(state_file, state)
            return _out("pending_device", None, ",".join(window["bundles"]), PENDING_REASON,
                        window["until"], delivered=False)
    if unknown:
        window["inventory_untrusted"] = True  # a failed lock retry must still skip the stale diff
    if now < window["until"] and not overdue:
        _save(state_file, state)
        return _out("open", None, ",".join(window["bundles"]), "install window open", window["until"],
                    delivered=not pending)
    if not backend.available:
        return _out("error", reason="install window expired but no MDM backend to lock it", until=window["until"],
                    delivered=not pending)
    try:
        backend.lock()
    except Exception as exc:  # noqa: BLE001 - the window stays queued for another lock attempt
        return _out("error", reason=f"MDM lock failed: {_clean(exc, 80)}", until=window["until"],
                    delivered=not pending)
    state["locked"] = True
    if not unknown:
        # Keep the original baseline and bundles until a new scan after this lock can be verified.
        closing = window["closing"] = {"locked_at": clock()}
        _save(state_file, state)
        error = _scan(backend, closing, clock)
        _save(state_file, state)
        return _closing_out(window, error or "waiting for a fresh post-lock inventory")
    report_nightly_expiry = nightly and window.get("never_opened") and (
        state.get("nightly_expiry_reported_at") is None
        or now - state["nightly_expiry_reported_at"] >= REPORT_INTERVAL)
    if report_nightly_expiry:
        state["nightly_expiry_reported_at"] = now
    state["window"] = None
    _save(state_file, state)
    if window.get("already_installed"):
        names = window.get("names", {})
        text = ", ".join(names.get(b) or b for b in window["bundles"])
        report(f"app-request: {text} already installed; the store stayed locked")
        try:
            notify(f"סינון: {text} כבר מותקן. החנות נשארה נעולה.")
        except Exception:  # noqa: BLE001
            pass
        return _out("already_installed", bundle=",".join(window["bundles"]),
                    reason="the requested app is already installed; no window opened", delivered=False)
    if window.get("never_opened"):
        if nightly:
            reason = "nightly window expired without a fresh pre-unlock inventory; installs stayed locked"
            if report_nightly_expiry:
                report(f"app-request: {reason}")
            return _out("locked", bundle=NIGHTLY_BUNDLE, reason=reason, blocked=[], delivered=False)
        reason = "the iPhone never answered the pre-unlock scan; the store stayed locked and the request expired"
        report(f"app-request: {reason} for {', '.join(window['bundles'])}")
        try:
            notify("סינון: האייפון לא הגיב במשך שעתיים, אז הבקשה פגה והחנות נשארה נעולה. אפשר לבקש שוב.")
        except Exception:  # noqa: BLE001
            pass
        return _out("locked", None, ",".join(window["bundles"]), reason, window["until"], blocked=[],
                    delivered=False)
    reason = "trusted baseline unavailable; install window closed; extra-app blocking skipped"
    report(f"app-request: {reason}")
    return _out("locked", reason=reason, blocked=[], delivered=False)


def status(state_file: Path, backend=None) -> dict:
    state = _load(state_file, backend)
    w = state["window"]
    recent = [{k: h.get(k) for k in ("t", "app", "bundle", "status")} for h in state["history"][-5:]]
    if w:
        if w.get("closing") is not None:
            return dict(_closing_out(w, "waiting for a fresh post-lock inventory"), recent=recent)
        delivered = "sent_at" not in w or w.get("delivered_at") is not None
        return _out("open" if delivered else "pending_device", None, ",".join(w["bundles"]),
                    "install window open" if delivered else PENDING_REASON, w["until"],
                    recent=recent, delivered=delivered)
    return _out("idle", reason="no install window open", recent=recent)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    state_file = config.db_path().parent / "app-requests.json"
    try:
        backend = mdm.backend(config.load().get("mdm", "backend", "none"))
        if argv == ["--tick"]:  # flags, so an app named "tick" or "status" is a request, never a subcommand
            out = tick(state_file, backend)
            try:  # the management-removal alarm rides on the same 2-minute tick (throttled inside)
                mdmwatch.watch(state_file.parent / "mdm-watch.json", backend, time.time())
            except Exception:  # noqa: BLE001 - the alarm must never break app installs
                pass
        else:
            ap = argparse.ArgumentParser(add_help=False)
            ap.add_argument("link", nargs="?")
            ap.add_argument("--status", action="store_true")
            ap.add_argument("--device", default=None)
            ap.add_argument("--note", default="")
            ap.add_argument("--dry-run", action="store_true")
            args = ap.parse_args(argv)
            cfg = config.load()
            model = cfg.get("apps", "ai_model", "") if cfg.get("apps", "ai_judge", False) else ""
            second = cfg.get("apps", "ai_second_model", "") if model else ""
            if args.status:
                if args.device:
                    target = mdm.for_device(backend, mdm.resolve_device(backend, args.device))
                    out = status(state_file, target)
                else:
                    ids = mdm.device_ids(backend)
                    results = {did: status(state_file, mdm.for_device(backend, did)) for did in ids}
                    out = dict(results[mdm.primary_device(ids)])
                    out["devices"] = results
            elif args.link is not None:
                out = request(args.link, state_file, backend, args.note, args.dry_run, ai_model=model,
                              ai_second=second, device=args.device)
                if backend.available or args.device is not None:
                    out["device_id"] = mdm.resolve_device(backend, args.device)
            else:
                raise ValueError("an app link or name is required")
    except SystemExit:
        out = _out("error", reason="usage: app_request.py <link or id> [--device iphone|ipad|id] "
                   "[--note ...] [--dry-run] | --tick | --status")
    except Exception as exc:  # noqa: BLE001 - the panel always gets one JSON line
        out = _out("error", reason=_clean(exc, 120))
    print(json.dumps(out, ensure_ascii=False))
    s = out["status"]
    return 0 if s in ("idle", "open", "closing", "locked", "pending_device") else EXIT.get(s, 1)


if __name__ == "__main__":
    sys.exit(main())
