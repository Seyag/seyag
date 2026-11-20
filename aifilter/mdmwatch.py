"""Alarm when the iPhone stops being managed (maintainer decision).

The management (MDM) profile can still be removed on the phone; only Apple Business Manager enrollment would make it
permanent. Web filtering does not depend on it (the locked cable profile holds proxy, DNS lock and app-delete lock),
but app control does. So the app tick asks ManageEngine every CHECK_SECONDS whether the phone is still enrolled and
messages the owner once per incident: when it is gone or no longer managed, or when it has not reported for
STALE_SECONDS (after asking it to report at most once per hour when stale for an hour). A ManageEngine outage alone never alerts.
"""
from __future__ import annotations

import math

CHECK_SECONDS = 10 * 60
SCAN_SECONDS = 3600
STALE_SECONDS = 24 * 3600
MANAGED = "2"  # ManageEngine managed_status of an enrolled, managed device

GONE = ("סינון: פרופיל הניהול הוסר מהאייפון, או שהאייפון כבר לא מנוהל.\n"
        "סינון האתרים ממשיך לפעול, אבל שליטת האפליקציות כבויה עד שהאייפון יחובר שוב לניהול.")
SILENT = ("סינון: האייפון לא דיווח למערכת הניהול כבר יותר מיממה.\n"
          "ייתכן שהוא כבוי או בלי אינטרנט, וייתכן שפרופיל הניהול הוסר.")
BACK = "סינון: האייפון שוב מנוהל ומדווח כרגיל."


def _ms(value) -> float | None:
    try:
        seconds = float(value) / 1000.0
        return seconds if math.isfinite(seconds) and seconds >= 0 else None
    except (TypeError, ValueError):
        return None


def check(state: dict, devices: list[dict] | None, device_id, now: float) -> tuple[str | None, bool]:
    """Advance state (mutated in place) for one look at ManageEngine's device list.

    devices None means ManageEngine could not be read: nothing changes. Returns (message to send or None,
    whether to ask the phone to report now)."""
    if devices is None:
        return None, False
    me = next((d for d in devices if str(d.get("device_id")) == str(device_id)), None)
    seen = _ms(me.get("last_contact_time")) if me else None
    # Cached snapshot for read-only views (the app API), so they never call ManageEngine themselves.
    state["last_contact"] = seen
    state["managed"] = bool(me) and str(me.get("managed_status")) == MANAGED
    if me is None or str(me.get("managed_status")) != MANAGED:
        problem = "gone"
    elif seen is not None and now - seen >= STALE_SECONDS:
        problem = "silent"
    else:
        problem = None
    scan = bool(me and problem is None and seen is not None and now - seen >= SCAN_SECONDS
                and now - float(state.get("scan_at", 0)) >= SCAN_SECONDS)
    if scan:
        state["scan_at"] = now
    message = None
    if problem and state.get("alerted") != problem and not (problem == "silent" and state.get("alerted") == "gone"):
        state["alerted"] = problem
        message = GONE if problem == "gone" else SILENT
    elif problem is None and state.get("alerted"):
        state.pop("alerted")
        message = BACK
    return message, scan


def send(message: str, timeout: float = 8.0) -> bool:
    """To the owner's filter topic, the same route as the service healthcheck alerts."""
    import subprocess

    from aifilter.export_settings import bridge_executable

    command = bridge_executable()
    if command is None:
        return False
    try:
        return subprocess.run([command, "mirror", "--title", "סינון: ניהול המכשירים", "--session", "ai-filter-appeals",
                               "--no-translate"], input=message, text=True, timeout=timeout,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def watch(state_file, backend, now: float, notify=send) -> str | None:
    """One throttled look, called from the app tick. Returns a short log note, or None when not due."""
    from aifilter import mdm

    if not getattr(backend, "available", False) or not hasattr(backend, "devices"):
        return None
    ids = mdm.device_ids(backend)
    legacy = mdm.legacy_device(ids)
    try:
        root = mdm.read_state(state_file, legacy)
    except (OSError, ValueError):
        root = {"devices": {}}
    due = [did for did in ids if now - float(root["devices"].get(did, {}).get("checked_at", 0)) >= CHECK_SECONDS]
    if not due:
        return None
    try:
        devices = backend.devices()
    except Exception:  # noqa: BLE001 - an API outage is not a device problem
        devices = None
    notes = {}
    for did in due:
        state = root["devices"].get(did, {})
        state["checked_at"] = now
        before = state.get("alerted")
        message, scan = check(state, devices, did, now)
        if scan:
            try:
                mdm.for_device(backend, did).scan()
            except Exception:  # noqa: BLE001
                pass
        if message and (len(ids) > 1 or did == mdm.IPAD):
            label = mdm.device_label(did)
            message = f"{label}: " + message.replace("מהאייפון", f"מ{label}").replace("האייפון", label)
        if message and not notify(message):
            if before is None:
                state.pop("alerted", None)
            else:
                state["alerted"] = before
        mdm.save_device_state(state_file, did, state, legacy)
        notes[did] = "unreadable" if devices is None else state.get("alerted") or "managed"
    return "mdm: " + (notes[ids[0]] if len(ids) == 1 else "; ".join(f"{did}: {note}" for did, note in notes.items()))
