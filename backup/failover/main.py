"""Automatic failover: start the backup filter VM when the Mac's heartbeat goes stale.

Runs every 5 minutes (Cloud Scheduler -> this Cloud Run function).
- Heartbeat object older than STALE_MIN and VM stopped  -> start VM (label auto=1).
- Heartbeat fresh again (< FRESH_MIN) and VM was auto-started -> stop VM.
A manually started VM (no auto label) is never stopped here.
- An optional weekly pause prevents automatic starts and stops an auto-started VM.
"""
import datetime as dt
import os
from zoneinfo import ZoneInfo

import functions_framework
from google.cloud import compute_v1, storage

PROJECT = os.environ["PROJECT"]
ZONE = os.environ["ZONE"]
VM = os.environ["VM"]
BUCKET = os.environ["BUCKET"]
OBJ = os.environ.get("HEARTBEAT", "heartbeat")
STALE_MIN = int(os.environ.get("STALE_MIN", "10"))
FRESH_MIN = int(os.environ.get("FRESH_MIN", "8"))  # heartbeat every 3 min + scheduler every 5


PAUSE_ZONE = os.environ.get("FAILOVER_PAUSE_TIMEZONE")
PAUSE_START = dt.time.fromisoformat(os.environ["FAILOVER_PAUSE_START"]) if PAUSE_ZONE else None
PAUSE_END = dt.time.fromisoformat(os.environ["FAILOVER_PAUSE_END"]) if PAUSE_ZONE else None
PAUSE_TZ = ZoneInfo(PAUSE_ZONE) if PAUSE_ZONE else None


def is_shabbat(now):
    """Use the configured Friday-to-Saturday pause, if enabled."""
    if PAUSE_TZ is None:
        return False
    local = now.astimezone(PAUSE_TZ)
    return (local.weekday() == 4 and local.time() >= PAUSE_START) or (
        local.weekday() == 5 and local.time() < PAUSE_END
    )


def heartbeat_age_min(now):
    blob = storage.Client().bucket(BUCKET).get_blob(OBJ)
    if blob is None:
        return None
    return (now - blob.updated).total_seconds() / 60


def decide(age, status, auto, shabbat=False):
    """Pure decision: returns 'start', 'stop' or None. A missing heartbeat counts as stale."""
    if shabbat:
        return "stop" if status == "RUNNING" and auto else None
    stale = age is None or age >= STALE_MIN
    if stale and status == "TERMINATED":
        return "start"
    if not stale and age < FRESH_MIN and status == "RUNNING" and auto:
        return "stop"
    return None


def _set_auto(ic, inst, value):
    labels = dict(inst.labels or {})
    labels["auto"] = value
    req = compute_v1.InstancesSetLabelsRequest(labels=labels, label_fingerprint=inst.label_fingerprint)
    ic.set_labels(project=PROJECT, zone=ZONE, instance=VM, instances_set_labels_request_resource=req).result()


def act(ic, inst, action):
    """Ownership label is set before a start and cleared only after a stop has succeeded,
    so a failed stop is retried on the next tick instead of leaving a paid VM running."""
    if action == "start":
        _set_auto(ic, inst, "1")
        ic.start(project=PROJECT, zone=ZONE, instance=VM).result()
    elif action == "stop":
        ic.stop(project=PROJECT, zone=ZONE, instance=VM).result()
        _set_auto(ic, ic.get(project=PROJECT, zone=ZONE, instance=VM), "0")


@functions_framework.http
def tick(_request):
    now = dt.datetime.now(dt.timezone.utc)
    age = heartbeat_age_min(now)
    ic = compute_v1.InstancesClient()
    inst = ic.get(project=PROJECT, zone=ZONE, instance=VM)
    auto = (inst.labels or {}).get("auto") == "1"
    action = decide(age, inst.status, auto, is_shabbat(now))
    if action:
        act(ic, inst, action)
    msg = f"shabbat={is_shabbat(now)} age={age if age is None else round(age, 1)} status={inst.status} auto={auto} action={action}"
    print(msg)
    return msg
