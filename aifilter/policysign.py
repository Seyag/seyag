"""Signed filter policy for the companion iOS app (maintainer decision).

The committee (COMMITTEE.md: these rules plus committee.py on the Mac) is the only signer. The Ed25519 private key
lives only in the Mac Keychain: never printed, exported, written to a file or put on the phone. The app pins the
public key in its build and accepts only documents signed by it.

Payload (exact bytes are signed): {"version": int, strictly increasing, "locked": bool, "rules": {name: bool}}.
A rule left out counts as on. Tightening signs at once. Loosening (a rule on -> off, or locked true -> false) needs a
recorded request confirmed again after 24 hours (rule 7) and is never signed at night 23:00-06:00 (rule 6).
"""
from __future__ import annotations

import base64
import json
import subprocess
import time
import uuid
from datetime import datetime
from pathlib import Path

from aifilter.export_settings import optional_path
from zoneinfo import ZoneInfo

RULES = ("approvedChats", "contactsOnly", "mediaFilter", "sensitiveContent", "stickerPacks", "linkPreviews",
         "linksOutside", "search", "stories", "adMedia", "otherBotWidgets")
CONFIRM_AFTER = 24 * 3600
ISRAEL = ZoneInfo("Asia/Jerusalem")
KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT = "dev.example.ai-filter.committee", "ed25519-policy-signing"
_SCRIPTS = optional_path("AIFILTER_KEYCHAIN_HELPERS", directory=True)


class PolicyError(ValueError):
    pass


def night(now: float) -> bool:
    h = datetime.fromtimestamp(now, ISRAEL).hour
    return h >= 23 or h < 6


class KeychainKey:
    """Raw 32-byte Ed25519 seed in the Keychain (base64), created once; read only inside this process."""

    def load(self) -> bytes | None:
        if _SCRIPTS is None:
            return None
        r = subprocess.run(["swift", str(_SCRIPTS / "keychain-read.swift"), KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT],
                           capture_output=True, timeout=120, check=False)
        return base64.b64decode(r.stdout.strip()) if r.returncode == 0 and r.stdout.strip() else None

    def create(self, seed: bytes) -> None:
        if _SCRIPTS is None:
            raise PolicyError("keychain helpers are not configured")
        r = subprocess.run(["swift", str(_SCRIPTS / "keychain-store.swift"), KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT,
                            "ai-filter committee policy signing key", "add"],
                           input=base64.b64encode(seed), capture_output=True, timeout=120, check=False)
        if r.returncode != 0:
            raise PolicyError("could not store the signing key in the Keychain")


def _private(keystore, create: bool):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

    seed = keystore.load()
    if seed is None:
        if not create:
            raise PolicyError("no committee signing key yet (run: committee.py public-key)")
        key = Ed25519PrivateKey.generate()
        keystore.create(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
        seed = keystore.load()
        if seed is None:
            raise PolicyError("signing key not readable after creating it")
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key(keystore) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return base64.b64encode(_private(keystore, create=True).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)).decode()


STRICTEST = {"version": 0, "locked": True, "rules": {}}  # the baseline before any signature: locked, all rules on


class _Lock:
    """One committee.py at a time per state file (fcntl), so two signers cannot race on version or a request."""

    def __init__(self, state_file: Path):
        self.path = Path(str(state_file) + ".lock")

    def __enter__(self):
        import fcntl

        self.fh = open(self.path, "a")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        self.fh.close()


def _load(state_file: Path) -> dict:
    """A missing file is a fresh committee (strictest baseline); a file that exists but cannot be read refuses."""
    if not state_file.exists():
        state = {}
    else:
        try:
            state = json.loads(state_file.read_text())
        except (OSError, ValueError):
            raise PolicyError("committee policy state is unreadable: refusing to sign") from None
        if not isinstance(state, dict):
            raise PolicyError("committee policy state is damaged: refusing to sign")
    state.setdefault("last", None)
    state.setdefault("requests", [])
    state.setdefault("log", [])
    return state


def _save(state_file: Path, state: dict) -> None:
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, ensure_ascii=False))
    tmp.replace(state_file)


def loosenings(old: dict | None, new: dict) -> list[str]:
    """What the new document loosens compared with the last signed one (none yet: the strictest baseline)."""
    old = old or STRICTEST
    old_rules = old.get("rules", {})
    out = [r for r in RULES if old_rules.get(r, True) and not new["rules"].get(r, True)]
    if old.get("locked", True) and not new["locked"]:
        out.append("locked")
    return out


def _check_payload(p) -> dict:
    if not isinstance(p, dict) or set(p) != {"version", "locked", "rules"}:
        raise PolicyError("payload must have exactly version, locked, rules")
    if type(p["version"]) is not int or not 0 < p["version"] < 2 ** 63 or type(p["locked"]) is not bool:
        raise PolicyError("version must be a positive int64 and locked a bool")
    if not isinstance(p["rules"], dict) or not set(p["rules"]) <= set(RULES) \
            or any(type(v) is not bool for v in p["rules"].values()):
        raise PolicyError(f"rules must map names from {', '.join(RULES)} to bools")
    return p


def request(state_file: Path, text: str, loosen: list[str], now: float | None = None) -> dict:
    """Record the owner's request to loosen exactly these items (rule names or "locked"); rule 7's clock starts."""
    now = time.time() if now is None else now
    scope = sorted(set(loosen))
    if not scope or not set(scope) <= set(RULES) | {"locked"}:
        raise PolicyError(f"name what to loosen: {', '.join(RULES)} or locked")
    with _Lock(state_file):
        state = _load(state_file)
        item = {"id": uuid.uuid4().hex[:8], "at": now, "text": text[:300], "loosen": scope, "confirmed_at": None,
                "decision": None, "used": False}
        state["requests"].append(item)
        _save(state_file, state)
    return item


def verified_answer(record: dict, bridge_key: str, owner_id: int) -> dict:
    """The owner's panel answer as signed by the companion bridge (ai-filter#2). Every field the gate uses comes from
    the verified payload, never from the record's unsigned fields. Anything missing, unpinned or wrong refuses."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not bridge_key or not isinstance(owner_id, int) or owner_id <= 0:
        raise PolicyError("the bridge signing key or the owner id is not pinned in config [committee]")
    sig = (record or {}).get("answer_sig")
    if not isinstance(sig, dict) or sig.get("key") != bridge_key:
        raise PolicyError("the answer is not signed by the pinned bridge key")
    try:
        body = base64.b64decode(sig["payload"], validate=True)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(bridge_key, validate=True)).verify(
            base64.b64decode(sig["signature"], validate=True), body)
        obj = json.loads(body)
    except (KeyError, TypeError, ValueError, InvalidSignature):
        raise PolicyError("the answer's signature does not verify") from None
    if not isinstance(obj, dict) or obj.get("v") != 1 or obj.get("kind") != "companion-decision-answer" \
            or obj.get("via") != "panel" or obj.get("routine") is not False or obj.get("by") != owner_id:
        raise PolicyError("the signed answer is not the owner's own panel answer")
    return {"id": obj.get("id"), "state": "answered", "choice": obj.get("choice"), "routine": False,
            "title": obj.get("title", ""), "created": obj.get("created", 0), "closed": obj.get("closed", 0)}


def confirm(state_file: Path, rid: str, decision: dict) -> dict:
    """The owner's calm re-confirmation, proven by his own tap on a control-panel decision: answered yes, not a
    routine card, its question names this request id, asked 24 hours or more after the request, and answered
    outside the night. Each decision confirms one request once."""
    if not isinstance(decision, dict) or decision.get("state") != "answered" or decision.get("choice") != "yes" \
            or decision.get("routine") is True:
        raise PolicyError("needs the owner's yes on a control-panel decision (not a routine card)")
    with _Lock(state_file):
        state = _load(state_file)
        item = next((r for r in state["requests"] if r["id"] == rid), None)
        if item is None:
            raise PolicyError("no such request")
        if rid not in str(decision.get("title", "")):
            raise PolicyError("the decision's question must name this request id")
        asked, answered = float(decision.get("created", 0)), float(decision.get("closed", 0))
        if asked - item["at"] < CONFIRM_AFTER or answered < asked:
            raise PolicyError("rule 7: confirmation counts only 24 hours after the request")
        if night(answered):
            raise PolicyError("rule 6: no loosening at night (23:00-06:00)")
        if any(r.get("decision") == decision.get("id") for r in state["requests"]):
            raise PolicyError("this decision already confirmed a request")
        item["confirmed_at"], item["decision"] = answered, decision.get("id")
        _save(state_file, state)
    return item


def sign(state_file: Path, payload: dict, keystore, request_id: str = "", now: float | None = None) -> dict:
    now = time.time() if now is None else now
    p = _check_payload(payload)
    with _Lock(state_file):
        return _sign_locked(state_file, p, keystore, request_id, now)


def _sign_locked(state_file: Path, p: dict, keystore, request_id: str, now: float) -> dict:
    state = _load(state_file)
    last = state["last"]
    if last and p["version"] <= last["version"]:
        raise PolicyError(f"version must be above {last['version']}")
    loose = loosenings(last, p)
    used = None
    if loose:
        if night(now):
            raise PolicyError("rule 6: no loosening at night (23:00-06:00)")
        used = next((r for r in state["requests"] if r["id"] == request_id and r["confirmed_at"]
                     and not r["used"] and set(loose) <= set(r.get("loosen") or [])), None)
        if used is None:
            raise PolicyError(f"rule 7: loosening {', '.join(loose)} needs a request for exactly that, "
                              "confirmed by the owner after 24 hours")
    body = json.dumps(p, separators=(",", ":"), ensure_ascii=False).encode()
    key = _private(keystore, create=False)
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    doc = {"payload": base64.b64encode(body).decode(), "signature": base64.b64encode(key.sign(body)).decode(),
           "publicKey": base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()}
    if used:
        used["used"] = True
    state["last"] = p
    state["log"].append({"t": now, "version": p["version"], "loosened": loose, "request": used and used["id"]})
    _save(state_file, state)
    return doc
