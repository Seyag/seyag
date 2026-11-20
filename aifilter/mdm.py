"""MDM backends for app installs on managed devices (scripts/app_request.py).

The App Store is locked through the MDM; an approved app request opens a short install window.
config.toml `[mdm] backend` picks one: "none" (no MDM API) or "manageengine" (ManageEngine MDM cloud, US).
CLI for the lead (metadata only, never secrets):
  python -m aifilter.mdm devices | apps | profiles | draft
`draft` creates (or finds) the filter's own profile with App Store installs allowed and reads it back,
without publishing or associating anything.
"""
from __future__ import annotations

import copy
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from aifilter.export_settings import optional_path


class MDMUnavailable(RuntimeError):
    pass


class MDMError(RuntimeError):
    """An MDM API call failed. Messages carry the method, path and HTTP status only: never tokens or bodies."""


class NoMDM:
    """No MDM API access: nothing can be unlocked, so approvals wait for the committee."""
    name, available = "none", False

    def installed_apps(self) -> set[str]:
        raise MDMUnavailable("no MDM backend configured")

    def unlock(self, minutes: int) -> None:
        raise MDMUnavailable("no MDM backend configured")

    def lock(self) -> None:
        raise MDMUnavailable("no MDM backend configured")

    def block_app(self, bundle: str) -> None:
        raise MDMUnavailable("no MDM backend configured")


BASE = "https://mdm.manageengine.com/api/v1/mdm"
KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT = "dev.example.manageengine", "api-oauth"
KEYCHAIN_READER = optional_path("AIFILTER_KEYCHAIN_HELPERS", "keychain-read.swift")
KEYCHAIN_STORE = optional_path("AIFILTER_KEYCHAIN_HELPERS", "keychain-store.swift")
TOKEN_ACCOUNT = "access-token-cache"  # short-lived access token shared by all filter processes (Zoho limits refreshes)
PROFILE_NAME = "סינון הבית: אפליקציות"
PROFILE_MARK = "Owned by ai-filter (aifilter/mdm.py): App Store install window and blocked apps."
RESTRICTIONS = "restrictionspolicy"
INSTALL_KEY = "allow_app_installation"  # iOS restrictions payload: "Users can install unapproved apps"
REMOVAL_KEY = "allow_app_removal"  # always false in the filter's profile: apps cannot be deleted (maintainer decision)
# Committee tightening 2026-11-16 (owner flagged TV/iTunes built-in apps); loosening only through COMMITTEE.md.
CONTENT_RESTRICTIONS = {
    "allow_itunes": False,
    "allow_news": False,
    "allow_podcasts": False,
    "allow_explicit_content": False,
    "allow_ibookstore_erotica_media": False,
    "allow_app_clips": False,
    "allow_marketplace_app_installation": False,
    "allow_web_distribution_app_installation": False,
    "is_rating_enabled": True,
    "country_code": "us",
    "movies_rating_value": "0",
    "tv_shows_rating_value": "0",
}
IOS = 1  # platform_type / platform of iOS (the API returns it as the string "1")
PUBLISHED = 110  # profile_status_id of a published profile (1 = yet to deploy; returned as strings)
# Never blocked, whatever an install-window diff says: Apple system apps, the filter route (Tailscale), the
# owner's Telegram way in (companion) and the MDM's own agent. Blocking one would cut the filter or the MDM.
NEVER_BLOCK = ("com.apple.", "io.tailscale.", "com.example.companion", "com.manageengine.")
_ACCOUNTS = re.compile(r"https://accounts\.zoho\.(?:com|eu|in|com\.au|com\.cn|jp|ca|sa|uk)")
_BUNDLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,199}")
_ID = re.compile(r"[0-9]{1,20}")

# Every call the backend may make. Anything else (DELETE, device commands, other payloads) is refused
# before it leaves the process. Writes that touch a profile are further limited to the filter's own profile.
_ALLOWED = [
    ("GET", r"/devices"), ("GET", r"/devices/{id}"), ("GET", r"/devices/{id}/apps"),
    ("GET", r"/devices/{id}/profiles"), ("POST", r"/devices/{id}/profiles"),
    ("GET", r"/profiles"), ("POST", r"/profiles"), ("GET", r"/profiles/{id}"),
    ("GET", r"/profiles/{id}/payloads"), ("GET", r"/profiles/{id}/payloads/restrictionspolicy"),
    ("POST", r"/profiles/{id}/payloads/restrictionspolicy"),
    ("GET", r"/profiles/{id}/payloads/restrictionspolicy/payloaditems/{id}"),
    ("PUT", r"/profiles/{id}/payloads/restrictionspolicy/payloaditems/{id}"),
    ("POST", r"/profiles/{id}/publish"),
    ("GET", r"/blacklist/apps"), ("POST", r"/blacklist/apps"), ("POST", r"/blacklist/devices"),
    ("GET", r"/blacklist/status"),
    # The one device action allowed (lead decision 2026-11-14): an inventory scan, so the app list is current.
    ("POST", r"/devices/{id}/actions/scan"),
]
_ALLOWED_RE = [(m, re.compile(p.replace("{id}", "[0-9]{1,20}"))) for m, p in _ALLOWED]


def _allowed(method: str, path: str) -> bool:
    return any(m == method and rx.fullmatch(path) for m, rx in _ALLOWED_RE)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # the Authorization header must never follow a redirect
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _urllib_transport(method: str, url: str, headers: dict, body: bytes | None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with _OPENER.open(req, timeout=30) as r:  # noqa: S310 - fixed https hosts, checked by the caller
            return r.status, r.read(5_000_000)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(20_000)


def _keychain_reader() -> bytes:
    """The OAuth JSON item, read inside this process only (stdout pipe, never argv, never a file)."""
    if KEYCHAIN_READER is None:
        raise MDMUnavailable("keychain helpers are not configured")
    try:
        r = subprocess.run(["swift", str(KEYCHAIN_READER), KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT],
                           capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MDMUnavailable(f"Keychain reader failed to run ({type(exc).__name__})") from None
    if r.returncode != 0 or not r.stdout:
        raise MDMUnavailable(f"Keychain item {KEYCHAIN_SERVICE}/{KEYCHAIN_ACCOUNT} unreadable "
                             f"(exit {r.returncode})")
    return r.stdout


class KeychainTokenCache:
    """The 1-hour access token in the Keychain, so separate processes (tick, CLI, panel) do not each refresh it:
    Zoho allows about 10 refreshes per 10 minutes and then blocks for a while. Never in a file or argv."""

    def load(self) -> tuple[str, float] | None:
        if KEYCHAIN_READER is None:
            return None
        try:
            r = subprocess.run(["swift", str(KEYCHAIN_READER), KEYCHAIN_SERVICE, TOKEN_ACCOUNT],
                               capture_output=True, timeout=120, check=False)
            data = json.loads(r.stdout) if r.returncode == 0 and r.stdout else None
            return (str(data["token"]), float(data["until"])) if isinstance(data, dict) else None
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
            return None

    def save(self, token: str, until: float) -> None:
        value = json.dumps({"token": token, "until": until}).encode()
        if KEYCHAIN_STORE is None:
            return
        for mode in ("replace", "add"):
            try:
                if subprocess.run(["swift", str(KEYCHAIN_STORE), KEYCHAIN_SERVICE, TOKEN_ACCOUNT,
                                   "ai-filter MDM access token cache", mode], input=value,
                                  capture_output=True, timeout=120, check=False).returncode == 0:
                    return
            except (OSError, subprocess.TimeoutExpired):
                return


def _err_code(raw: bytes) -> str:
    try:
        data = json.loads(raw or b"{}")
    except ValueError:
        return ""
    if not isinstance(data, dict):
        return ""
    code = data.get("error_code") or data.get("error") or data.get("code") or ""
    return re.sub(r"[^A-Za-z0-9_.-]", "", str(code))[:40]


def _true(v) -> bool:
    """ManageEngine returns booleans as JSON booleans in some responses and as "true"/"false" in others."""
    return v is True or str(v).lower() == "true"


def _num(x) -> int:
    s = str(x)
    if not _ID.fullmatch(s):
        raise MDMError("unexpected id in MDM response")
    return int(s)


IPHONE = "101"
IPAD = "102"


def configured_device_ids() -> tuple[str, ...]:
    from aifilter import config
    cfg = config.load()
    ids = cfg.get("mdm", "device_ids")
    if ids is None:
        ids = [cfg.get("mdm", "device_id")]
    if not isinstance(ids, (list, tuple)) or not ids or any(not _ID.fullmatch(str(d)) for d in ids):
        raise MDMUnavailable("config.toml [mdm] device_ids is missing or invalid")
    return tuple(dict.fromkeys(str(d) for d in ids))


def device_ids(backend) -> tuple[str, ...]:
    """The configured fleet; older backends still expose only device_id."""
    ids = getattr(backend, "device_ids", None)
    return tuple(str(d) for d in ids) if ids else (str(getattr(backend, "device_id", "default")),)


def primary_device(ids) -> str:
    return IPHONE if IPHONE in ids else ids[0]


def legacy_device(ids) -> str:
    # A direct iPad-only invocation must never adopt or edit the original iPhone profile/state.
    return IPHONE if IPHONE in ids or IPAD in ids else ids[0]


def resolve_device(backend, target=None) -> str:
    ids = device_ids(backend)
    target = primary_device(ids) if target is None else {"iphone": IPHONE, "ipad": IPAD}.get(str(target).lower(), str(target))
    if target not in ids:
        raise ValueError("target device is not configured")
    return target


def for_device(backend, target):
    target = resolve_device(backend, target)
    return backend.for_device(target) if hasattr(backend, "for_device") else backend


def device_label(device_id) -> str:
    return {IPHONE: "האייפון", IPAD: "האייפד"}.get(str(device_id), str(device_id))


def read_state(path: Path, legacy_device: str) -> dict:
    """Move the complete legacy record to its original device, never to a newly selected target."""
    state = json.loads(path.read_text()) if path.exists() else {}
    if not isinstance(state, dict):
        raise ValueError("invalid MDM state")
    if "devices" not in state:
        state = {"devices": {str(legacy_device): state} if state else {}}
    if not isinstance(state["devices"], dict):
        raise ValueError("invalid device state")
    return state


_state_locks = threading.local()


@contextmanager
def state_lock(path: Path):
    """Serialize complete transactions; nested saves reuse this thread's file lock."""
    key = (os.getpid(), path.resolve())
    held = getattr(_state_locks, "held", None)
    if held is None:
        held = _state_locks.held = set()
    if key in held:
        yield
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(path.suffix + ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)  # wait for an in-flight tick/request instead of dropping the request
        held.add(key)
        try:
            yield
        finally:
            held.remove(key)


def save_device_state(path: Path, device_id: str, state: dict, legacy_device: str):
    # Merge peer records atomically; callers also hold state_lock across read, MDM calls and save.
    with state_lock(path):
        root = read_state(path, legacy_device)
        root["devices"][str(device_id)] = state
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, prefix=path.name + ".", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            try:
                tmp.write(json.dumps(root, indent=1, ensure_ascii=False))
                tmp.close()
                tmp_path.replace(path)
            finally:
                tmp_path.unlink(missing_ok=True)


class ManageEngineMDM:
    """ManageEngine MDM cloud. OAuth item: Keychain `dev.example.manageengine/api-oauth`
    (client_id, client_secret, refresh_token, accounts); the access token lives in memory only.
    Each instance targets one configured device; for_device selects another without sharing its profile.
    unlock / lock publish that device's restrictions. block_app, installed_apps and scan also target only it.
    CLI fleet operations and app_request.tick iterate device_ids, continuing past individual failures."""
    name, available = "manageengine", True

    def __init__(self, device_id: str | None = None, state_file: Path | None = None, transport=None,
                 read_secret=None, clock=time.time, token_cache=None, device_ids=None):
        self._device_id = device_id
        self._device_ids = (tuple(dict.fromkeys(str(d) for d in device_ids)) if device_ids is not None
                            else ((str(device_id),) if device_id is not None else None))
        self._state_file = state_file
        self._transport = transport or _urllib_transport
        self._read_secret = read_secret or _keychain_reader
        self._clock = clock
        self._cred: dict | None = None
        self._token: str | None = None
        self._token_until = 0.0
        # Real runs share the token through the Keychain; tests (own transport) never touch it.
        self._token_cache = token_cache if token_cache is not None else (KeychainTokenCache() if transport is None else None)

    def __repr__(self):  # never show credentials
        return "ManageEngineMDM()"

    # ---- configuration and local state ----
    @property
    def device_ids(self) -> tuple[str, ...]:
        if self._device_ids is None:
            self._device_ids = configured_device_ids()
        if not self._device_ids or any(not _ID.fullmatch(d) for d in self._device_ids):
            raise MDMUnavailable("invalid managed device ids")
        return self._device_ids

    @property
    def device_id(self) -> int:
        target = str(self._device_id) if self._device_id is not None else primary_device(self.device_ids)
        if target not in self.device_ids:
            raise MDMUnavailable("target device is not configured")
        return int(target)

    def for_device(self, target):
        child = copy.copy(self)
        child._device_id = resolve_device(self, target)
        return child

    @property
    def profile_name(self) -> str:
        # Keep the original iPhone profile; other devices need independent payloads. Publishing a shared
        # payload would change every associated device, even if the association POST names only one.
        if str(self.device_id) == legacy_device(self.device_ids):
            return PROFILE_NAME
        return f"{PROFILE_NAME} ({self.device_id})"

    @property
    def state_file(self) -> Path:
        if self._state_file is None:
            from aifilter import config
            self._state_file = config.db_path().parent / "mdm-state.json"
        return self._state_file

    def _load(self) -> dict:
        root = read_state(self.state_file, legacy_device(self.device_ids))
        state = root["devices"].get(str(self.device_id), {})
        state.setdefault("blocked", {})
        return state

    def _save(self, state: dict):
        save_device_state(self.state_file, str(self.device_id), state, legacy_device(self.device_ids))

    # ---- OAuth and HTTP ----
    def _credentials(self) -> dict:
        if self._cred is None:
            try:
                cred = json.loads(self._read_secret())
            except ValueError:
                raise MDMUnavailable("Keychain item is not JSON") from None
            need = ("client_id", "client_secret", "refresh_token", "accounts")
            if not isinstance(cred, dict) or not all(isinstance(cred.get(k), str) and cred[k] for k in need):
                raise MDMUnavailable("Keychain item lacks client_id/client_secret/refresh_token/accounts")
            accounts = cred["accounts"].rstrip("/")
            if not _ACCOUNTS.fullmatch(accounts):
                raise MDMUnavailable("Keychain item has an unexpected accounts URL")
            self._cred = {k: cred[k] for k in need[:3]} | {"accounts": accounts}
        return self._cred

    def _access_token(self, force=False) -> str:
        if self._token and not force and self._clock() < self._token_until:
            return self._token
        if not force and self._token_cache is not None:
            cached = self._token_cache.load()
            if cached and cached[0] and self._clock() < cached[1]:
                self._token, self._token_until = cached
                return self._token
        cred = self._credentials()
        body = urllib.parse.urlencode({"grant_type": "refresh_token", "refresh_token": cred["refresh_token"],
                                       "client_id": cred["client_id"],
                                       "client_secret": cred["client_secret"]}).encode()
        status, raw = self._transport("POST", cred["accounts"] + "/oauth/v2/token",
                                      {"Content-Type": "application/x-www-form-urlencoded"}, body)
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {}
        token = data.get("access_token") if isinstance(data, dict) else None
        if status != 200 or not isinstance(token, str) or not token:
            hint = " (Zoho allows about 10 refreshes per 10 minutes; retry later)" \
                if _err_code(raw) == "AccessDenied" else ""
            raise MDMError(f"OAuth token refresh failed: HTTP {status} {_err_code(raw)}".strip() + hint)
        try:
            ttl = max(60, min(int(data.get("expires_in", 3600)), 3600))
        except (TypeError, ValueError):
            ttl = 3600
        self._token, self._token_until = token, self._clock() + ttl - 60
        if self._token_cache is not None:
            self._token_cache.save(token, self._token_until)
        return token

    def _call(self, method: str, path: str, body=None, query: dict | None = None, missing_ok=False) -> dict:
        if not _allowed(method, path):
            raise MDMError(f"refused: {method} {path} is not on the allowed MDM call list")
        url = BASE + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = None if body is None else json.dumps(body).encode()
        for attempt in (0, 1):
            headers = {"Authorization": "Zoho-oauthtoken " + self._access_token(force=attempt == 1),
                       "Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            status, raw = self._transport(method, url, headers, data)
            if status != 401:
                break
        if status == 404 and missing_ok:
            return {}
        if status not in (200, 201, 202, 204):
            raise MDMError(f"{method} {path}: HTTP {status} {_err_code(raw)}".strip())
        if not raw:
            return {}
        try:
            out = json.loads(raw)
        except ValueError:
            raise MDMError(f"{method} {path}: response is not JSON") from None
        return out if isinstance(out, dict) else {"items": out}

    def _get_all(self, path: str, key: str) -> list:
        """A list endpoint, following ManageEngine's paging.next (same host and path only)."""
        # /blacklist/apps rejects the limit parameter (HTTP 400 IAM0028, seen live 2026-11-15)
        items, query = [], ({} if path.startswith("/blacklist") else {"limit": 200})
        for _ in range(50):
            page = self._call("GET", path, query=query)
            got = page.get(key) or []
            if not isinstance(got, list):
                raise MDMError(f"GET {path}: '{key}' is not a list")
            items += got
            nxt = (page.get("paging") or {}).get("next") if isinstance(page.get("paging"), dict) else None
            if not got or not nxt:
                return items
            u = urllib.parse.urlsplit(nxt)
            if u.netloc != urllib.parse.urlsplit(BASE).netloc or not u.path.endswith(path):
                raise MDMError(f"GET {path}: unexpected paging link")
            query = dict(urllib.parse.parse_qsl(u.query))
        raise MDMError(f"GET {path}: too many pages")

    # ---- the filter's own profile ----
    def _owned_profile(self, state: dict, create: bool) -> int | None:
        pid = state.get("profile_id")
        if pid:
            p = self._call("GET", f"/profiles/{_num(pid)}")
            if _true(p.get("is_moved_to_trash")) or p.get("profile_name") != self.profile_name:
                raise MDMError("the filter's profile was trashed or renamed in ManageEngine; check by hand")
            return _num(pid)
        for p in self._get_all("/profiles", "profiles"):  # adopt ours only (same name AND ownership mark)
            if p.get("profile_name") == self.profile_name and p.get("profile_description") == PROFILE_MARK \
                    and str(p.get("platform_type")) == str(IOS) and not _true(p.get("is_moved_to_trash")):
                state["profile_id"] = str(_num(p["profile_id"]))
                self._save(state)
                return _num(p["profile_id"])
        if not create:
            return None
        p = self._call("POST", "/profiles", {"profile_name": self.profile_name, "profile_description": PROFILE_MARK,
                                             "platform_type": IOS, "scope": 0})
        state["profile_id"] = str(_num(p["profile_id"]))
        state.pop("payload_id", None)
        self._save(state)
        return _num(p["profile_id"])

    def _ensure_restrictions(self, pid: int, state: dict, allow: bool) -> bool:
        """The profile's restrictions payload with installs allowed or not. True when anything changed."""
        path = f"/profiles/{pid}/payloads/{RESTRICTIONS}"
        items = self._call("GET", path, missing_ok=True).get("payloaditems") or []  # 404 until one exists
        if not items:
            self._call("POST", path, {INSTALL_KEY: allow, REMOVAL_KEY: False, **CONTENT_RESTRICTIONS})
            items = self._call("GET", path).get("payloaditems") or []
            if not items:
                raise MDMError(f"POST {path}: payload not created")
            state["payload_id"] = str(_num(items[0]))
            self._save(state)
            return True
        item_id = _num(items[0])
        state["payload_id"] = str(item_id)
        cur = self._call("GET", f"{path}/payloaditems/{item_id}")
        required = {INSTALL_KEY: allow, REMOVAL_KEY: False, **CONTENT_RESTRICTIONS}
        if all(str(cur.get(key)).lower() == str(value).lower() for key, value in required.items()):
            return False
        new = {k: v for k, v in cur.items() if k != "payload_id"} | required
        self._call("PUT", f"{path}/payloaditems/{item_id}", new)
        return True

    def _set_installs(self, allow: bool):
        with state_lock(self.state_file):
            self._set_installs_locked(allow)

    def _set_installs_locked(self, allow: bool):
        state = self._load()
        pid = self._owned_profile(state, create=True)
        changed = self._ensure_restrictions(pid, state, allow)
        if changed or str(self._call("GET", f"/profiles/{pid}").get("profile_status_id")) != str(PUBLISHED):
            self._call("POST", f"/profiles/{pid}/publish")
        self._call("POST", f"/devices/{self.device_id}/profiles", {"profile_ids": [pid]})
        state["allow_installs"], state["changed_at"] = allow, int(self._clock())
        self._save(state)

    # ---- the four backend operations ----
    def scan(self) -> None:
        """Ask this device for a fresh inventory (apps, profiles). Read-only on the device."""
        self._call("POST", f"/devices/{self.device_id}/actions/scan")

    def installed_apps(self) -> set[str]:
        """Bundle ids in this device's app inventory. An empty inventory is an error, never an empty set: the
        install-window diff would otherwise treat every app found by a later scan as new and block it."""
        apps = self._get_all(f"/devices/{self.device_id}/apps", "installed_apps")
        got = {a["identifier"] for a in apps if isinstance(a, dict) and isinstance(a.get("identifier"), str)
               and _BUNDLE.fullmatch(a["identifier"])}
        if not got:
            raise MDMError("the device's app inventory is empty in ManageEngine (no app scan yet)")
        return got

    def unlock(self, minutes: int) -> None:
        if not isinstance(minutes, int) or not 1 <= minutes <= 120:
            raise ValueError("minutes must be 1-120")
        self._set_installs(True)  # app_request.tick locks again when the window ends

    def lock(self) -> None:
        self._set_installs(False)

    def block_app(self, bundle: str) -> bool:
        """Blocklist one app on this device. False (nothing sent) for a NEVER_BLOCK app."""
        with state_lock(self.state_file):
            return self._block_app_locked(bundle)

    def _block_app_locked(self, bundle: str) -> bool:
        if not isinstance(bundle, str) or not _BUNDLE.fullmatch(bundle):
            raise ValueError("bad bundle id")
        if any(bundle.lower().startswith(p) for p in NEVER_BLOCK):
            return False
        state = self._load()
        gid = state["blocked"].get(bundle)
        if not gid:
            for a in self._get_all("/blacklist/apps", "apps"):
                if str(a.get("identifier", "")).lower() == bundle.lower() and str(a.get("platform")) == str(IOS):
                    gid = str(_num(a["appgroupid"]))
                    break
        if not gid:
            got = self._call("POST", "/blacklist/apps",
                             {"apps": [{"identifier": bundle, "platform": IOS, "appname": bundle}]})
            match = [a for a in got.get("apps") or [] if str(a.get("identifier", "")).lower() == bundle.lower()]
            if not match or not match[0].get("appgroupid"):  # live 2026-11-15: the POST answer omits the id
                match = [a for a in self._get_all("/blacklist/apps", "apps")
                         if str(a.get("identifier", "")).lower() == bundle.lower() and str(a.get("platform")) == str(IOS)]
            if not match or not match[0].get("appgroupid"):
                raise MDMError("POST /blacklist/apps: no app group id returned")
            gid = str(_num(match[0]["appgroupid"]))
        state["blocked"][bundle] = gid  # recorded before the push: a retry reuses the same app group
        self._save(state)
        self._call("POST", "/blacklist/devices", {"resource_ids": [self.device_id], "app_group_ids": [_num(gid)]})
        return True

    # ---- read-only views for the CLI ----
    def devices(self) -> list[dict]:
        keep = ("device_id", "device_name", "platform_type", "model", "os_version", "is_supervised",
                "managed_status", "last_contact_time")
        return [{k: d.get(k) for k in keep if k in d} for d in self._get_all("/devices", "devices")]

    def profiles(self) -> list[dict]:
        keep = ("profile_id", "profile_name", "platform_type", "profile_status", "profile_version", "payloads")
        return [{k: p.get(k) for k in keep if k in p} for p in self._get_all("/profiles", "profiles")]

    def draft(self) -> dict:
        """Create or find the filter's profile with installs ALLOWED; no publish, no association."""
        with state_lock(self.state_file):
            return self._draft_locked()

    def _draft_locked(self) -> dict:
        state = self._load()
        pid = self._owned_profile(state, create=True)
        self._ensure_restrictions(pid, state, allow=True)
        p = self._call("GET", f"/profiles/{pid}")
        item = self._call("GET", f"/profiles/{pid}/payloads/{RESTRICTIONS}/payloaditems/{_num(state['payload_id'])}")
        return {"profile_id": pid, "profile_name": p.get("profile_name"), "status": p.get("profile_status"),
                "version": p.get("profile_version"), "payloads": p.get("payloads"),
                INSTALL_KEY: item.get(INSTALL_KEY), "payload_keys": len(item)}


BACKENDS = {"none": NoMDM, "manageengine": ManageEngineMDM}


def backend(name: str | None):
    try:
        return BACKENDS[name or "none"]()
    except KeyError:
        raise ValueError(f"unknown mdm backend: {name!r}") from None


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv not in (["devices"], ["apps"], ["profiles"], ["draft"], ["scan"], ["lock"]):
        print("usage: python -m aifilter.mdm devices | apps | profiles | draft | scan | lock", file=sys.stderr)
        return 2
    me = ManageEngineMDM(device_id=os.environ.get("AIFILTER_MDM_DEVICE"))
    try:
        if argv == ["devices"]:
            out = me.devices()
        elif argv == ["profiles"]:
            out = me.profiles()
        else:
            out = {}
            for did in me.device_ids:
                target = me.for_device(did)
                try:
                    if argv == ["apps"]:
                        apps = sorted(target.installed_apps())
                        result = {"count": len(apps), "apps": apps}
                    elif argv == ["scan"]:
                        target.scan()
                        result = {"scan": "requested"}
                    elif argv == ["lock"]:
                        target.lock()
                        result = {"lock": "pushed"}
                    else:
                        result = target.draft()
                    out[did] = result
                except (MDMError, MDMUnavailable, ValueError) as exc:
                    out[did] = {"error": str(exc)}
            if any("error" in result for result in out.values()):
                print(json.dumps(out, ensure_ascii=False))
                return 1
    except (MDMError, MDMUnavailable, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(out, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
