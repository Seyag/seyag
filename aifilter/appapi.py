"""Usage: .venv/bin/python -m aifilter.appapi   (serves 127.0.0.1:[appapi] port; publish with `tailscale serve` only)

Publish exactly once, tailnet only (never Funnel), before starting it:
    tailscale serve --bg --https=8140 http://127.0.0.1:8140
At startup the server reads `tailscale serve status --json` and refuses to start unless https :8140 "/" is the
only Serve route to 127.0.0.1:8140, with no other path on that port, no other port or TCP forward to it, and no
Funnel on it.

JSON API for the owner's native committee app (status, requests, switches, chat, devices, audit).

Security model:
- Binds to 127.0.0.1 only. Tailscale Serve (never Funnel) proxies to it and adds the caller's
  `Tailscale-User-Login` header; a request is served only when it comes from 127.0.0.1, carries that
  header, and the login is in `[appapi] owners` (empty list = nobody). Browser requests (any Origin
  header) and non-JSON posts are refused, so a web page cannot ride on the tailnet identity.
- Tightening switches apply at once. Every domain loosening goes through `Store.loosen()` with
  `require_request=True` (night, 7-day denial, list/policy and a confirmed committee request); its
  refusal is returned verbatim. Other loosenings are only queued as committee requests.
- NEVER_SWITCHES and store.NEVER_LOOSEN hosts (COMMITTEE.md rule 4) are refused server-side whatever the input.
- Every mutating call, refused or not, appends to the committee audit log (who, what, result); calls that fail
  authentication are logged as `unverified:<claimed login>`.
- The filter proxy refuses this API's port on the Mac's own addresses (addon.protected_ports), because a
  request relayed by the proxy would reach Serve as the Mac and carry the Mac owner's login. Accepted residual
  risk: a process running on the Mac itself can call 127.0.0.1 with any header (it can already edit the DB).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aifilter import committeechat, config, mdm, policysign  # noqa: E402
from aifilter.mcp_server import Committee  # noqa: E402
from aifilter.schedules import DEFAULT_FOCUS_FILE, JERUSALEM, SchedulePolicy, in_window, read_focus_file  # noqa: E402
from aifilter.store import ALLOW, MAX_OVERRIDE_DAYS, TEXT_ONLY, TRUSTED, Store, never_loosen  # noqa: E402
from aifilter.suffixes import normalize  # noqa: E402

BIND = "127.0.0.1"  # fixed: Tailscale Serve proxies locally; never a tailnet or public address
DEFAULT_PORT = 8140
MAX_BODY = 16 * 1024
SOCKET_TIMEOUT = 30  # seconds a client may stall a request
WA_FLAG = ROOT / "data" / "whatsapp-text-only"  # same file as addon.WA_FLAG and scripts/whatsapp-text-only

TIGHTEN_SWITCHES = ("block_host", "text_only_host", "block_app", "block_channel", "close_install_window",
                    "start_focus", "revoke_approval", "whatsapp_text_only_on")
LOOSEN_SWITCHES = ("open_host", "whatsapp_text_only_off")
# Never a switch, whatever the input (COMMITTEE.md rule 4; spec "what must never be a switch").
NEVER_SWITCHES = ("x_open_feed", "x_mode", "social_feeds", "filter_off", "proxy_off", "pac", "pac_lock",
                  "dns", "dns_lock", "mdm", "mdm_profile", "mdm_restrictions", "allow_app_removal",
                  "allow_erase", "allowed_devices", "owner", "passthrough", "config")
REQUEST_KINDS = ("domain", "app", "channel", "window", "appeal", "rule")


class Refused(ValueError):
    """A request the server will not carry out; the message is shown to the owner as is."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


def _never_host(value: str) -> bool:
    host = str(value).lower().strip().rstrip(".")
    if "://" in host:
        host = urlsplit(host).hostname or ""
    return never_loosen(host)


def _host(value) -> str:
    host = normalize(str(value or "").strip())
    if not committeechat.HOST_RE.fullmatch(host) or "." not in host:
        raise Refused("a valid host name is required", 400)
    return host


def _text(body: dict, key: str, *, required=True, limit=300) -> str:
    value = body.get(key, "")
    if not isinstance(value, str) or (required and not value.strip()):
        raise Refused(f"{key} is required", 400)
    return value.strip()[:limit]


class AppAPI:
    def __init__(self, store: Store, *, state_dir: Path | None = None, backend=None, clock=None, ask=None,
                 focus_file: Path | None = None, wa_flag: Path | None = None, cfg=None):
        self.store, self.backend, self.ask = store, backend, ask
        self.clock = clock  # None: Store.loosen uses its own night-rule clock
        self.state_dir = Path(state_dir or config.db_path().parent)
        self.focus_file = Path(focus_file or DEFAULT_FOCUS_FILE)
        self.wa_flag = Path(wa_flag or WA_FLAG)
        self.cfg = cfg or config.load()

    def _now(self) -> float:
        return self.clock() if self.clock else time.time()

    def _committee(self, who: str) -> Committee:
        return Committee(self.store, f"appapi:{who}", "tighten", clock=self._now, backend=self.backend,
                         app_state=self.state_dir / "app-requests.json", focus_file=self.focus_file)

    # Reads ----------------------------------------------------------------
    def status(self) -> dict:
        now = datetime.fromtimestamp(self._now(), JERUSALEM)
        schedule = self.cfg.raw.get("schedule", {})
        night, work = schedule.get("night", {}), schedule.get("work", {})
        focus = [{"topic": b.topic, "start": b.start.isoformat(), "end": b.end.isoformat()}
                 for b in self._focus(now)]
        night_on = night.get("enabled", True) and in_window(now, night.get("start", "23:00"), night.get("end", "06:00"))
        work_on = work.get("enabled", True) and in_window(now, work.get("start", "09:00"), work.get("end", "17:00"),
                                                          {6, 0, 1, 2, 3})
        mode = "focus" if focus else "night" if night_on else "work" if work_on else "normal"
        return {
            "mode": mode,
            "now": now.isoformat(),
            "schedule": {
                "night": {"enabled": bool(night.get("enabled", True)), "start": night.get("start", "23:00"),
                          "end": night.get("end", "06:00"), "active": bool(night_on)},
                "work": {"enabled": bool(work.get("enabled", True)), "start": work.get("start", "09:00"),
                         "end": work.get("end", "17:00"), "weekdays": "sun-thu", "active": bool(work_on)},
            },
            "focus_blocks": focus,
            "whatsapp_text_only": self.wa_flag.exists(),
            "devices": [{"device_id": d["device_id"], "label": d["label"], "last_contact": d["last_contact"],
                         "managed": d["managed"]} for d in self.devices()["devices"]],
            "pending_requests": len(self.store.committee_requests()) + len(self.store.appeals()),
        }

    def _focus(self, now: datetime) -> list:
        """Active focus blocks, read only: the proxy's retained copy plus the bridge file, never written here."""
        retained = SchedulePolicy(self.cfg, focus_file=self.focus_file,
                                  state_file=self.state_dir / "focus-blocks-active.json")._retained()
        blocks = {b.id: b for b in [*retained, *(read_focus_file(self.focus_file) or [])] if b.active(now)}
        return sorted(blocks.values(), key=lambda b: (b.end, b.id))

    def requests(self) -> dict:
        def reason(payload):
            try:
                data = json.loads(payload)
            except (TypeError, ValueError):
                return ""
            return str(data.get("reason", "")) if isinstance(data, dict) else ""

        committee = [{"id": r[0], "kind": r[1], "target": r[2], "reason": reason(r[3]), "status": r[4],
                      "created": r[5]} for r in self.store.committee_requests()]
        appeals = [{"id": r[0], "host": r[1], "url": r[2], "note": r[3], "created": r[4]} for r in self.store.appeals()]
        try:
            policy = policysign._load(self.state_dir / "committee-policy.json")["requests"]
        except policysign.PolicyError:
            policy = []
        rules = [{"id": r.get("id"), "loosen": r.get("loosen", []), "created": r.get("at"),
                  "confirmable_at": (r.get("at") or 0) + policysign.CONFIRM_AFTER,
                  "confirmed_at": r.get("confirmed_at"), "used": bool(r.get("used"))}
                 for r in policy if not r.get("used")]
        return {"committee": committee, "appeals": appeals, "rules": rules}

    def switches(self) -> dict:
        return {"tighten": list(TIGHTEN_SWITCHES), "loosen": list(LOOSEN_SWITCHES), "never": list(NEVER_SWITCHES),
                "state": {"whatsapp_text_only": self.wa_flag.exists()},
                "focus_topics": sorted(self.cfg.raw.get("focus", {}).get("topics", {}))}

    def chat_history(self) -> dict:
        return {"history": committeechat.load_history(self.state_dir / "committee-chat.json")}

    def devices(self) -> dict:
        """Cached state only (app tick + MDM watch files); never calls ManageEngine."""
        try:
            ids = mdm.configured_device_ids()
        except mdm.MDMUnavailable:
            ids = ()
        legacy = mdm.legacy_device(ids) if ids else mdm.IPHONE

        def read(name):
            try:
                return mdm.read_state(self.state_dir / name, legacy).get("devices", {})
            except (OSError, ValueError):
                return {}

        apps, watch = read("app-requests.json"), read("mdm-watch.json")
        out = []
        for did in ids:
            a, w = apps.get(did, {}), watch.get(did, {})
            window = a.get("window") if isinstance(a.get("window"), dict) else None
            history = a.get("history") if isinstance(a.get("history"), list) else []
            out.append({
                "device_id": did, "label": mdm.device_label(did),
                "managed": w.get("managed"), "last_contact": w.get("last_contact"),
                "checked_at": w.get("checked_at"), "alert": w.get("alerted"),
                "install_window": None if not window else {
                    "bundles": window.get("bundles", []), "until": window.get("until"),
                    "delivered": "sent_at" not in window or window.get("delivered_at") is not None},
                "recent_requests": [{k: h.get(k) for k in ("t", "app", "bundle", "status")}
                                    for h in history[-5:] if isinstance(h, dict)],
            })
        return {"devices": out}

    def audit_log(self, limit: int = 100) -> dict:
        return {"entries": [{"ts": r[0], "agent": r[1], "action": r[2], "target": r[3], "outcome": r[4],
                             "detail": r[5]} for r in self.store.audit_history(limit)]}

    # Writes ---------------------------------------------------------------
    def new_request(self, who: str, body: dict) -> dict:
        kind = body.get("kind")
        if kind not in REQUEST_KINDS:
            raise Refused(f"kind must be one of {', '.join(REQUEST_KINDS)}", 400)
        target, reason = _text(body, "target", limit=500), _text(body, "reason")
        if _never_host(target) or target in NEVER_SWITCHES:
            raise Refused("rule 4: this is never approved", 403)
        if kind == "rule":  # companion policy rules: rule 7's 24-hour clock starts now
            item = policysign.request(self.state_dir / "committee-policy.json", reason, [target], self._now())
            self.store.audit(f"appapi:{who}", "record-proposal", f"rule:{target}", "proposed", f"policy {item['id']}")
            return {"request_id": item["id"], "kind": kind, "status": "pending",
                    "confirmable_at": item["at"] + policysign.CONFIRM_AFTER}
        payload = {"reason": reason, "via": "appapi"}
        if kind in ("domain", "appeal"):
            target = _host(target)
        if kind == "domain":  # what exactly is asked for; a later open_host must match it (Store.loosen)
            verdict, days = body.get("verdict", ALLOW), body.get("days")
            if verdict not in (ALLOW, TRUSTED, TEXT_ONLY):
                raise Refused("verdict must be allow, trusted or textonly", 400)
            if isinstance(days, bool) or not isinstance(days, (int, float)) or not 0 < days <= MAX_OVERRIDE_DAYS:
                raise Refused(f"days must be 1-{MAX_OVERRIDE_DAYS}", 400)
            payload.update(verdict=verdict, days=days)
        rid = self.store.create_committee_proposal(kind, target, json.dumps(payload, ensure_ascii=False),
                                                   f"appapi:{who}")
        return {"request_id": rid, "kind": kind, "status": "pending",
                "note": "queued for the committee; nothing opens until it is approved"}

    def switch(self, who: str, body: dict) -> dict:
        name = body.get("switch")
        agent = f"appapi:{who}"
        if name in NEVER_SWITCHES:
            raise Refused("this can never be switched", 403)
        committee = self._committee(who)
        if name == "block_host":
            committee.block("domain", _host(body.get("host")), _text(body, "reason", required=False) or "app")
        elif name == "text_only_host":
            host = _host(body.get("host"))
            if not self.store.text_only_tightens(host):  # over nothing, a block, a list or a policy: loosening
                return self._loosen(agent, host, TEXT_ONLY, body)
            committee._tighten("text-only-host", host,
                               lambda: self.store.set_verdict(host, TEXT_ONLY, "admin", f"{agent}: text only"))
        elif name == "block_app":
            committee.block("app", _text(body, "bundle_id", limit=200), _text(body, "reason", required=False) or "app")
        elif name == "block_channel":
            committee.block("channel", _text(body, "channel_id", limit=100),
                            _text(body, "reason", required=False) or "app")
        elif name == "close_install_window":
            if self.backend is None:
                raise Refused("MDM unavailable", 503)
            committee.close_window(str(body.get("device") or "all"))
        elif name == "start_focus":
            return {"switch": name, **committee.start_focus(body.get("topic"), body.get("minutes"))}
        elif name == "revoke_approval":
            committee.revoke_approval(body.get("kind"), _text(body, "target", limit=500))
        elif name == "whatsapp_text_only_on":
            committee._tighten("whatsapp-text-only", "on", lambda: self.wa_flag.touch())
        elif name == "open_host":
            verdict = body.get("verdict", ALLOW)
            if verdict not in (ALLOW, TRUSTED, TEXT_ONLY):
                raise Refused("verdict must be allow, trusted or textonly", 400)
            return self._loosen(agent, _host(body.get("host")), verdict, body)
        elif name == "whatsapp_text_only_off":
            raise Refused("rule 7: loosening this switch needs a committee request (POST /api/v1/requests)")
        else:
            raise Refused("unknown switch", 400)
        return {"switch": name, "applied": True}

    def _loosen(self, agent: str, host: str, verdict: str, body: dict) -> dict:
        if _never_host(host):
            raise Refused("rule 4: this is never approved", 403)
        reason = _text(body, "reason")
        days = body.get("days")
        if isinstance(days, bool) or not isinstance(days, (int, float)):
            raise Refused("days is required", 400)
        now = self.clock() if self.clock else None
        try:
            self.store.loosen(host, verdict, "admin", f"{agent}: {reason}", days=days, now=now,
                              request_id=body.get("request_id"), require_request=True)
        except ValueError as exc:  # Store.loosen's refusal, verbatim
            raise Refused(str(exc)) from None
        return {"switch": body.get("switch"), "applied": True, "host": host, "verdict": verdict}

    def chat(self, who: str, body: dict) -> dict:
        message = _text(body, "message", limit=1000)
        return committeechat.converse(message, state_dir=self.state_dir, store=self.store, ask=self.ask,
                                      app_backend=self.backend)


def _audit_target(body) -> str:
    if not isinstance(body, dict):
        return "-"
    for key in ("switch", "kind", "host", "target"):
        if isinstance(body.get(key), str):
            return f"{key}={body[key][:120]}"
    return "-"


def make_handler(api: AppAPI, owners):
    owners = {str(o).strip().lower() for o in owners if str(o).strip()}
    routes_get = {"/api/v1/status": api.status, "/api/v1/requests": api.requests,
                  "/api/v1/switches": api.switches, "/api/v1/chat": api.chat_history,
                  "/api/v1/devices": api.devices}
    routes_post = {"/api/v1/requests": ("request", api.new_request), "/api/v1/switches": ("switch", api.switch),
                   "/api/v1/chat": ("chat", api.chat)}

    class Handler(BaseHTTPRequestHandler):
        server_version = "aifilter-appapi"
        sys_version = ""
        timeout = SOCKET_TIMEOUT

        def log_message(self, *a):
            pass

        def _send(self, code: int, obj: dict):
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("content-type", "application/json; charset=utf-8")
            self.send_header("cache-control", "no-store")
            self.send_header("x-content-type-options", "nosniff")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _identity(self) -> tuple[str | None, int, str]:
            """(owner login, 0, '') or (None, status, reason)."""
            if self.client_address[0] != BIND:
                return None, 403, "only through the local Tailscale Serve proxy"
            if self.headers.get("tailscale-funnel-request") is not None:
                return None, 403, "not over Funnel"
            if self.headers.get("origin") is not None:
                return None, 403, "browser requests are not accepted"
            login = (self.headers.get("tailscale-user-login") or "").strip().lower()
            if not login:
                return None, 401, "no Tailscale identity"
            if login not in owners:
                return None, 403, "not an owner"
            return login, 0, ""

        def do_GET(self):
            who, code, why = self._identity()
            if not who:
                return self._send(code, {"error": why})
            url = urlsplit(self.path)
            if url.path == "/api/v1/audit":
                try:
                    limit = max(1, min(int(parse_qs(url.query).get("limit", ["100"])[0]), 500))
                except ValueError:
                    return self._send(400, {"error": "limit must be a number"})
                return self._send(200, api.audit_log(limit))
            handler = routes_get.get(url.path)
            if not handler:
                return self._send(404, {"error": "not found"})
            try:
                return self._send(200, handler())
            except Exception:  # noqa: BLE001 - never leak internals
                return self._send(500, {"error": "internal error"})

        def do_POST(self):
            path = urlsplit(self.path).path
            who, code, why = self._identity()
            route = routes_post.get(path)
            action = route[0] if route else path[:60]
            body = None
            if who and route:
                try:
                    size = int(self.headers.get("content-length") or 0)
                    if not self.headers.get("content-type", "").lower().startswith("application/json"):
                        code, why = 415, "content-type must be application/json"
                    elif not 0 < size <= MAX_BODY:
                        code, why = 413, "body must be 1-16384 bytes"
                    else:
                        body = json.loads(self.rfile.read(size).decode("utf-8"))
                        if not isinstance(body, dict):
                            code, why = 400, "body must be a JSON object"
                except (ValueError, UnicodeDecodeError, RecursionError):
                    code, why = 400, "invalid JSON"
                    body = None
            elif who:
                code, why = 404, "not found"
            agent = f"appapi:{who}" if who else f"unverified:{(self.headers.get('tailscale-user-login') or '-')[:80]}"
            target = _audit_target(body)
            if code:
                outcome = "rejected" if code in (401, 403) else "invalid"
                api.store.audit(agent, action, target, outcome, f"{code} {why}")
                return self._send(code, {"error": why})
            try:
                result = route[1](who, body)
            except Refused as exc:
                api.store.audit(agent, action, target, "refused", str(exc))
                return self._send(exc.status, {"error": str(exc), "refused": True})
            except TimeoutError:
                api.store.audit(agent, action, target, "failed", "busy")
                return self._send(503, {"error": "busy, try again"})
            except (ValueError, PermissionError, policysign.PolicyError) as exc:
                api.store.audit(agent, action, target, "refused", str(exc))
                return self._send(409, {"error": str(exc), "refused": True})
            except Exception as exc:  # noqa: BLE001 - never leak internals
                api.store.audit(agent, action, target, "failed", type(exc).__name__)
                return self._send(500, {"error": "internal error"})
            api.store.audit(agent, action, target, "ok", json.dumps(result, ensure_ascii=False)[:300])
            return self._send(200, result)

        def do_PUT(self):
            self._send(405, {"error": "method not allowed"})

        do_DELETE = do_PATCH = do_PUT

    return Handler


def _points_here(proxy: str, port: int) -> bool:
    url = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
    try:
        return url.hostname in ("127.0.0.1", "localhost", "::1", "0.0.0.0") and url.port == port
    except ValueError:
        return False


def serve_problem(status, port: int) -> str | None:
    """Why the Tailscale Serve configuration is not the pinned one (https :port "/" -> 127.0.0.1:port), or None."""
    if not isinstance(status, dict):
        return "unreadable serve status"
    pinned = 0
    for hostport, site in (status.get("Web") or {}).items():
        handlers = (site or {}).get("Handlers") or {}
        ours = str(hostport).rsplit(":", 1)[-1] == str(port)
        for path, handler in handlers.items():
            proxy = str((handler or {}).get("Proxy") or "")
            here = bool(proxy) and _points_here(proxy, port)
            if ours and (path != "/" or not here or proxy.rstrip("/") != f"http://127.0.0.1:{port}"):
                return f"Serve {hostport}{path} is not exactly {port} -> 127.0.0.1:{port}"
            if here and not ours:
                return f"Serve {hostport}{path} also proxies to the API"
            pinned += ours and here
    for tcp_port, entry in (status.get("TCP") or {}).items():
        forward = str((entry or {}).get("TCPForward") or "")
        if forward and _points_here(forward, port):
            return f"Serve TCP {tcp_port} forwards to the API"
        if str(tcp_port) == str(port) and forward:
            return f"Serve TCP {tcp_port} is a raw forward, not https"
    if any(on and str(hp).rsplit(":", 1)[-1] == str(port) for hp, on in (status.get("AllowFunnel") or {}).items()):
        return f"Funnel is on for port {port}"
    if pinned != 1:
        return f"Serve does not publish https :{port} -> 127.0.0.1:{port}"
    return None


TAILSCALE_CANDIDATES = ("/usr/local/bin/tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale")
SERVE_CHECK_SECONDS = 300


def tailscale_binary(configured: str = "") -> str:
    """Absolute path of the tailscale CLI; never looked up on PATH (launchd gives none)."""
    import os
    for path in ((configured,) if configured else ()) + TAILSCALE_CANDIDATES:
        if os.path.isabs(path) and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise FileNotFoundError("tailscale CLI not found ([appapi] tailscale, /usr/local/bin, Tailscale.app)")


def serve_status(binary: str | None = None) -> dict:
    out = subprocess.run([binary or tailscale_binary(), "serve", "status", "--json"], capture_output=True,
                         text=True, timeout=15, check=True)
    return json.loads(out.stdout or "{}")


def watch_serve(server, store: Store, port: int, status_fn, *, interval: float = SERVE_CHECK_SECONDS,
                stop=None) -> str | None:
    """Re-check the Serve route every `interval` seconds; on a bad or unreadable route, audit it and stop the
    server. Returns the reason it stopped (None when `stop` was set first)."""
    import threading
    stop = stop or threading.Event()
    while not stop.wait(interval):
        try:
            problem = serve_problem(status_fn(), port)
        except (OSError, subprocess.SubprocessError, ValueError):
            problem = "could not read tailscale serve status"
        if problem:
            store.audit("appapi:server", "serve-check", str(port), "stopped", problem)
            print(f"stopping: {problem}", flush=True)
            server.shutdown()
            return problem
    return None


def main():
    cfg = config.load()
    owners = cfg.get("appapi", "owners", []) or []
    if not owners:  # exit 0: launchd (KeepAlive SuccessfulExit=false) does not restart it in a loop
        print("[appapi] owners is empty: nobody could use the API, not starting", flush=True)
        return
    port = int(cfg.get("appapi", "port", DEFAULT_PORT))
    try:
        binary = tailscale_binary(str(cfg.get("appapi", "tailscale", "") or ""))
        status = serve_status(binary)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise SystemExit("could not read `tailscale serve status`; retrying later") from None  # nonzero: launchd retries
    problem = serve_problem(status, port)
    if problem:  # exit 0: stays down until the Serve setup is fixed and the service is reloaded
        print(f"refusing to start: {problem}. Expected exactly: "
              f"tailscale serve --bg --https={port} http://127.0.0.1:{port}", flush=True)
        return
    import threading
    backend = mdm.backend(cfg.get("mdm", "backend", "none"))
    store = Store(config.db_path())
    api = AppAPI(store, backend=backend, cfg=cfg)
    server = ThreadingHTTPServer((BIND, port), make_handler(api, owners))
    stopped = []
    threading.Thread(target=lambda: stopped.append(watch_serve(server, store, port, lambda: serve_status(binary))),
                     daemon=True).start()
    print(f"app api on http://{BIND}:{port}/api/v1 for {len(owners)} owner(s)", flush=True)
    server.serve_forever()
    server.server_close()  # exit 0 after a bad route: launchd leaves it down until Serve is fixed and reloaded


if __name__ == "__main__":
    main()
