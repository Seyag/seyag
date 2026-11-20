"""The owner's native-app API: Tailscale Serve identity, the single loosening gate, never-switches and audit."""
import io
import json
from datetime import datetime
from ipaddress import ip_network
from zoneinfo import ZoneInfo

import pytest

from aifilter import appapi, committeechat, config, mdm, selfguard
from aifilter import store as store_mod
from aifilter.store import ALLOW, BLOCK, NEVER_LOOSEN, TEXT_ONLY, Store

OWNER = "owner@example.com"
DAY = datetime(2026, 11, 18, 12, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()
NIGHT = datetime(2026, 11, 18, 23, 30, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()


class FakeConn:
    """A socket stand-in, so the real handler runs without a network or a fixed port."""

    def __init__(self, data: bytes):
        self.rfile, self.out = io.BytesIO(data), io.BytesIO()

    def makefile(self, mode, *args, **kwargs):
        return self.rfile if "r" in mode else self.out

    def sendall(self, data):
        self.out.write(data)

    def settimeout(self, value):
        self.timeout = value


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "filter.db")


@pytest.fixture
def make_api(store, tmp_path):
    def build(clock=None, backend=None, ask=None):
        return appapi.AppAPI(store, state_dir=tmp_path, backend=backend, clock=clock, ask=ask,
                             focus_file=tmp_path / "focus.json", wa_flag=tmp_path / "wa-text-only",
                             cfg=config.load())
    return build


def call(api, method, path, body=None, *, login=OWNER, client="127.0.0.1", headers=None,
         ctype="application/json"):
    data = b"" if body is None else json.dumps(body).encode()
    lines = [f"{method} {path} HTTP/1.1", "Host: filter.example.ts.net"]
    if login is not None:
        lines.append(f"Tailscale-User-Login: {login}")
    if body is not None:
        lines += [f"Content-Type: {ctype}", f"Content-Length: {len(data)}"]
    lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
    conn = FakeConn(("\r\n".join(lines) + "\r\n\r\n").encode() + data)
    appapi.make_handler(api, [OWNER])(conn, (client, 40000), None)
    raw = conn.out.getvalue()
    head, _, payload = raw.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    return status, json.loads(payload or b"{}"), head.decode().lower()


def approved_request(store, host, *, verdict=ALLOW, days=2, created=DAY - 2 * 86400, confirmed=DAY - 3600,
                     status="approved"):
    """A committee request for exactly this loosening, decided and confirmed by the owner."""
    rid = store.create_committee_request("domain", host, json.dumps({"reason": "need", "verdict": verdict,
                                                                     "days": days}), created=created)
    if status:
        store.decide_committee_request(rid, status, "committee")
    if confirmed is not None:
        store._q("INSERT INTO owner_confirmations(request_id,confirmed,channel) VALUES(?,?,?)", (rid, confirmed, "t"))
    return rid


def audit(store):
    return [dict(zip(("ts", "agent", "action", "target", "outcome", "detail"), r)) for r in store.audit_history(50)]


# Auth ---------------------------------------------------------------------
def test_missing_header_is_rejected_and_audited(make_api, store):
    api = make_api()
    assert call(api, "GET", "/api/v1/status", login=None)[0] == 401
    status, body, _ = call(api, "POST", "/api/v1/switches", {"switch": "block_host", "host": "a.example"}, login=None)
    assert status == 401 and body["error"] == "no Tailscale identity"
    assert store.verdict("a.example") is None
    assert audit(store)[0]["outcome"] == "rejected" and audit(store)[0]["agent"] == "unverified:-"


def test_wrong_user_is_rejected(make_api, store):
    api = make_api()
    assert call(api, "GET", "/api/v1/status", login="intruder@example.com")[0] == 403
    status, _, _ = call(api, "POST", "/api/v1/switches", {"switch": "block_host", "host": "a.example"},
                        login="intruder@example.com")
    assert status == 403 and store.verdict("a.example") is None
    entry = audit(store)[0]
    assert entry["agent"] == "unverified:intruder@example.com" and entry["outcome"] == "rejected"


def test_non_local_client_is_rejected_even_with_owner_header(make_api, store):
    lan = str(ip_network("192.168.0.0/16")[42])
    tailnet = str(ip_network("100.64.0.0/10")[42])
    api = make_api()
    for client in (lan, tailnet, "::1"):
        assert call(api, "GET", "/api/v1/status", client=client)[0] == 403
    status, _, _ = call(api, "POST", "/api/v1/switches", {"switch": "block_host", "host": "a.example"},
                        client=lan)
    assert status == 403 and store.verdict("a.example") is None


def test_browser_origin_and_non_json_are_rejected(make_api, store):
    api = make_api()
    assert call(api, "GET", "/api/v1/status", headers={"Origin": "https://evil.example"})[0] == 403
    assert call(api, "GET", "/api/v1/status", headers={"Tailscale-Funnel-Request": "?1"})[0] == 403
    status, _, _ = call(api, "POST", "/api/v1/switches", {"switch": "block_host", "host": "a.example"},
                        ctype="text/plain")
    assert status == 415 and store.verdict("a.example") is None


def test_empty_owner_list_admits_nobody(make_api):
    api = make_api()
    conn = FakeConn(f"GET /api/v1/status HTTP/1.1\r\nTailscale-User-Login: {OWNER}\r\n\r\n".encode())
    appapi.make_handler(api, [])(conn, ("127.0.0.1", 1), None)
    assert conn.out.getvalue().split(b"\r\n")[0].split(b" ")[1] == b"403"


def test_server_never_binds_beyond_loopback():
    assert appapi.BIND == "127.0.0.1"
    assert "ThreadingHTTPServer((BIND, port)" in open(appapi.__file__).read()  # no configurable bind address


# Loosening goes only through Store.loosen ----------------------------------
def test_night_loosening_refused_verbatim_through_loosen(make_api, store):
    rid = approved_request(store, "school.example")
    status, body, _ = call(make_api(clock=lambda: NIGHT), "POST", "/api/v1/switches",
                           {"switch": "open_host", "host": "school.example", "days": 2, "reason": "homework",
                            "request_id": rid})
    assert status == 409 and body == {"error": "rule 6: no loosening at night (23:00-06:00 Israel)", "refused": True}
    assert store.verdict("school.example") is None
    assert audit(store)[0]["outcome"] == "refused" and "rule 6" in audit(store)[0]["detail"]


def test_loosening_needs_confirmed_request_for_that_domain(make_api, store):
    api = make_api(clock=lambda: DAY)
    req = {"switch": "open_host", "host": "school.example", "days": 2, "reason": "homework"}
    status, body, _ = call(api, "POST", "/api/v1/switches", req)
    assert status == 409 and body["error"] == "needs a confirmed committee request for this domain"
    other = approved_request(store, "other.example")
    assert call(api, "POST", "/api/v1/switches", {**req, "request_id": other})[0] == 409
    assert store.verdict("school.example") is None
    good = approved_request(store, "school.example")
    status, body, _ = call(api, "POST", "/api/v1/switches", {**req, "request_id": good})
    assert status == 200 and body["applied"] and store.verdict("school.example") == ALLOW


@pytest.mark.parametrize("kwargs, error", [
    ({"status": "declined"}, "the committee has not approved this request"),
    ({"status": None}, "the committee has not approved this request"),
    ({"confirmed": None}, "rule 7: confirmation counts only 24 hours after the request"),
    ({"confirmed": DAY - 2 * 86400 + 3600}, "rule 7: confirmation counts only 24 hours after the request"),
    ({"confirmed": NIGHT - 86400}, "rule 6: the confirmation was given at night"),
    ({"days": 7}, "the request does not match this verdict, duration and scope"),
    ({"verdict": "trusted"}, "the request does not match this verdict, duration and scope"),
])
def test_request_must_be_approved_calmly_confirmed_and_matching(make_api, store, kwargs, error):
    rid = approved_request(store, "school.example", **kwargs)
    status, body, _ = call(make_api(clock=lambda: DAY), "POST", "/api/v1/switches",
                           {"switch": "open_host", "host": "school.example", "days": 2, "reason": "x",
                            "request_id": rid})
    assert status == 409 and body["error"] == error
    assert store.verdict("school.example") is None and store.committee_request(rid)[4] != "used"


def test_request_is_single_use(make_api, store):
    api = make_api(clock=lambda: DAY)
    rid = approved_request(store, "school.example")
    req = {"switch": "open_host", "host": "school.example", "days": 2, "reason": "x", "request_id": rid}
    assert call(api, "POST", "/api/v1/switches", req)[0] == 200
    assert store.committee_request(rid)[4] == "used"
    store._q("DELETE FROM overrides")
    status, body, _ = call(api, "POST", "/api/v1/switches", req)
    assert status == 409 and body["error"] == "the committee has not approved this request"
    assert store.verdict("school.example") is None


# Text-only is a loosening unless a standing open rule is all it replaces (review P1-a, P1-b)
def test_text_only_on_unjudged_host_is_a_loosening(make_api, store):
    status, body, _ = call(make_api(clock=lambda: DAY), "POST", "/api/v1/switches",
                           {"switch": "text_only_host", "host": "unjudged-forum.example", "days": 1, "reason": "x"})
    assert status == 409 and body["error"] == "needs a confirmed committee request for this domain"
    assert store.verdict("unjudged-forum.example") is None and store.standing("unjudged-forum.example") is None


def test_text_only_over_temporary_approval_keeps_standing_block(make_api, store):
    store.set_verdict("site.example", BLOCK, "ai", "ai block")
    store.set_override("site.example", ALLOW, "admin", "committee 3d", 3)
    status, _, _ = call(make_api(clock=lambda: DAY), "POST", "/api/v1/switches",
                        {"switch": "text_only_host", "host": "site.example", "days": 1, "reason": "x"})
    assert status == 409
    assert store.standing("site.example") == (BLOCK, "ai") and [r[0] for r in store.overrides()] == ["site.example"]


def test_chat_text_only_over_temporary_approval_or_unjudged_is_refused(store):
    store.set_verdict("site.example", BLOCK, "ai", "ai block")
    store.set_override("site.example", ALLOW, "admin", "committee 3d", 3)
    for host in ("site.example", "unjudged.example"):
        ask = lambda m, system=None, h=host: {"reply": "ok", "action": "text_only_host", "target": h, "loosen": []}
        out = committeechat.answer("text only", [], ask=ask, store=store)
        assert out["result"]["refused"]
    assert store.standing("site.example") == (BLOCK, "ai") and store.standing("unjudged.example") is None
    assert [r[0] for r in store.overrides()] == ["site.example"]


def test_text_only_over_standing_open_rule_is_a_tightening(make_api, store):
    store.set_verdict("news.example", ALLOW, "ai", "judged fine")
    assert call(make_api(), "POST", "/api/v1/switches", {"switch": "text_only_host", "host": "news.example"})[0] == 200
    assert store.verdict("news.example") == TEXT_ONLY


def test_block_keeps_policy_row(make_api, store):
    store.set_verdict("feed.example", TEXT_ONLY, "policy", "social feed")
    assert call(make_api(), "POST", "/api/v1/switches",
                {"switch": "block_host", "host": "feed.example", "reason": "x"})[0] == 200
    assert store.standing("feed.example") == (BLOCK, "admin") and store.network_blocked("feed.example")
    assert store._policy_row("feed.example") == (TEXT_ONLY, "policy")  # the lock stays
    with pytest.raises(ValueError, match="rule 4"):
        store.set_verdict("feed.example", ALLOW, "admin", "weaker than the policy")
    store.set_verdict("feed2.example", BLOCK, "policy", "feed")
    call(make_api(), "POST", "/api/v1/switches", {"switch": "text_only_host", "host": "feed2.example",
                                                   "days": 1, "reason": "x"})
    assert store._policy_row("feed2.example") == (BLOCK, "policy")


def test_seven_day_denial_and_text_only_over_block_refused(make_api, store):
    store.set_verdict("shop.example", BLOCK, "admin", "denied")
    api = make_api(clock=lambda: DAY)
    status, body, _ = call(api, "POST", "/api/v1/switches", {"switch": "text_only_host", "host": "shop.example",
                                                              "days": 1, "reason": "receipt"})
    assert status == 409 and body["error"] == "rule 5: this domain or a parent was denied within the last 7 days"
    assert store.verdict("shop.example") == BLOCK


def test_whatsapp_off_is_not_a_live_switch(make_api, tmp_path):
    (tmp_path / "wa-text-only").touch()
    status, body, _ = call(make_api(), "POST", "/api/v1/switches", {"switch": "whatsapp_text_only_off"})
    assert status == 409 and "rule 7" in body["error"] and (tmp_path / "wa-text-only").exists()


# Never-switches -------------------------------------------------------------
@pytest.mark.parametrize("payload", [
    {"switch": "dns_lock"}, {"switch": "pac"}, {"switch": "mdm_restrictions"}, {"switch": "x_open_feed"},
    {"switch": "open_host", "host": "x.com", "days": 1, "reason": "news", "request_id": 1},
    {"switch": "open_host", "host": "www.instagram.com", "days": 1, "reason": "x", "request_id": 1},
])
def test_never_switches_refused_server_side(make_api, store, payload):
    rid = approved_request(store, payload.get("host", "x.com"), days=1)
    status, body, _ = call(make_api(clock=lambda: DAY), "POST", "/api/v1/switches",
                           {**payload, **({"request_id": rid} if "host" in payload else {})})
    assert status == 403 and body["refused"]
    assert store.verdict("x.com") is None and store.verdict("www.instagram.com") is None
    assert audit(store)[0]["outcome"] == "refused"


def test_never_items_cannot_even_be_requested(make_api, store):
    for target in ("x.com", "https://www.tiktok.com/@a", "dns_lock"):
        status, _, _ = call(make_api(), "POST", "/api/v1/requests",
                            {"kind": "domain", "target": target, "reason": "please"})
        assert status in (400, 403)
    assert store.committee_requests() == []


# Tightening applies at once -------------------------------------------------
def test_tighten_switches_apply_immediately(make_api, store, tmp_path):
    api = make_api()
    status, body, _ = call(api, "POST", "/api/v1/switches", {"switch": "block_host", "host": "News.Example",
                                                              "reason": "too much"})
    assert status == 200 and body == {"switch": "block_host", "applied": True}
    assert store.verdict("news.example") == BLOCK
    store.set_verdict("blog.example", ALLOW, "ai", "judged fine")  # text-only tightens only a standing open rule
    assert call(api, "POST", "/api/v1/switches", {"switch": "text_only_host", "host": "blog.example"})[0] == 200
    assert store.verdict("blog.example") == TEXT_ONLY
    assert call(api, "POST", "/api/v1/switches", {"switch": "whatsapp_text_only_on"})[0] == 200
    assert (tmp_path / "wa-text-only").exists()
    assert call(api, "POST", "/api/v1/switches", {"switch": "block_app", "bundle_id": "com.example.game"})[0] == 200
    assert store.entity_verdict("app", "com.example.game")[0] == "block"
    assert call(api, "POST", "/api/v1/switches", {"switch": "close_install_window"})[0] == 503


def test_focus_switch_writes_a_block_and_status_shows_it(make_api, tmp_path):
    api = make_api()
    status, body, _ = call(api, "POST", "/api/v1/switches", {"switch": "start_focus", "topic": "Example Project", "minutes": 30})
    assert status == 200 and body["applied"] and body["topic"] == "Example Project"
    status, data, _ = call(api, "GET", "/api/v1/status")
    assert status == 200 and data["mode"] == "focus" and data["focus_blocks"][0]["topic"] == "Example Project"
    assert call(api, "POST", "/api/v1/switches", {"switch": "start_focus", "topic": "Example Project", "minutes": 999})[0] == 409


# Audit ------------------------------------------------------------------------
def test_every_mutating_call_is_audited(make_api, store):
    api = make_api(clock=lambda: DAY)
    call(api, "POST", "/api/v1/switches", {"switch": "block_host", "host": "a.example"})
    call(api, "POST", "/api/v1/switches", {"switch": "dns_lock"})
    call(api, "POST", "/api/v1/switches", {"switch": "open_host", "host": "b.example", "days": 1, "reason": "x"})
    call(api, "POST", "/api/v1/requests", {"kind": "domain", "target": "c.example", "reason": "school", "days": 1})
    mine = [e for e in audit(store) if e["agent"] == f"appapi:{OWNER}"]
    api_lines = [(e["action"], e["target"], e["outcome"]) for e in mine if e["action"] in ("switch", "request")]
    assert api_lines[::-1] == [("switch", "switch=block_host", "ok"), ("switch", "switch=dns_lock", "refused"),
                               ("switch", "switch=open_host", "refused"), ("request", "kind=domain", "ok")]
    status, data, _ = call(api, "GET", "/api/v1/audit?limit=3")
    assert status == 200 and len(data["entries"]) == 3


# Requests, chat, devices ----------------------------------------------------
def test_new_request_is_queued_never_applied(make_api, store):
    api = make_api()
    status, body, _ = call(api, "POST", "/api/v1/requests", {"kind": "domain", "target": "Docs.Example",
                                                              "reason": "school project", "days": 3})
    assert status == 200 and body["status"] == "pending"
    assert store.verdict("docs.example") is None
    assert call(api, "POST", "/api/v1/requests", {"kind": "domain", "target": "docs.example"})[0] == 400
    status, data, _ = call(api, "GET", "/api/v1/requests")
    assert data["committee"][0]["target"] == "docs.example" and data["committee"][0]["reason"] == "school project"
    status, body, _ = call(api, "POST", "/api/v1/requests", {"kind": "rule", "target": "stories", "reason": "calm"})
    assert status == 200 and body["confirmable_at"] - DAY > 0
    assert call(api, "GET", "/api/v1/requests")[1]["rules"][0]["loosen"] == ["stories"]


def test_chat_wraps_committee_chat_and_keeps_history(make_api, store):
    ask = lambda messages, system=None: {"reply": "נחסם.", "action": "block_host", "target": "bad.example",
                                          "loosen": []}
    api = make_api(ask=ask, backend=mdm.NoMDM())
    status, body, _ = call(api, "POST", "/api/v1/chat", {"message": "תחסום את bad.example"})
    assert status == 200 and body["reply"] == "נחסם." and store.verdict("bad.example") == BLOCK
    history = call(api, "GET", "/api/v1/chat")[1]["history"]
    assert history[-1] == {"role": "assistant", "content": "נחסם."}


def test_devices_read_cached_state_only(make_api, tmp_path):
    (tmp_path / "mdm-watch.json").write_text(json.dumps({"devices": {
        mdm.IPHONE: {"checked_at": DAY, "last_contact": DAY - 60, "managed": True}}}))
    status, data, head = call(make_api(), "GET", "/api/v1/devices")
    assert status == 200 and "cache-control: no-store" in head
    iphone = next(d for d in data["devices"] if d["device_id"] == mdm.IPHONE)
    assert iphone["managed"] is True and iphone["last_contact"] == DAY - 60 and iphone["install_window"] is None


def test_unknown_routes_and_methods(make_api):
    api = make_api()
    assert call(api, "GET", "/api/v1/nope")[0] == 404
    assert call(api, "PUT", "/api/v1/switches", {"switch": "x"})[0] == 405
    assert call(api, "POST", "/api/v1/switches", {"switch": "made_up"})[0] == 400


# Hardening (review P2-c, P3) -------------------------------------------------
def test_never_loosen_list_is_enforced_in_store_for_every_caller(store):
    import policy
    assert set(policy.TEXT_ONLY_SITES) | set(policy.BLOCKED_FEEDS) <= set(NEVER_LOOSEN)
    for host in ("www.youtube.com", "threads.net", "nordvpn.com", "m.tiktok.com"):
        with pytest.raises(ValueError, match="rule 4: this is never approved"):
            store.loosen(host, ALLOW, "admin", "x", days=1, now=DAY)


def test_domain_request_records_what_is_asked(make_api, store):
    status, body, _ = call(make_api(), "POST", "/api/v1/requests",
                           {"kind": "domain", "target": "docs.example", "reason": "x", "verdict": "trusted", "days": 2})
    assert status == 200 and json.loads(store.committee_request(body["request_id"])[3])["verdict"] == "trusted"
    assert call(make_api(), "POST", "/api/v1/requests",
                {"kind": "domain", "target": "docs.example", "reason": "x", "days": 31})[0] == 400


def test_proxy_refuses_the_api_port_on_this_mac(store):
    from test_filter import make_filter
    port = int(config.load().get("appapi", "port"))
    filt = make_filter(store)
    assert port in filt.protected_ports
    why = selfguard.refusal(["203.0.113.10"], port, filt.protected_ports, is_local=lambda ip: True)
    assert why and "this Mac" in why
    assert selfguard.refusal(["203.0.113.10"], 443, filt.protected_ports, is_local=lambda ip: True) is None


def test_deeply_nested_json_is_a_bad_request(make_api, store):
    api = make_api()
    data = b"[" * 10000
    raw = (f"POST /api/v1/switches HTTP/1.1\r\nTailscale-User-Login: {OWNER}\r\nContent-Type: application/json\r\n"
           f"Content-Length: {len(data)}\r\n\r\n").encode() + data
    conn = FakeConn(raw)
    appapi.make_handler(api, [OWNER])(conn, ("127.0.0.1", 1), None)
    assert conn.out.getvalue().split(b"\r\n")[0].split(b" ")[1] == b"400"
    assert conn.timeout == appapi.SOCKET_TIMEOUT
    assert audit(store)[0]["outcome"] == "invalid"


def test_chat_lock_has_a_timeout(make_api, monkeypatch, tmp_path):
    import fcntl
    monkeypatch.setattr(committeechat, "LOCK_TIMEOUT", 0.2)
    with open(tmp_path / "committee-chat.json.lock", "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        api = make_api(ask=lambda m, system=None: {"reply": "x", "action": "none", "target": "", "loosen": []},
                       backend=mdm.NoMDM())
        status, body, _ = call(api, "POST", "/api/v1/chat", {"message": "hi"})
    assert status == 503 and body["error"] == "busy, try again"


def test_status_does_not_write_focus_state(make_api, tmp_path):
    call(make_api(), "POST", "/api/v1/switches", {"switch": "start_focus", "topic": "Example Project", "minutes": 30})
    assert call(make_api(), "GET", "/api/v1/status")[1]["mode"] == "focus"
    assert not (tmp_path / "focus-blocks-active.json").exists()


def test_main_with_no_owners_exits_cleanly_without_binding(monkeypatch):
    monkeypatch.setattr(appapi, "ThreadingHTTPServer", lambda *a, **k: pytest.fail("must not bind"))
    assert config.load().get("appapi", "owners") == []
    assert appapi.main() is None



# Review round 2 ---------------------------------------------------------------
def test_committee_block_on_policy_host_survives_policy_reapply(make_api, store):
    import policy
    policy.apply(store)
    assert store.standing("x.com") == (TEXT_ONLY, "policy")
    assert call(make_api(), "POST", "/api/v1/switches", {"switch": "block_host", "host": "x.com", "reason": "x"})[0] == 200
    for _ in range(2):
        assert store.verdict("x.com") == BLOCK and store.network_blocked("x.com")
        assert store._policy_row("x.com") == (TEXT_ONLY, "policy")
        policy.apply(store)
    store.set_verdict("reddit.com", BLOCK, "policy", "committee chat")  # a stricter policy row
    policy.apply(store)
    assert store.standing("reddit.com") == (BLOCK, "policy")


def test_equal_committee_deny_on_policy_host_records_denial_and_clears_approval(store):
    store.set_verdict("feed.example", BLOCK, "policy", "feed")
    store.set_override("feed.example", ALLOW, "admin", "legacy approval", 3)
    store._q("DELETE FROM domain_denials")
    store.set_verdict("feed.example", BLOCK, "admin", "committee: deny")
    assert store._q("SELECT count(*) FROM domain_denials WHERE host='feed.example'")[0][0] == 1
    assert store.overrides() == [] and store.network_blocked("feed.example")


def test_text_only_under_a_standing_parent_allow_is_a_tightening(make_api, store):
    store.set_verdict("example.org", ALLOW, "admin", "ok")
    status, _, _ = call(make_api(), "POST", "/api/v1/switches", {"switch": "text_only_host", "host": "sub.example.org"})
    assert status == 200 and store.verdict("sub.example.org") == TEXT_ONLY


def test_used_request_cannot_be_decided_again_and_races_once(store):
    import threading
    rid = approved_request(store, "open.example", days=3)
    results = []

    def go():
        try:
            store.loosen("open.example", ALLOW, "admin", "r", days=3, now=DAY, request_id=rid, require_request=True)
            results.append("ok")
        except ValueError as exc:
            results.append(str(exc))
    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count("ok") == 1
    with pytest.raises(ValueError, match="already used"):
        store.decide_committee_request(rid, "approved", "again")
    assert store.committee_request(rid)[4] == "used"


def test_admin_page_text_only_on_unjudged_host_is_an_opening(store):
    import admin
    form = b"host=unjudged.example&verdict=textonly"
    raw = (b"POST /domain HTTP/1.1\r\nHost: mac:8090\r\nOrigin: http://mac:8090\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(form)).encode()
           + b"\r\n\r\n" + form)
    conn = FakeConn(raw)
    admin.make_handler(store, {"mac"}, resolve=lambda ip: "mac")(conn, ("203.0.113.10", 1), None)
    assert conn.out.getvalue().split(b"\r\n")[0].split(b" ")[1] == b"400"  # an opening needs days and the gate
    assert store.standing("unjudged.example") is None


GOOD_SERVE = {"TCP": {"443": {"HTTPS": True}, "8140": {"HTTPS": True}},
              "Web": {"filter.example.ts.net:443": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:4194"}}},
                      "filter.example.ts.net:8140": {"Handlers": {"/": {"Proxy": "http://127.0.0.1:8140"}}}},
              "AllowFunnel": {"filter.example.ts.net:10000": True}}


@pytest.mark.parametrize("change, problem", [
    (lambda s: None, None),
    (lambda s: s["Web"].pop("filter.example.ts.net:8140"), "does not publish"),
    (lambda s: s["AllowFunnel"].update({"filter.example.ts.net:8140": True}), "Funnel"),
    (lambda s: s["Web"]["filter.example.ts.net:8140"]["Handlers"].update({"/x": {"Proxy": "http://127.0.0.1:9"}}), "not exactly"),
    (lambda s: s["Web"]["filter.example.ts.net:443"]["Handlers"].update({"/api": {"Proxy": "http://localhost:8140"}}),
     "also proxies"),
    (lambda s: s["TCP"].update({"9000": {"TCPForward": "127.0.0.1:8140"}}), "forwards to the API"),
    (lambda s: s["Web"]["filter.example.ts.net:8140"]["Handlers"]["/"].update({"Proxy": "http://127.0.0.1:8141"}), "not exactly"),
])
def test_serve_configuration_is_pinned(change, problem):
    import copy
    status = copy.deepcopy(GOOD_SERVE)
    change(status)
    found = appapi.serve_problem(status, 8140)
    assert (found is None) if problem is None else (problem in found)


def test_main_refuses_to_start_on_a_wrong_serve_setup(monkeypatch):
    cfg = config.Config({**config.load().raw, "appapi": {"port": 8140, "owners": [OWNER]}})
    monkeypatch.setattr(appapi.config, "load", lambda *a: cfg)
    monkeypatch.setattr(appapi, "tailscale_binary", lambda configured="": "/fake/tailscale")
    monkeypatch.setattr(appapi, "serve_status", lambda *a: {**GOOD_SERVE, "AllowFunnel": {"filter.example.ts.net:8140": True}})
    monkeypatch.setattr(appapi, "ThreadingHTTPServer", lambda *a, **k: pytest.fail("must not bind"))
    assert appapi.main() is None


# Review round 3 ---------------------------------------------------------------
def test_tailscale_resolver_needs_no_path(monkeypatch, tmp_path):
    fake = tmp_path / "tailscale"
    fake.write_text("#!/bin/sh\necho '{}'\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(appapi, "TAILSCALE_CANDIDATES", ("/nonexistent/tailscale", str(fake)))
    assert appapi.tailscale_binary() == str(fake)
    assert appapi.tailscale_binary(str(fake)) == str(fake)
    assert appapi.serve_status(appapi.tailscale_binary()) == {}
    monkeypatch.setattr(appapi, "TAILSCALE_CANDIDATES", ("tailscale",))  # a bare name is never looked up
    with pytest.raises(FileNotFoundError):
        appapi.tailscale_binary()


def test_launchd_plist_sets_path():
    import plistlib
    with open(appapi.ROOT / "deploy/com.example.ai-filter-appapi.plist", "rb") as fh:
        plist = plistlib.load(fh)
    assert "/usr/local/bin" in plist["EnvironmentVariables"]["PATH"].split(":")
    assert plist["KeepAlive"] == {"SuccessfulExit": False}


def test_server_stops_when_the_serve_route_changes(store):
    statuses = iter([GOOD_SERVE, GOOD_SERVE, {**GOOD_SERVE, "AllowFunnel": {"filter.example.ts.net:8140": True}}])

    class FakeServer:
        stopped = False

        def shutdown(self):
            self.stopped = True

    server = FakeServer()
    reason = appapi.watch_serve(server, store, 8140, lambda: next(statuses), interval=0.001)
    assert server.stopped and "Funnel" in reason
    entry = audit(store)[0]
    assert (entry["agent"], entry["action"], entry["outcome"]) == ("appapi:server", "serve-check", "stopped")


def test_chat_block_keeps_a_house_wide_committee_block(store):
    store.set_verdict("forum.example", BLOCK, "admin", "committee: deny")
    ask = lambda m, system=None: {"reply": "ok", "action": "block_host", "target": "forum.example", "loosen": []}
    committeechat.answer("block it", [], ask=ask, store=store)
    assert store.standing("forum.example") == (BLOCK, "admin") and store.network_blocked("forum.example")


def test_policy_prune_dry_run_then_apply(store, capsys):
    import policy
    policy.apply(store)
    store.set_verdict("old-feed.example", BLOCK, "policy", policy.BLOCK_REASON)  # left the lists since
    store.set_verdict("oldtext.example", TEXT_ONLY, "policy", policy.TEXT_ONLY_REASON)
    store.set_verdict("oldtext.example", BLOCK, "admin", "committee")  # its policy now lives on as a lock
    store.set_verdict("chat.example", BLOCK, "policy", "committee chat")  # never pruned
    stale = sorted(policy.prune(store))
    assert stale == [("lock", "oldtext.example"), ("row", "old-feed.example")]
    assert store.standing("old-feed.example") == (BLOCK, "policy")  # dry run changes nothing
    assert sorted(policy.prune(store, remove=True)) == stale
    assert store.standing("old-feed.example") is None and store._policy_row("oldtext.example") is None
    assert store.standing("oldtext.example") == (BLOCK, "admin")
    assert store.standing("chat.example") == (BLOCK, "policy") and store.standing("x.com") == (TEXT_ONLY, "policy")
    assert policy.prune(store) == []


# Final review ------------------------------------------------------------------
def test_chat_block_during_temporary_approval_closes_it(store):
    store.set_verdict("site.example", BLOCK, "admin", "deny")
    store.set_override("site.example", ALLOW, "admin", "re-approved", 3)
    ask = lambda m, system=None: {"reply": "ok", "action": "block_host", "target": "site.example", "loosen": []}
    out = committeechat.answer("block it", [], ask=ask, store=store)
    assert out["result"]["verdict"] == BLOCK and store.verdict("site.example") == BLOCK and store.overrides() == []
    assert store.standing("site.example") == (BLOCK, "admin")


def test_prune_never_touches_admin_rows_or_shared_locks(store):
    import policy
    policy.apply(store)
    store.set_verdict("x.com", BLOCK, "admin", "committee")  # the committee takes x.com; the policy stays a lock
    store.set_verdict("old.example", BLOCK, "policy", policy.BLOCK_REASON)  # delisted policy row
    store.set_verdict("adm.example", BLOCK, "admin", policy.BLOCK_REASON)  # admin row carrying our reason text
    store.set_verdict("chat.example", BLOCK, "policy", "committee chat")
    assert policy.prune(store) == [("row", "old.example")]
    policy.prune(store, remove=True)
    assert store.standing("x.com") == (BLOCK, "admin") and store._policy_row("x.com") == (TEXT_ONLY, "policy")
    assert store.standing("adm.example") == (BLOCK, "admin") and store.standing("chat.example") == (BLOCK, "policy")
    assert store.standing("old.example") is None


def test_chat_lock_reason_survives_a_policy_lock_write(store):
    import policy
    store.set_verdict("gone.example", BLOCK, "admin", "committee")
    store.set_verdict("gone.example", BLOCK, "policy", "committee chat")  # chat lock beside the committee row
    store._lock_policy("gone.example", BLOCK, policy.BLOCK_REASON)  # later a policy.py lock on the same host
    assert "committee chat" in store._q("SELECT reason FROM policy_locks WHERE host='gone.example'")[0][0]
    assert policy.prune(store, remove=True) == []
    assert store._policy_row("gone.example") == (BLOCK, "policy")


def test_old_policy_locks_table_gains_reason_column(tmp_path):
    import sqlite3
    db = sqlite3.connect(str(tmp_path / "old.db"))
    db.execute("CREATE TABLE policy_locks (host TEXT PRIMARY KEY, verdict TEXT NOT NULL, updated REAL NOT NULL)")
    db.execute("INSERT INTO policy_locks VALUES('legacy.example','block',1)")
    db.commit()
    db.close()
    store = Store(tmp_path / "old.db")
    assert store.policy_records() == [("lock", "legacy.example", "block", "legacy")]
    store._lock_policy("new.example", TEXT_ONLY, "r")
    assert store._policy_row("legacy.example") == (BLOCK, "policy")


# Codex final review --------------------------------------------------------------
def _old_layout_db(path, rows=()):
    import sqlite3
    db = sqlite3.connect(str(path))
    db.execute("CREATE TABLE policy_locks (host TEXT PRIMARY KEY, verdict TEXT NOT NULL, updated REAL NOT NULL)")
    db.executemany("INSERT INTO policy_locks VALUES(?,?,1)", rows)
    db.commit()
    db.close()


def test_legacy_lock_survives_policy_relock_and_prune(tmp_path, monkeypatch):
    import policy
    _old_layout_db(tmp_path / "old.db", [("x.com", BLOCK)])
    store = Store(tmp_path / "old.db")
    store.set_verdict("x.com", BLOCK, "admin", "committee")
    policy.apply(store)  # relocks x.com with policy.py's own reason
    monkeypatch.setattr(policy, "TEXT_ONLY_SITES", [h for h in policy.TEXT_ONLY_SITES if h != "x.com"])
    monkeypatch.setattr(store_mod, "NEVER_LOOSEN", tuple(h for h in store_mod.NEVER_LOOSEN if h != "x.com"))
    assert ("lock", "x.com") not in policy.prune(store, remove=True)
    assert store._policy_row("x.com") == (BLOCK, "policy")
    with pytest.raises(ValueError, match="rule 4"):
        store.set_verdict("x.com", ALLOW, "admin", "open it")


def test_lock_without_a_reason_is_never_pruned(store):
    import policy
    store._lock_policy("gone.example", BLOCK)  # no owner given
    store._lock_policy("gone.example", BLOCK, policy.BLOCK_REASON)
    assert policy.prune(store, remove=True) == [] and store._policy_row("gone.example") == (BLOCK, "policy")


def test_old_database_migrates_once_under_parallel_opens(tmp_path):
    import sqlite3
    import subprocess
    import sys
    path = tmp_path / "old.db"
    _old_layout_db(path, [("legacy.example", BLOCK)])
    with sqlite3.connect(path) as db:
        db.execute("""CREATE TABLE overrides (
            host TEXT PRIMARY KEY, verdict TEXT NOT NULL, source TEXT NOT NULL, reason TEXT,
            created REAL NOT NULL, expires REAL NOT NULL
        )""")
        db.execute("INSERT INTO overrides VALUES ('temporary.example', 'allow', 'admin', '', 1, 2)")
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from aifilter.store import Store; "
            "Store(sys.argv[2]); print('ok')")
    procs = [subprocess.Popen([sys.executable, "-c", code, str(appapi.ROOT), str(path)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(8)]
    results = [p.communicate(timeout=60) for p in procs]
    assert all(p.returncode == 0 for p in procs), [err for _, err in results if err]
    store = Store(path)
    assert store.policy_records() == [("lock", "legacy.example", "block", "legacy")]
    assert store._q("SELECT host, include_subdomains FROM overrides") == [("temporary.example", 0)]



def test_lock_owner_that_is_a_substring_of_the_policy_reason_is_kept(store):
    import policy
    store.set_verdict("feed.example", BLOCK, "admin", "committee")
    store.set_verdict("feed.example", BLOCK, "policy", policy.BLOCK_REASON)  # policy.py's lock beside the row
    store.set_verdict("feed.example", BLOCK, "policy", policy.BLOCK_REASON[:3])  # a second writer, a substring
    assert store._q("SELECT reason FROM policy_locks WHERE host='feed.example'")[0][0] != policy.BLOCK_REASON
    assert policy.prune(store, remove=True) == []
    with pytest.raises(ValueError, match="rule 4"):
        store.set_verdict("feed.example", ALLOW, "admin", "open it")


def test_lock_owner_cannot_contain_the_separator(store):
    import policy
    store._lock_policy("gone.example", BLOCK, f"x | {policy.BLOCK_REASON}")  # would look like two owners
    reason = store._q("SELECT reason FROM policy_locks WHERE host='gone.example'")[0][0]
    assert " | " not in reason and reason != policy.BLOCK_REASON
    assert policy.prune(store, remove=True) == [] and store._policy_row("gone.example") == (BLOCK, "policy")
