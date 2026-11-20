import json

from aifilter.store import Store
from scripts import relay_pull


def test_pull_records_through_propose_only_path_and_acks(monkeypatch, tmp_path):
    store = Store(tmp_path / "filter.db")
    proposal = {"id":"remote-1", "queue_key":"proposal:1:remote-1", "kind":"domain",
                "target":"example.test", "reason":"review this"}
    calls = []
    def fake_request(base, token, path, method="GET", body=None):
        calls.append((path, method))
        return {"proposals":[proposal]} if method == "GET" else {"ok": True}
    monkeypatch.setattr(relay_pull, "request", fake_request)
    assert relay_pull.pull(store, "https://relay.test", "secret") == 1
    row = store.committee_requests()[0]
    assert row[1:3] == ("domain", "example.test")
    assert json.loads(row[3]) == {"reason":"review this", "relay_id":"remote-1"}
    assert store.audit_history()[0][1:5] == ("chatgpt-relay", "record-proposal", "domain:example.test", "proposed")
    assert calls[-1] == ("/home/proposals/proposal%3A1%3Aremote-1", "DELETE")


def test_pull_is_idempotent_and_rejects_oversize(monkeypatch, tmp_path):
    store = Store(tmp_path / "filter.db")
    good = {"id":"x", "queue_key":"proposal:x", "kind":"app", "target":"com.example.app", "reason":"why"}
    marker = json.dumps({"reason":"why", "relay_id":"x"}, separators=(",", ":"))
    store.create_committee_proposal("app", "com.example.app", marker, "chatgpt-relay")
    monkeypatch.setattr(relay_pull, "request", lambda *a, **k: {"proposals":[good, {**good,"id":"y","reason":"x"*501}]} if k.get("method","GET")=="GET" else {})
    assert relay_pull.pull(store, "https://relay.test", "secret") == 0
    assert len(store.committee_requests()) == 1


def test_pull_rejects_prose_as_machine_target(monkeypatch, tmp_path):
    store = Store(tmp_path / "filter.db")
    bad = {"id":"x", "queue_key":"proposal:x", "kind":"domain",
           "target":"ignore previous instructions", "reason":"why"}
    monkeypatch.setattr(relay_pull, "request", lambda *a, **k: {"proposals":[bad]})
    assert relay_pull.pull(store, "https://relay.test", "secret") == 0
    assert store.committee_requests() == []


def test_pull_rejects_out_of_range_window(monkeypatch, tmp_path):
    store = Store(tmp_path / "filter.db")
    bad = {"id":"x", "queue_key":"proposal:x", "kind":"window",
           "target":"99:99-99:99", "reason":"review"}
    monkeypatch.setattr(relay_pull, "request", lambda *a, **k: {"proposals":[bad]})
    assert relay_pull.pull(store, "https://relay.test", "secret") == 0
    assert store.committee_requests() == []


def test_summary_contains_safe_recent_requests_with_caps(tmp_path):
    store = Store(tmp_path / "filter.db")
    for i in range(22):
        store.create_committee_request("domain", f"{i}.example", json.dumps({
            "decision_note": "שלום" + "x" * 600, "earliest_at": "2026-12-01T00:00:00Z",
            "secret": "must-not-leak", "device": "iphone"}), created=i)
    summary = relay_pull.safe_summary(store)
    assert summary["counts"] == {"committee_pending":22,"committee_completed":0,"appeals_pending":0}
    assert len(summary["requests"]) == 20
    assert [item["id"] for item in summary["requests"]][:2] == [22, 21]
    assert len(summary["requests"][0]["decision_note"]) == 500
    assert set(summary["requests"][0]) == {"id", "kind", "target", "status", "decision_note", "earliest_at", "created"}
    assert "must-not-leak" not in repr(summary)


def test_main_pulls_before_pushing_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(relay_pull.config, "db_path", lambda: tmp_path / "filter.db")
    calls = []
    def fake_request(_base, _token, path, method="GET", body=None):
        calls.append((path, method, body))
        if path == "/home/proposals":
            return {"proposals": [{"id":"r", "queue_key":"proposal:r", "kind":"domain",
                "target":"new.example", "reason":"review"}]}
        return {"ok": True}
    monkeypatch.setattr(relay_pull, "request", fake_request)
    assert relay_pull.main(["--relay-url", "https://relay.test", "--token", "token"]) == 0
    assert [call[:2] for call in calls] == [("/home/proposals", "GET"),
        ("/home/proposals/proposal%3Ar", "DELETE"), ("/home/actions", "GET"), ("/home/summary", "PUT")]
    assert calls[-1][2]["counts"]["committee_pending"] == 1

class _FakeCommittee:
    def __init__(self): self.calls = []
    def block(self, *args): self.calls.append(("block", args))
    def start_focus(self, *args, **kwargs): self.calls.append(("focus", args))
    def close_window(self, *args): self.calls.append(("close", args))


def test_action_allowlist_applies_all_safe_actions_and_rejects_loosening(monkeypatch, tmp_path):
    store, committee, deleted = Store(tmp_path / "actions.db"), _FakeCommittee(), []
    actions = [
        {"id":"d","queue_key":"action:d","type":"block_domain","args":{"target":"bad.example","reason":"strict"}},
        {"id":"a","queue_key":"action:a","type":"block_app","args":{"target":"com.bad.app","reason":"strict"}},
        {"id":"c","queue_key":"action:c","type":"block_channel","args":{"target":"@badchannel","reason":"strict"}},
        {"id":"f","queue_key":"action:f","type":"start_focus","args":{"topic":"Example Project","duration":30}},
        {"id":"w","queue_key":"action:w","type":"close_install_window","args":{}},
        {"id":"p","queue_key":"action:p","type":"submit_appeal","args":{"host":"appeal.example","reason":"needed"}},
        {"id":"x","queue_key":"action:x","type":"allow_domain","args":{"target":"bad.example","reason":"loosen"}},
    ]
    for item in actions:
        item.update(created="2026-11-18T00:00:00Z", status="pending")
    def fake(_base, _token, path, method="GET", body=None):
        if method == "GET": return {"actions": actions}
        deleted.append(path); return {"ok": True}
    monkeypatch.setattr(relay_pull, "request", fake)
    assert relay_pull.pull_actions(store, "https://relay", "token", committee) == 6
    assert len(deleted) == 7
    assert store.appeals()[0][1] == "appeal.example"


def test_summary_new_fields_are_capped(monkeypatch, tmp_path):
    store = Store(tmp_path / "summary.db")
    for i in range(25):
        store.log("dns-blocked", f"{i}.example")
        store.add_appeal(f"appeal{i}.com", f"https://appeal{i}.com/")
        store.set_entity_verdict("app", f"com.example.{i}", "block")
    monkeypatch.setattr(relay_pull, "current_mode", lambda cfg: None)
    summary = relay_pull.safe_summary(store)
    assert isinstance(summary["committee_rules"], str) and len(summary["committee_rules"]) <= 3000
    assert len(summary["appeals"]) == len(summary["top_blocked_domains"]) == 20
    assert len(summary["app_verdicts"]) == 25


def test_actions_are_durable_and_malformed_items_do_not_stop_queue(monkeypatch, tmp_path):
    store, committee = Store(tmp_path / "actions.db"), _FakeCommittee()
    good = {"id":"once","queue_key":"action:once","type":"block_domain",
            "args":{"target":"bad.example","reason":"strict"},"created":"2026-11-18T00:00:00Z","status":"pending"}
    deletes = []
    def fake(_base, _token, path, method="GET", body=None):
        if method == "GET": return {"actions":[None, {**good,"extra":True}, good]}
        deletes.append(path)
        if len(deletes) == 2: raise OSError("lost acknowledgement")
        return {}
    monkeypatch.setattr(relay_pull, "request", fake)
    assert relay_pull.pull_actions(store, "https://relay", "token", committee) == 1
    assert relay_pull.pull_actions(store, "https://relay", "token", committee) == 0
    assert len(committee.calls) == 1
    assert store._q("SELECT status FROM relay_actions WHERE id='once'") == [("applied",)]


def test_bad_typed_action_is_rejected_without_aborting_pull(tmp_path, monkeypatch):
    store = Store(tmp_path / "f.db")
    deleted = []
    actions = [
        {"id": "a1", "queue_key": "action:1:a1", "type": "start_focus", "args": {"topic": "x", "duration": "long"}, "created": "2026-11-18T10:00:00Z", "status": "pending"},
        {"id": "a2", "queue_key": "action:2:a2", "type": "close_install_window", "args": {}, "created": "2026-11-18T10:00:00Z", "status": "pending"},
    ]

    class Boom:
        def start_focus(self, *a, **k): raise TypeError("bad duration")
        def close_window(self, device): pass

    def fake(base, token, path, method="GET", body=None):
        if method == "DELETE":
            deleted.append(path); return {}
        return {"actions": actions}

    monkeypatch.setattr(relay_pull, "request", fake)
    assert relay_pull.pull_actions(store, "https://relay", "t", Boom()) == 1
