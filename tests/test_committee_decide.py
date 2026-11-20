import json

from aifilter.store import Store
from scripts import committee_decide


def test_store_decision_merges_payload_and_preserves_hebrew(tmp_path):
    store = Store(tmp_path / "filter.db")
    request_id = store.create_committee_request("app", "com.example.App", '{"reason":"why"}')
    assert store.decide_committee_request(request_id, "waiting", "ממתינים", "2026-12-01T10:00:00Z")
    row = store.committee_request(request_id)
    payload = json.loads(row[3])
    assert row[4] == "waiting"
    assert payload["reason"] == "why"
    assert payload["decision_note"] == "ממתינים"
    assert payload["earliest_at"] == "2026-12-01T10:00:00Z"
    assert payload["decided_at"].endswith("Z")


def test_decide_script_updates_configured_store(monkeypatch, tmp_path):
    path = tmp_path / "filter.db"
    request_id = Store(path).create_committee_request("domain", "example.test")
    monkeypatch.setattr(committee_decide.config, "db_path", lambda: path)
    assert committee_decide.main([str(request_id), "declined", "--note", "לא"]) == 0
    row = Store(path).committee_request(request_id)
    assert row[4] == "declined"
    assert json.loads(row[3])["decision_note"] == "לא"
