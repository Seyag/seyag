import io
import json
from pathlib import Path
import pytest

from aifilter import committeechat, policysign
from aifilter.store import ALLOW, BLOCK, TEXT_ONLY, TRUSTED


class FakeStore:
    def __init__(self):
        self.calls = []

    def set_verdict(self, host: str, verdict: str, source: str, reason: str = "", days=None):
        self.calls.append((host, verdict, source, reason))


def test_block_host_calls_set_verdict_with_block():
    store = FakeStore()

    def fake_ask(messages, system=None):
        return {
            "reply": "האתר נחסם לפי בקשתך.",
            "action": "block_host",
            "target": "example.com",
            "loosen": [],
        }

    res = committeechat.answer("חסום את example.com", [], ask=fake_ask, store=store)
    assert res["action"] == "block_host"
    assert res["target"] == "example.com"
    assert res["reply"] == "האתר נחסם לפי בקשתך."
    assert store.calls == [("example.com", BLOCK, "policy", "committee chat")]


@pytest.mark.parametrize("invalid_host", [
    "invalid_host_no_dot",
    "bad..host-with-special!char.com",
    "http://example.com",
    "ab",
    "",
    "a" * 254 + ".com",
])
def test_invalid_host_is_ignored(invalid_host):
    store = FakeStore()

    def fake_ask(messages, system=None):
        return {
            "reply": "חסימה לא בוצעה.",
            "action": "block_host",
            "target": invalid_host,
            "loosen": [],
        }

    res = committeechat.answer("חסום משהו", [], ask=fake_ask, store=store)
    assert res["action"] == "none"
    assert res["target"] == ""
    assert res["reply"] == "חסימה לא בוצעה."
    assert store.calls == []


def test_request_loosening_files_request_and_appends_24h_line(tmp_path):
    policy_file = tmp_path / "policy.json"
    now_ts = 1_800_000_000.0

    def fake_ask(messages, system=None):
        return {
            "reply": "הבקשה להקלה נרשמה.",
            "action": "request_loosening",
            "target": "",
            "loosen": ["stories", "search"],
        }

    res = committeechat.answer(
        "אני רוצה לפתוח סטוריז",
        [],
        ask=fake_ask,
        policy_state=policy_file,
        now=now_ts,
    )
    assert res["action"] == "request_loosening"
    assert res["result"] is not None
    rid = res["result"]["id"]
    assert rid
    expected_line = f"\nבקשה {rid}: אפשר לאשר רק אחרי 24 שעות, ברוגע ולא בלילה."
    assert res["reply"].endswith(expected_line)

    state = json.loads(policy_file.read_text(encoding="utf-8"))
    assert len(state["requests"]) == 1
    req = state["requests"][0]
    assert req["id"] == rid
    assert req["loosen"] == ["search", "stories"]
    assert req["at"] == now_ts


def test_unknown_rule_name_is_ignored(tmp_path):
    policy_file = tmp_path / "policy.json"

    def fake_ask(messages, system=None):
        return {
            "reply": "בקשה עם חוק לא מוכר.",
            "action": "request_loosening",
            "target": "",
            "loosen": ["nonExistentRuleName"],
        }

    res = committeechat.answer(
        "פתח חוק לא קיים",
        [],
        ask=fake_ask,
        policy_state=policy_file,
    )
    assert res["action"] == "none"
    assert res["target"] == ""
    assert res["reply"] == "בקשה עם חוק לא מוכר."
    assert not policy_file.exists() or len(json.loads(policy_file.read_text()).get("requests", [])) == 0


def test_empty_loosening_is_ignored(tmp_path):
    policy_file = tmp_path / "policy.json"

    def fake_ask(messages, system=None):
        return {
            "reply": "בקשה ריקה.",
            "action": "request_loosening",
            "target": "",
            "loosen": [],
        }

    res = committeechat.answer("פתח", [], ask=fake_ask, policy_state=policy_file)
    assert res["action"] == "none"
    assert res["target"] == ""
    assert not policy_file.exists() or len(json.loads(policy_file.read_text()).get("requests", [])) == 0


def test_ask_exception_gives_fallback_reply():
    def failing_ask(messages, system=None):
        raise RuntimeError("network down or model timeout")

    res = committeechat.answer("שלום", [], ask=failing_ask)
    assert res["reply"] == "הוועדה לא זמינה כרגע, נסה שוב עוד מעט."
    assert res["action"] == "none"
    assert res["target"] == ""
    assert res["result"] is None


def test_app_request_calls_fake_request(monkeypatch, tmp_path):
    called = []

    def fake_request(target, app_state, app_backend, note=""):
        called.append((target, app_state, app_backend, note))
        return {"status": "approved", "reason": "approved for study"}

    monkeypatch.setattr(committeechat.app_request, "request", fake_request)

    def fake_ask(messages, system=None):
        return {
            "reply": "בודק בקשת אפליקציה.",
            "action": "app_request",
            "target": "https://apps.apple.com/app/id123456",
            "loosen": [],
        }

    app_state = tmp_path / "app-requests.json"
    fake_backend = object()
    res = committeechat.answer(
        "אני צריך מילון",
        [],
        ask=fake_ask,
        app_state=app_state,
        app_backend=fake_backend,
    )
    assert res["action"] == "app_request"
    assert res["target"] == "https://apps.apple.com/app/id123456"
    assert len(called) == 1
    assert called[0] == ("https://apps.apple.com/app/id123456", app_state, fake_backend, "committee chat")
    assert "approved: approved for study" in res["reply"]


def test_no_action_can_call_anything_that_loosens():
    class StrictStore:
        def __init__(self):
            self.verdicts = []

        def set_verdict(self, host: str, verdict: str, source: str, reason: str = "", days=None):
            if verdict not in (BLOCK, TEXT_ONLY):
                raise AssertionError(f"Illegal loosening verdict recorded: {verdict!r}")
            self.verdicts.append(verdict)

        def text_only_tightens(self, host: str) -> bool:
            return True  # site2.com stands open, so text-only is a tightening here

    store = StrictStore()

    # block_host
    res1 = committeechat.answer(
        "חסום את site1.com",
        [],
        ask=lambda m, **k: {"reply": "חוסם", "action": "block_host", "target": "site1.com", "loosen": []},
        store=store,
    )
    assert res1["action"] == "block_host"

    # text_only_host
    res2 = committeechat.answer(
        "שים טקסט בלבד על site2.com",
        [],
        ask=lambda m, **k: {"reply": "טקסט בלבד", "action": "text_only_host", "target": "site2.com", "loosen": []},
        store=store,
    )
    assert res2["action"] == "text_only_host"

    # Actions attempting to loosen directly on the store
    for malicious in ("allow", "trusted", "allow_host", "open_domain", "unblock", "whitelist"):
        res = committeechat.answer(
            f"פתח את site3.com",
            [],
            ask=lambda m, **k: {"reply": "מנסה לפתוח", "action": malicious, "target": "site3.com", "loosen": []},
            store=store,
        )
        assert res["action"] == "none"

    assert set(store.verdicts) <= {BLOCK, TEXT_ONLY}
    assert ALLOW not in store.verdicts
    assert TRUSTED not in store.verdicts
    assert len(store.verdicts) == 2


def test_docstring_usage_on_line_1():
    doc = committeechat.__doc__
    assert doc is not None
    first_line = doc.splitlines()[0].strip()
    assert 'python -m aifilter.committeechat < {"message": "..."}' in first_line


def test_schema_structure():
    schema = committeechat.SCHEMA
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"reply", "action", "target", "loosen"}
    assert schema["properties"]["action"]["enum"] == [
        "none", "block_host", "text_only_host", "request_loosening", "app_request"
    ]
    assert set(schema["properties"]["loosen"]["items"]["enum"]) == set(policysign.RULES)


def test_history_passed_to_ask():
    seen = []

    def fake_ask(messages, system=None):
        seen.extend(messages)
        return {"reply": "תשובה", "action": "none", "target": "", "loosen": []}

    history = [{"role": "user", "content": f"msg {i}"} for i in range(15)]
    committeechat.answer("הודעה חדשה", history, ask=fake_ask)

    # Only last 10 turns plus the new message
    assert len(seen) == 11
    assert seen[-1] == {"role": "user", "content": "הודעה חדשה"}
    assert seen[0] == {"role": "user", "content": "msg 5"}


def test_main_cli(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "filter.db"))
    history_file = tmp_path / "committee-chat.json"
    fake_input = json.dumps({"message": "שלום"})
    monkeypatch.setattr("sys.stdin", io.StringIO(fake_input))

    def fake_ask(messages, system=None):
        return {
            "reply": "שלום, במה אוכל לעזור?",
            "action": "none",
            "target": "",
            "loosen": [],
        }

    monkeypatch.setattr(committeechat, "default_ask", fake_ask)
    code = committeechat.main([])
    assert code == 0

    printed = capsys.readouterr().out.strip()
    out = json.loads(printed)
    assert out["reply"] == "שלום, במה אוכל לעזור?"
    assert out["action"] == "none"

    assert history_file.exists()
    saved_hist = json.loads(history_file.read_text(encoding="utf-8"))
    assert len(saved_hist) == 2
    assert saved_hist[0] == {"role": "user", "content": "שלום"}
    assert saved_hist[1] == {"role": "assistant", "content": "שלום, במה אוכל לעזור?"}
