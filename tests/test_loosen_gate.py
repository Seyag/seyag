from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from aifilter import committeechat
from aifilter.store import ALLOW, BLOCK, Store
from scripts.check_config_loosening import loosenings


DAY = datetime(2026, 11, 18, 12, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()
NIGHT = datetime(2026, 11, 18, 23, 30, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()


def test_night_and_list_approval_refused(tmp_path):
    store = Store(tmp_path / "db")
    with pytest.raises(ValueError, match="night"):
        store.loosen("x.com", ALLOW, "admin", "test", days=3, now=NIGHT)
    store.replace_blocklists([("bad.example", "oisd_nsfw")])
    with pytest.raises(ValueError, match="rule 4"):
        store.loosen("bad.example", ALLOW, "admin", "test", days=3, now=DAY)


def test_denial_memory_refuses_reapproval(tmp_path):
    store = Store(tmp_path / "db")
    store.loosen("school.example", ALLOW, "admin", "first", days=1, now=DAY)
    store.set_verdict("school.example", BLOCK, "admin", "denied")
    with pytest.raises(ValueError, match="7 days"):
        store.loosen("school.example", ALLOW, "admin", "again", days=1, now=DAY + 60)


def test_text_only_cannot_replace_admin_block(tmp_path):
    store = Store(tmp_path / "db")
    store.set_verdict("blocked.example", BLOCK, "admin", "parent")
    answer = lambda *_args, **_kw: {"reply": "ok", "action": "text_only_host",
                                    "target": "blocked.example", "loosen": []}
    committeechat.answer("text only", [], ask=answer, store=store)
    assert store.verdict("blocked.example") == BLOCK


def test_specific_ai_block_beats_temporary_parent_allow(tmp_path):
    store = Store(tmp_path / "db")
    store.set_verdict("www.walla.co.il", BLOCK, "ai", "unsafe")
    store.set_override("walla.co.il", ALLOW, "admin", "legacy approval", 3)
    assert store.verdict("www.walla.co.il") == BLOCK


def test_passthrough_requires_confirmed_request(tmp_path):
    store = Store(tmp_path / "db")
    with pytest.raises(ValueError, match="confirmed request"):
        store.loosen("bank.example", "trusted", "admin", "pinned", passthrough=True, now=DAY)


def test_ci_detects_known_config_loosenings():
    old = {"youtube": {"ai_check": False}, "x": {"enabled": False},
           "schedule": {"night_allow": ["essential.example"]}, "passthrough": {"hosts": []}}
    new = {"youtube": {"ai_check": True}, "x": {"enabled": True},
           "schedule": {"night_allow": ["essential.example", "video.example"]},
           "passthrough": {"hosts": ["opaque.example"]}}
    assert loosenings(old, new) == ["youtube.ai_check", "x.enabled",
                                    "schedule.night_allow+=video.example",
                                    "passthrough.hosts+=opaque.example"]


def test_ci_detects_calibrated_youtube_mode_as_a_loosening():
    strict = {"youtube": {"modesty_mode": "strict"}}
    calibrated = {"youtube": {"modesty_mode": "calibrated"}}
    assert loosenings(strict, calibrated) == ["youtube.modesty_mode=calibrated"]
    assert loosenings({}, calibrated) == ["youtube.modesty_mode=calibrated"]
    assert loosenings(calibrated, strict) == []


def test_ci_detects_work_device_exemption_loosening():
    old = {"schedule": {"work": {}}}
    exempt = {"schedule": {"work": {"exempt_devices": ["203.0.113.10"]}}}
    assert loosenings(old, exempt) == ["schedule.work.exempt_devices+=203.0.113.10"]
    assert loosenings(exempt, old) == []  # removing an exemption tightens


def _clock(monkeypatch, now=DAY):
    import time
    monkeypatch.setattr(time, "time", lambda: now)


def test_p1_1_admin_cannot_weaken_policy_row_or_loosen_under_it(tmp_path):
    store = Store(tmp_path / "db")
    store.set_verdict("instagram.com", BLOCK, "policy", "feed")
    with pytest.raises(ValueError, match="rule 4"):
        store.set_verdict("instagram.com", "textonly", "admin", "manual")
    with pytest.raises(ValueError, match="rule 4"):
        store.set_verdict("www.instagram.com", "textonly", "admin", "manual")
    store.set_verdict("m.instagram.com", BLOCK, "admin", "child row")  # a stricter or equal admin row is fine
    store._q("DELETE FROM domain_denials")
    with pytest.raises(ValueError, match="rule 4"):  # a policy row on the parent still gates the child
        store.loosen("m.instagram.com", ALLOW, "admin", "x", days=3, now=DAY)
    assert store.verdict("m.instagram.com") == BLOCK and store.verdict("instagram.com") == BLOCK


def test_p1_1_textonly_over_block_must_be_temporary_and_daytime(tmp_path):
    store = Store(tmp_path / "db")
    store.set_verdict("shop.example", BLOCK, "admin", "denied")
    store._q("DELETE FROM domain_denials")
    with pytest.raises(ValueError, match="temporary"):
        store.loosen("shop.example", "textonly", "admin", "manual", now=DAY)
    with pytest.raises(ValueError, match="night"):
        store.loosen("shop.example", "textonly", "admin", "manual", days=2, now=NIGHT)


def test_p1_2_parent_denial_blocks_child_approval(tmp_path, monkeypatch):
    store = Store(tmp_path / "db")
    _clock(monkeypatch)  # the denial is stamped with time.time(); pin it to DAY so the 7-day window is fixed
    store.set_verdict("example.com", BLOCK, "admin", "deny")
    with pytest.raises(ValueError, match="7 days"):
        store.loosen("www.example.com", ALLOW, "admin", "x", days=3, now=DAY + 60)
    store.loosen("www.example.com", ALLOW, "admin", "x", days=3, now=DAY + 8 * 86400)


def test_p1_3_policy_block_clears_same_name_approval(tmp_path, monkeypatch):
    _clock(monkeypatch)
    store = Store(tmp_path / "db")
    store.loosen("forum.example", ALLOW, "admin", "x", days=3, now=DAY)
    assert store.verdict("forum.example") == ALLOW
    store.set_verdict("forum.example", BLOCK, "policy", "committee chat")
    assert store.verdict("forum.example") == BLOCK
    store.loosen("blog.example", ALLOW, "admin", "x", days=3, now=DAY)
    store.set_verdict("blog.example", "textonly", "policy", "committee chat")
    assert store.verdict("blog.example") == "textonly"


def test_p1_4_appeal_approves_exact_host_only(tmp_path, monkeypatch):
    _clock(monkeypatch)
    store = Store(tmp_path / "db")
    store.add_appeal("www.wiki.example", "https://www.wiki.example/p")
    (row,) = store.appeals()
    assert row[1] == "www.wiki.example"
    store.resolve_appeal(row[0], True, days=1)
    assert store.verdict("www.wiki.example") == ALLOW
    assert store.verdict("wiki.example") is None and store.verdict("x.www.wiki.example") is None


def test_p1_4_inherited_approval_never_beats_specific_list_entry(tmp_path, monkeypatch):
    from aifilter.hotstore import ProxyStore
    _clock(monkeypatch)
    store = Store(tmp_path / "db")
    store.replace_blocklists([("porn.example.org", "oisd")])
    store.loosen("example.org", ALLOW, "admin", "appeal", days=3, now=DAY, domain=True)
    assert store.verdict("example.org") == ALLOW and store.verdict("www.example.org") == ALLOW
    assert store.verdict("porn.example.org") == BLOCK and store.verdict("a.porn.example.org") == BLOCK
    hot = ProxyStore(tmp_path / "db", recent_hosts=tmp_path / "hosts.log", poll=.01)
    try:
        assert hot.verdict("www.example.org") == ALLOW
        assert hot.verdict("porn.example.org") == BLOCK and hot.verdict("a.porn.example.org") == BLOCK
    finally:
        hot.close()
