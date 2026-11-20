import json
import fcntl
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from threading import Event
from zoneinfo import ZoneInfo

import pytest

from aifilter import mdm, mcp_server
from aifilter.store import Store
from scripts import app_request as ar

NOON = datetime(2026, 11, 15, 12, 0, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()
NIGHT = datetime(2026, 11, 15, 23, 30, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()


def app(**kw):
    base = {"trackId": 123456789, "bundleId": "com.example.dict", "trackName": "Hebrew Dictionary",
            "primaryGenreName": "Reference", "genres": ["Reference"], "contentAdvisoryRating": "4+",
            "description": "Look up words offline."}
    return {**base, **kw}


@pytest.fixture(autouse=True)
def _no_ledger(monkeypatch, tmp_path):
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "filter.db"))
    monkeypatch.setattr(ar, "LEDGER", tmp_path / "no-review-log")  # never the real one
    monkeypatch.setattr(ar.mdmwatch, "send", lambda message: True)
    monkeypatch.setattr(ar.config, "load", lambda: type("Config", (), {"get": lambda self, *args: args[-1]})())


class FakeMDM:
    available = True
    device_id = 7

    def __init__(self, installed):
        self.installed, self.calls = set(installed), []
        self._reported = set(installed)
        self._contact = NOON - 3600
        self._scanned_after = None

    @property
    def contact(self):
        return self._contact

    @contact.setter
    def contact(self, at):
        self._contact = at
        if self._scanned_after is not None and at > self._scanned_after:
            self._reported = self.installed.copy()
            self._scanned_after = None

    def installed_apps(self):
        if not self._reported:
            raise mdm.MDMError("the device's app inventory is empty in ManageEngine (no app scan yet)")
        return self._reported.copy()

    def unlock(self, minutes):
        self.calls.append(("unlock", minutes))

    def devices(self):
        return [{"device_id": 7, "managed_status": "2", "last_contact_time": self.contact * 1000}]

    def scan(self):
        self.calls.append(("scan",))
        self._scanned_after = self.contact

    def lock(self):
        self.calls.append(("lock",))

    def block_app(self, bundle):
        self.calls.append(("block", bundle))


def fresh_contact(backend, after):
    backend.contact = after + ar.CONTACT_MARGIN + 1
    return backend.contact


def close_window(path, backend, at, report=pytest.fail):
    assert ar.tick(path, backend, report, now=at)["status"] == "closing"
    return ar.tick(path, backend, report, now=fresh_contact(backend, at))


def legacy_window(path, **fields):
    """A window persisted by an older version (unlock sent at request time, no pre-unlock scan phase)."""
    window = {"bundles": [], "snapshot": [], "until": 0, "sent_at": None, "delivered_at": None}
    window.update(fields)
    path.write_text(json.dumps({"devices": {"7": {"history": [], "window": window}}}))


def fetcher(result, seen=None):
    def fetch(url):
        if seen is not None:
            seen.append(url)
        return json.dumps({"resultCount": 1 if result else 0, "results": [result] if result else []}).encode()
    return fetch


@pytest.mark.parametrize("text,want", [
    ("https://apps.apple.com/il/app/%D7%9E%D7%99%D7%9C%D7%95%D7%9F/id123456789", "123456789"),
    ("https://apps.apple.com/us/app/whatsapp-messenger/id310633997?l=he&uo=4", "310633997"),
    ("https://apps.apple.com/app/id310633997", "310633997"),
    ("https://apps.apple.com/zh-hans/app/x/id310633997", "310633997"),
    ("  310633997 ", "310633997"),
    ("id310633997", "310633997"),
    ("", None), ("12345", None), ("http://apps.apple.com/app/id310633997", None),
    ("https://evil.example/apps.apple.com/app/id310633997", None),
    ("https://apps.apple.com.evil.example/app/id310633997", None),
    ("310633997; rm -rf ~", None), ("310633997 && curl x", None), ("$(id)310633997", None),
    ("https://apps.apple.com/app/id310633997\n--dry-run", None),
    ("https://apps.apple.com/app/x/id310633997?a=`id`", None),
    ("https://apps.apple.com/app/../../id310633997/../x", None),
    ("٣١٠٦٣٣٩٩٧", None),  # non-ASCII digits never reach the URL
    ("1" * 600, None),
])
def test_parse_app_id(text, want):
    assert ar.parse_app_id(text) == want


def test_lookup_fixed_url_and_us_fallback():
    seen = []

    def fetch(url):
        seen.append(url)
        return (b'{"results": []}' if "country=il" in url else json.dumps({"results": [app()]}).encode())
    assert ar.lookup("123456789", fetch)["bundleId"] == "com.example.dict"
    assert seen == ["https://itunes.apple.com/lookup?id=123456789&country=il",
                    "https://itunes.apple.com/lookup?id=123456789&country=us"]


@pytest.mark.parametrize("kw,status,word", [
    ({}, "approved", "Reference"),
    ({"bundleId": "com.burbn.instagram"}, "denied", "blocked apps"),
    ({"bundleId": "ph.telegra.Telegraph"}, "denied", "blocked apps"),
    ({"contentAdvisoryRating": "17+"}, "review", "17+"),
    ({"contentAdvisoryRating": "18+"}, "denied", "18+"),
    ({"contentAdvisoryRating": "18+"}, "denied", "18+"),
    ({"primaryGenreName": "Social Networking", "genres": ["Social Networking"]}, "denied", "Social"),
    ({"genres": ["Reference", "Casino"]}, "denied", "Casino"),
    ({"primaryGenreName": "Dating", "genres": ["Dating"]}, "denied", "Dating"),
    ({"trackName": "Fast VPN"}, "denied", "VPN"),
    ({"description": "A private browser with tabs"}, "review", "browser"),
    ({"trackName": "Private Browser"}, "denied", "Browser"),
    ({"description": "Route traffic via Tor"}, "review", "Tor"),
    ({"description": "Watch live streaming"}, "review", "live streaming"),
    ({"description": "Meet people in anonymous chat rooms"}, "review", "anonymous chat"),
    ({"description": "Text editor and monitor"}, "approved", ""),  # 'tor' only as a word
    ({"trackName": "Family Chat"}, "review", "messaging"),
    ({"description": "The secure messaging app for teams"}, "review", "messaging"),
    ({"primaryGenreName": "Games", "genres": ["Games", "Education"]}, "review", "Games"),
    ({"primaryGenreName": "Education", "genres": ["Education", "Entertainment"]}, "review", "Entertainment"),
    ({"primaryGenreName": "Photo & Video", "genres": ["Photo & Video"]}, "review", "Photo"),
    ({"primaryGenreName": "News", "genres": ["News"]}, "review", "News"),
    ({"primaryGenreName": "Shopping", "genres": ["Shopping"]}, "review", "Shopping"),
    ({"primaryGenreName": "Music", "genres": ["Music"]}, "review", "safe list"),
    ({"primaryGenreName": None, "genres": []}, "review", "unknown"),
    ({"contentAdvisoryRating": None}, "review", "rating"),
    ({"primaryGenreName": "Education", "genres": ["Education"], "contentAdvisoryRating": "12+"}, "approved", ""),
])
def test_decide_branches(kw, status, word):
    got, reason = ar.decide(app(**kw), NOON, [])
    assert got == status and word in reason and "\n" not in reason


def test_night_rule_fixed_clock():
    assert ar.decide(app(), NIGHT, [])[0] == "review"
    assert "night" in ar.decide(app(), NIGHT, [])[1]
    early = datetime(2026, 11, 15, 5, 59, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()
    assert ar.decide(app(), early, [])[0] == "review"
    six = datetime(2026, 11, 15, 6, 0, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()
    assert ar.decide(app(), six, [])[0] == "approved"
    for g in ("Medical", "Health & Fitness", "Finance"):
        assert ar.decide(app(primaryGenreName=g, genres=[g]), NIGHT, [])[0] == "approved"
    assert ar.decide(app(bundleId="com.burbn.instagram"), NIGHT, [])[0] == "denied"


def test_seven_day_denial_memory():
    past = [{"t": NOON - 6 * 86400, "bundle": "com.example.dict", "status": "denied"}]
    assert ar.decide(app(), NOON, past) == ("denied", "denied less than 7 days ago; not reviewed again yet")
    old = [{"t": NOON - 8 * 86400, "bundle": "com.example.dict", "status": "denied"}]
    assert ar.decide(app(), NOON, old)[0] == "approved"


def test_denial_recorded_and_remembered(tmp_path):
    state, lines = tmp_path / "s.json", []
    out = ar.request("123456789", state, FakeMDM(["com.existing"]), fetch=fetcher(app(trackName="Proxy Pro")),
                     report=lines.append, now=NOON)
    assert out["status"] == "denied" and lines == []
    out = ar.request("123456789", state, FakeMDM(["com.existing"]), fetch=fetcher(app()), report=lines.append, now=NOON + 3600)
    assert out["status"] == "denied" and "7 days" in out["reason"]


def test_review_one_ledger_line(tmp_path):
    lines = []
    out = ar.request("123456789", tmp_path / "s.json", FakeMDM(["com.existing"]), note="school\x1b[2J group",
                     fetch=fetcher(app(trackName="Class Chat")), report=lines.append, now=NOON)
    assert out["status"] == "review" and len(lines) == 1
    assert "Class Chat" in lines[0] and "owner note: school [2J group" in lines[0] and "\x1b" not in lines[0]


def test_approved_opens_window(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.a", "com.b"])
    out = ar.request("123456789", state, backend, fetch=fetcher(app()), report=lambda l: None, now=NOON)
    # Tightened rule: the request only asks the device for a fresh inventory; the store stays locked.
    assert out["status"] == "approved" and out["delivered"] is False and out["until"] is None
    assert out["bundle"] == "com.example.dict" and out["reason"].endswith(ar.PENDING_REASON)
    assert backend.calls == [("lock",), ("scan",)]
    saved = json.loads(state.read_text())["devices"]["7"]
    assert saved["window"]["names"] == {"com.example.dict": "Hebrew Dictionary"}
    assert saved["window"]["scan_requested_at"] == NOON and saved["window"]["snapshot"] is None
    assert saved["window"]["sent_at"] is None and saved["window"]["delivered_at"] is None
    assert saved["window"]["until"] == NOON + ar.PENDING_MAX
    assert saved["history"][-1]["status"] == "approved"


@pytest.mark.parametrize("lock_fails", [False, True])
def test_queue_requires_a_successful_lock_before_baseline(tmp_path, monkeypatch, lock_fails):
    path, backend = tmp_path / "state.json", FakeMDM(["com.existing"])
    real_lock, real_scan = backend.lock, backend.scan

    def lock():
        real_lock()
        if lock_fails:
            raise OSError("cannot lock")

    def scan():
        saved = ar._load(path, backend)
        assert saved["locked"] and saved["window"]["snapshot"] is None
        assert backend.calls == [("lock",)]
        real_scan()

    monkeypatch.setattr(backend, "lock", lock)
    monkeypatch.setattr(backend, "scan", scan)
    result = ar.request("123456789", path, backend, fetch=fetcher(app()), now=NOON, report=pytest.fail)
    if lock_fails:
        assert result["status"] == "error" and "lock failed" in result["reason"]
        assert ar._load(path, backend)["window"] is None
        assert backend.calls == [("lock",)]
        assert ar.tick(path, backend, now=fresh_contact(backend, NOON), report=pytest.fail)["status"] == "error"
        assert backend.calls == [("lock",), ("lock",)]
    else:
        assert result["status"] == "approved"
        assert ar.tick(path, backend, now=fresh_contact(backend, NOON), report=pytest.fail)["status"] == "open"
        assert ar._load(path, backend)["window"]["snapshot"] == ["com.existing"]
        assert backend.calls == [("lock",), ("scan",), ("unlock", 15)]


def test_previous_version_pending_scan_is_repeated_after_lock(tmp_path):
    path, backend = _pending_window(tmp_path)
    saved = ar._load(path, backend)
    saved["locked"] = False  # older queued requests did not establish a lock before their scan
    ar._save(path, saved)
    backend.calls.clear()
    first_contact = fresh_contact(backend, NOON)
    assert ar.tick(path, backend, now=first_contact, report=pytest.fail)["status"] == "pending_device"
    assert backend.calls == [("lock",), ("scan",)]
    assert ar._load(path, backend)["window"]["snapshot"] is None
    assert ar.tick(path, backend, now=fresh_contact(backend, first_contact), report=pytest.fail)["status"] == "open"


def test_dry_run_changes_nothing(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.existing"])
    out = ar.request("123456789", state, backend, dry=True, fetch=fetcher(app()), report=pytest.fail, now=NOON)
    assert out["status"] == "approved" and out["reason"].startswith("dry run")
    assert backend.calls == [] and not state.exists()


def test_no_mdm_exit_4(tmp_path, monkeypatch, capsys):
    lines = []
    out = ar.request("123456789", tmp_path / "s.json", mdm.NoMDM(), fetch=fetcher(app()), report=lines.append,
                     now=NOON)
    assert out["status"] == "approved_waiting_mdm" and out["until"] is None and len(lines) == 1
    assert ar.EXIT[out["status"]] == 4
    # Through main: config backend "none", lookup mocked.
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "filter.db"))
    monkeypatch.setattr(ar, "_fetch", fetcher(app()))
    monkeypatch.setattr(ar, "request", lambda *a, **k: out)
    assert ar.main(["https://apps.apple.com/app/id123456789"]) == 4
    printed = capsys.readouterr().out.strip().splitlines()
    assert len(printed) == 1 and set(json.loads(printed[0])) == {"status", "app", "bundle", "reason", "until"}


def test_main_bad_input_exit_1(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "filter.db"))
    monkeypatch.setattr(ar, "_fetch", lambda url: pytest.fail("network"))
    assert ar.main(["123; rm -rf /"]) == 1
    assert ar.main([]) == 1
    assert ar.main(["--help"]) == 1
    outs = capsys.readouterr().out.strip().splitlines()
    assert len(outs) == 3 and all(json.loads(o)["status"] == "error" for o in outs)


def test_lookup_failure_is_error(tmp_path):
    def boom(url):
        raise OSError("timed out")
    out = ar.request("123456789", tmp_path / "s.json", FakeMDM(["com.existing"]), fetch=boom, report=pytest.fail, now=NOON)
    assert out["status"] == "error" and "timed out" in out["reason"]
    out = ar.request("123456789", tmp_path / "s.json", FakeMDM(["com.existing"]), fetch=fetcher(None), report=pytest.fail, now=NOON)
    assert out["status"] == "error"


def test_tick_blocks_extra_app_and_is_idempotent(tmp_path):
    state, backend, lines = tmp_path / "s.json", FakeMDM(["com.a"]), []
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=lines.append, now=NOON)
    opened = ar.tick(state, backend, lines.append, now=fresh_contact(backend, NOON))
    assert opened["status"] == "open"
    backend.installed |= {"com.example.dict", "com.sneaky.game"}
    out = close_window(state, backend, opened["until"], lines.append)
    assert out["status"] == "locked" and out["blocked"] == ["com.sneaky.game"]
    assert backend.calls == [("lock",), ("scan",), ("unlock", 15), ("lock",), ("scan",),
                             ("block", "com.sneaky.game")]
    assert len(lines) == 1 and "com.sneaky.game" in lines[0]
    assert ar.tick(state, backend, lines.append, now=NOON + 2000)["status"] == "idle"
    assert len(backend.calls) == 6 and len(lines) == 1


def test_tick_without_window_or_state(tmp_path):
    assert ar.tick(tmp_path / "none.json", mdm.NoMDM(), pytest.fail, now=NOON)["status"] == "idle"


def test_tick_retries_after_lock_failure(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.existing"])
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=lambda l: None, now=NOON)
    opened = ar.tick(state, backend, pytest.fail, now=fresh_contact(backend, NOON))
    assert opened["status"] == "open"
    backend.lock = lambda: (_ for _ in ()).throw(OSError("mdm down"))
    assert ar.tick(state, backend, pytest.fail, now=opened["until"])["status"] == "error"
    assert json.loads(state.read_text())["devices"]["7"]["window"]  # kept for the next tick


def test_scan_failure_fails_closed(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.existing"])
    backend.scan = lambda: (_ for _ in ()).throw(OSError("mdm down"))
    out = ar.request("123456789", state, backend, fetch=fetcher(app()), report=lambda l: None, now=NOON)
    assert out["status"] == "error" and out["until"] is None and "scan failed" in out["reason"]
    assert ("lock",) in backend.calls and json.loads(state.read_text())["devices"]["7"]["window"]["until"] == NOON
    assert not any(call[0] == "unlock" for call in backend.calls)
    out = ar.tick(state, backend, report=lambda l: None, now=NOON + 1)  # an expired scan window is closed at once
    assert out["status"] == "locked" and json.loads(state.read_text())["devices"]["7"]["window"] is None


def test_unlock_failure_fails_closed(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.a"])
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=lambda l: None, now=NOON)
    unlock_at = fresh_contact(backend, NOON)
    backend.unlock = lambda minutes: (_ for _ in ()).throw(OSError("mdm down"))
    out = ar.tick(state, backend, report=lambda l: None, now=unlock_at)
    assert out["status"] == "error" and "unlock failed" in out["reason"]
    saved = json.loads(state.read_text())["devices"]["7"]["window"]
    assert backend.calls[-1] == ("lock",) and saved["unlock_failed"] and saved["until"] == unlock_at
    backend.installed.add("com.partial.unlock")  # a half-applied unlock still gets its apps blocked
    out = close_window(state, backend, unlock_at + 1, lambda l: None)
    assert out["status"] == "locked" and out["blocked"] == ["com.partial.unlock"]
    assert json.loads(state.read_text())["devices"]["7"]["window"] is None


def test_backends():
    assert isinstance(mdm.backend("none"), mdm.NoMDM) and not mdm.NoMDM.available
    me = mdm.backend("manageengine")
    assert isinstance(me, mdm.ManageEngineMDM) and me.available and "secret" not in repr(me).lower()
    with pytest.raises(ValueError):
        mdm.backend("other")


def test_set_restrictions_import_has_no_side_effects():
    from deploy import set_restrictions
    assert "com.burbn.instagram" in set_restrictions.BLOCKED_APPS and callable(set_restrictions.main)


def test_mdm_failure_before_unlock_is_exit_4_and_opens_nothing(tmp_path):
    lines, backend = [], FakeMDM([])
    out = ar.request("123456789", tmp_path / "s.json", backend, fetch=fetcher(app()), report=lines.append, now=NOON)
    assert out["status"] == "approved_waiting_mdm" and ar.EXIT[out["status"]] == 4 and out["until"] is None
    assert backend.calls == [("lock",)] and len(lines) == 1 and "MDM failed before unlock" in out["reason"]
    assert json.loads((tmp_path / "s.json").read_text())["devices"]["7"]["window"] is None


@pytest.mark.parametrize("minute,duration", [(0, 15), (25, 4)])
def test_nightly_testflight_window_scans_then_opens_once(tmp_path, monkeypatch, minute, duration):
    monkeypatch.setitem(ar.COMMITTEE_APPROVED, "com.example.static", "test approval")
    state, lines = tmp_path / "s.json", []
    at = datetime(2026, 11, 16, 2, minute, tzinfo=ar.ISRAEL).timestamp()
    end = datetime(2026, 11, 16, 2, 30, tzinfo=ar.ISRAEL).timestamp()
    backend = FakeMDM(["com.existing", "com.apple.TestFlight"])
    assert ar.tick(state, backend, report=lines.append, now=at - minute * 60 - 1)["status"] == "idle"
    backend.contact = at
    queued = ar.tick(state, backend, report=lines.append, now=at)
    assert queued["status"] == "pending_device" and queued["until"] == end
    assert backend.calls == [("lock",), ("lock",), ("scan",)]
    assert ar.tick(state, backend, report=lines.append, now=at + 1)["status"] == "pending_device"
    assert ar._load(state, backend)["window"]["snapshot"] is None
    backend.installed.add("com.preexisting")
    unlock_at = fresh_contact(backend, at)
    opened = ar.tick(state, backend, report=lines.append, now=unlock_at)
    assert opened["status"] == "open" and opened["until"] == min(end, unlock_at + 900)
    assert opened["bundle"] == ar.NIGHTLY_BUNDLE and backend.calls[-1] == ("unlock", duration)
    backend.installed |= {ar.NIGHTLY_BUNDLE, "com.example.static", "com.unapproved"}
    backend.contact = unlock_at + 1
    ar.tick(state, backend, report=lines.append, now=unlock_at + 1)
    assert ar._load(state, backend)["window"]["snapshot"] == ["com.apple.TestFlight", "com.existing", "com.preexisting"]
    assert close_window(state, backend, opened["until"], lines.append)["blocked"] == ["com.unapproved"]
    assert ar.tick(state, backend, report=lines.append, now=backend.contact + 1)["status"] == "idle"
    assert backend.calls[-3:] == [("lock",), ("scan",), ("block", "com.unapproved")]


def test_nightly_window_never_unlocks_on_a_late_contact(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.existing"])
    end = datetime(2026, 11, 16, 2, 30, tzinfo=ar.ISRAEL).timestamp()
    assert ar.tick(state, backend, report=pytest.fail, now=end - 120)["status"] == "pending_device"
    backend.contact = end - 1
    reports = []
    assert ar.tick(state, backend, report=reports.append, now=end)["status"] == "locked"
    assert backend.calls == [("lock",), ("scan",), ("lock",)]
    assert len(reports) == 1 and "nightly" in reports[0]


def test_nightly_window_ignores_daily_cap_and_throttles_expiry_notice(tmp_path):
    state, backend, reports = tmp_path / "s.json", FakeMDM(["com.existing"]), []
    at = datetime(2026, 11, 16, 2, 0, tzinfo=ar.ISRAEL).timestamp()
    for day, delay, expected_reports in ((0, 3600, 1), (1, 1800, 1), (2, 1800, 2)):
        start = at + day * 86400
        saved = ar._load(state, backend)
        capped = [start - 3600, start - 1800, start - 60]
        saved["window_requests"] = capped
        ar._save(state, saved)
        assert ar.tick(state, backend, now=start, report=pytest.fail)["status"] == "pending_device"
        assert ar.tick(state, backend, now=start + delay, report=reports.append)["status"] == "locked"
        assert ar._load(state, backend)["window_requests"] == capped
        assert len(reports) == expected_reports
    assert all("nightly window expired" in line for line in reports)
    assert not any(call[0] == "unlock" for call in backend.calls)


def test_legacy_nightly_window_still_closes_on_schedule(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.a"])
    at = datetime(2026, 11, 16, 2, 5, tzinfo=ar.ISRAEL).timestamp()
    end = datetime(2026, 11, 16, 2, 30, tzinfo=ar.ISRAEL).timestamp()
    legacy_window(state, label="nightly updates", until=end, snapshot=["com.a"], sent_at=at, delivered_at=at,
                  scan_at=at)
    backend.installed.add("com.new")
    out = close_window(state, backend, end, lambda l: None)
    assert out["status"] == "locked" and ("block", "com.new") in backend.calls


def test_name_search_finds_the_app_and_rejects_junk(tmp_path):
    seen = []
    def fetch(url):
        seen.append(url)
        if "/search?" in url:
            return json.dumps({"results": [{"trackId": 123456789}]}).encode()
        return json.dumps({"resultCount": 1, "results": [app()]}).encode()
    out = ar.request("Hebrew Dictionary", tmp_path / "s.json", FakeMDM(["com.existing"]), dry=True, fetch=fetch,
                     report=pytest.fail, now=NOON)
    assert out["app"] == "Hebrew Dictionary" and "term=Hebrew%20Dictionary" in seen[0]
    for junk in ("123; rm -rf /", "a", "12345", "x" * 61, "<script>"):
        assert ar.search_app_id(junk, fetch=lambda url: pytest.fail("network")) is None


def test_tick_and_status_words_are_requests_not_subcommands(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "filter.db"))
    seen = []
    monkeypatch.setattr(ar, "request", lambda link, *a, **k: seen.append(link) or ar._out("review", reason="x"))
    assert ar.main(["tick"]) == 3 and ar.main(["status"]) == 3 and seen == ["tick", "status"]
    assert ar.main(["--status"]) == 0


def test_book_genre_spelling_is_safe():
    got, _ = ar.decide(app(primaryGenreName="Book", genres=["Book"]), NOON, [])
    assert got == "approved"


def test_testflight_trusted_installer_day_approved_night_reviewed():
    tf = app(bundleId="com.apple.TestFlight", trackName="TestFlight", primaryGenreName="Developer Tools",
             genres=["Developer Tools"])
    status, reason = ar.decide(tf, NOON, [])
    assert status == "approved" and "TestFlight" in reason
    # the night rule precedes every allow path, trusted installers included
    status, reason = ar.decide(tf, NIGHT, [])
    assert status == "review" and "night" in reason
    # a different developer tool still goes to the committee
    other = dict(tf, bundleId="com.example.devtool", trackName="Dev Tool")
    assert ar.decide(other, NOON, [])[0] == "review"


def test_committee_approved_list_day_and_night(monkeypatch):
    from scripts import app_request as ar
    monkeypatch.setitem(ar.COMMITTEE_APPROVED, "example.finance", "test approval")
    app = {"bundleId": "example.finance", "trackName": "Example Finance", "primaryGenreName": "Finance",
           "genres": ["Finance", "Lifestyle"], "contentAdvisoryRating": "17+", "description": ""}
    for now in (1763200800, 1763240400):  # day and night
        assert ar.decide(app, now, [])[0] == "approved"
    assert ar.decide({**app, "contentAdvisoryRating": "18+"}, 1763200800, [])[0] == "denied"
    assert all(k == k.lower() for k in ar.COMMITTEE_APPROVED)


def test_delivery_immediate_and_status_once(tmp_path):
    state, backend, messages = tmp_path / "state.json", FakeMDM(["com.existing"]), []
    out = ar.request("123456789", state, backend, fetch=fetcher(app()), report=pytest.fail, now=NOON)
    assert out["status"] == "approved" and ar.status(state)["status"] == "pending_device"
    assert ar.status(state)["delivered"] is False
    unlock_at = fresh_contact(backend, NOON)
    out = ar.tick(state, backend, report=pytest.fail, now=unlock_at, notify=messages.append)
    assert out["status"] == "open" and out["delivered"] is True and out["until"] == unlock_at + 900
    assert ar.status(state)["delivered"] is True
    ar.tick(state, backend, report=pytest.fail, now=unlock_at + 1, notify=messages.append)
    assert messages == ["סינון: חנות האפליקציות פתוחה עכשיו ל-15 דקות להתקנת Hebrew Dictionary."]


def test_late_delivery_extends_window_and_scans_are_throttled(tmp_path):
    state, backend, messages = tmp_path / "state.json", FakeMDM(["com.existing"]), []
    backend.contact = NOON - 1
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=pytest.fail, now=NOON)
    for offset in (119, 120, 121, 600, 601, 1000):
        out = ar.tick(state, backend, report=pytest.fail, now=NOON + offset, notify=messages.append)
        assert out["status"] == "pending_device" and not out["delivered"]
    assert backend.calls.count(("scan",)) == 4  # initial, 120, 600, 1000
    assert not any(call[0] == "unlock" for call in backend.calls)
    assert len(messages) == 1 and "10 שניות" in messages[0]
    backend.contact = NOON + 1000
    out = ar.tick(state, backend, report=pytest.fail, now=NOON + 1001, notify=messages.append)
    assert out["until"] == NOON + 1901 and out["delivered"]  # 15 minutes from the unlock, never earlier
    assert len(messages) == 2 and "Hebrew Dictionary" in messages[1]
    assert ar.tick(state, backend, report=pytest.fail, now=NOON + 1900, notify=messages.append)["status"] == "open"
    assert close_window(state, backend, NOON + 1901)["status"] == "locked"
    assert len(messages) == 2


def test_never_delivered_locks_and_reports_once(tmp_path):
    state, backend, messages, reports = tmp_path / "state.json", FakeMDM(["com.existing"]), [], []
    backend.contact = NOON - 1
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=reports.append, now=NOON)
    assert ar.tick(state, backend, reports.append, now=NOON + ar.PENDING_MAX - 1,
                   notify=messages.append)["status"] == "pending_device"
    out = ar.tick(state, backend, reports.append, now=NOON + ar.PENDING_MAX, notify=messages.append)
    assert out["status"] == "locked" and not out["delivered"]
    assert len(reports) == 1 and "never answered the pre-unlock scan" in reports[0] and "com.example.dict" in reports[0]
    assert not any(call[0] == "unlock" for call in backend.calls)
    assert len(messages) == 2 and "במשך שעתיים" in messages[1]
    assert ar.tick(state, backend, reports.append, now=NOON + ar.PENDING_MAX + 1,
                   notify=messages.append)["status"] == "idle"
    assert len(messages) == 2 and backend.calls.count(("lock",)) == 2


def test_legacy_nightly_delivery_never_extends_fixed_end(tmp_path):
    state, backend = tmp_path / "state.json", FakeMDM(["com.existing"])
    at = datetime(2026, 11, 16, 2, 5, tzinfo=ar.ISRAEL).timestamp()
    end = at + 25 * 60
    legacy_window(state, label="nightly updates", until=end, snapshot=[], sent_at=at, scan_at=at)
    backend.contact = end - 60
    out = ar.tick(state, backend, pytest.fail, now=end - 60, notify=pytest.fail)
    assert out["delivered"] and out["until"] == end
    reports = []
    assert ar.tick(state, backend, reports.append, now=end, notify=pytest.fail)["status"] == "locked"
    assert len(reports) == 1 and "blocking skipped" in reports[0]


def _pending_window(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.existing"])
    backend.contact = NOON - 3600  # last contact before the unlock: not delivered
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=lambda l: None, now=NOON)
    return state, backend


def test_overdue_window_locks_even_if_the_phone_just_called_in(tmp_path):
    state, backend = _pending_window(tmp_path)
    backend.contact = NOON + ar.PENDING_MAX + 60
    out = ar.tick(state, backend, report=lambda l: None, now=NOON + ar.PENDING_MAX + 120, notify=lambda m: None)
    assert out["status"] == "locked" and ("lock",) in backend.calls


@pytest.mark.parametrize("missing", [False, True])
def test_transient_device_read_failure_keeps_window_until_pending_expiry(tmp_path, missing):
    state, backend = _pending_window(tmp_path)
    reports = []
    original_devices = backend.devices

    def boom():
        raise RuntimeError("ManageEngine down")

    backend.devices = (lambda: []) if missing else boom
    before = json.loads(state.read_text())["devices"]["7"]["window"]
    for at in (NOON + 60, NOON + 61):
        out = ar.tick(state, backend, report=reports.append, now=at, notify=lambda m: None)
        saved = json.loads(state.read_text())["devices"]["7"]["window"]
        assert out["status"] == "pending_device" and saved["bundles"] == before["bundles"]
        assert saved["until"] == before["until"] and backend.calls.count(("lock",)) == 1
    assert len(reports) == 1 and "will retry" in reports[0]

    backend.devices = original_devices
    out = ar.tick(state, backend, report=reports.append, now=NOON + ar.PENDING_MAX, notify=lambda m: None)
    assert out["status"] == "locked" and ("lock",) in backend.calls


def test_transient_inventory_refresh_keeps_window_until_pending_expiry(tmp_path):
    state, backend = _pending_window(tmp_path)
    fresh_contact(backend, NOON)
    reports = []
    original_inventory = backend.installed_apps

    def boom():
        raise RuntimeError("inventory unavailable")

    backend.installed_apps = boom
    before = json.loads(state.read_text())["devices"]["7"]["window"]
    for at in (backend.contact, backend.contact + 1):
        out = ar.tick(state, backend, report=reports.append, now=at, notify=lambda m: None)
        saved = json.loads(state.read_text())["devices"]["7"]["window"]
        assert out["status"] == "pending_device" and saved["bundles"] == before["bundles"]
        assert saved["until"] == before["until"] and saved["delivered_at"] is None
        assert backend.calls.count(("lock",)) == 1
    assert len(reports) == 1 and "will retry" in reports[0]

    backend.installed_apps = original_inventory
    out = ar.tick(state, backend, report=reports.append, now=NOON + ar.PENDING_MAX, notify=lambda m: None)
    assert out["status"] == "locked" and ("lock",) in backend.calls


def test_state_write_failure_never_stops_the_lock(tmp_path, monkeypatch):
    state, backend = _pending_window(tmp_path)
    opened = ar.tick(state, backend, now=fresh_contact(backend, NOON), report=pytest.fail)

    def failing(path, data):
        raise OSError("disk full")

    monkeypatch.setattr(ar, "_save", failing)
    out = ar.tick(state, backend, report=pytest.fail, now=opened["until"], notify=pytest.fail)
    assert out["status"] == "error" and "disk full" in out["reason"]
    assert backend.calls[:4] == [("lock",), ("scan",), ("unlock", 15), ("lock",)]
    assert ar._load(state, backend)["window"]["until"] == opened["until"]


def test_inventory_is_taken_before_unlock_and_never_refreshed_after(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.a"])
    backend.contact = NOON - 3600
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=lambda l: None, now=NOON)
    backend.installed |= {"com.old.unseen", "com.example.approved-app-5"}  # inventory caught up late
    fresh_contact(backend, NOON)  # apps present now were there before the unlock
    assert ar.tick(state, backend, report=lambda l: None, now=NOON + 120, notify=lambda m: None)["status"] == "open"
    backend.installed |= {"com.example.dict", "com.sneaky.new"}
    backend.contact = NOON + 200  # a later contact must not fold com.sneaky.new into the baseline
    assert ar.tick(state, backend, report=lambda l: None, now=NOON + 300, notify=lambda m: None)["status"] == "open"
    out = close_window(state, backend, NOON + 120 + 901, lambda l: None)
    assert out["status"] == "locked" and out["blocked"] == ["com.sneaky.new"]


class FleetDevice(FakeMDM):
    def __init__(self, did, fleet):
        super().__init__([f"com.existing.{did}"])
        self.device_id, self.fleet = did, fleet
        self.unreadable = False

    @property
    def device_ids(self):
        return self.fleet.device_ids

    def for_device(self, did):
        return self.fleet.for_device(did)

    def devices(self):
        return [{"device_id": did, "managed_status": "2", "last_contact_time": dev.contact * 1000}
                for did, dev in self.fleet.targets.items() if not dev.unreadable]

    def installed_apps(self):
        if self.unreadable:
            raise RuntimeError("inventory unreadable")
        return super().installed_apps()


class Fleet:
    available = True
    device_ids = (mdm.IPHONE, mdm.IPAD)
    device_id = mdm.IPHONE

    def __init__(self):
        self.targets = {did: FleetDevice(did, self) for did in self.device_ids}

    def for_device(self, did):
        return self.targets[did]


def test_tick_initializes_both_devices_locked_without_opening_windows(tmp_path):
    fleet, path = Fleet(), tmp_path / "s.json"
    out = ar.tick(path, fleet, now=NOON, report=pytest.fail, notify=pytest.fail)
    assert set(out["devices"]) == set(fleet.device_ids)
    assert all(d.calls == [("lock",)] for d in fleet.targets.values())
    ar.tick(path, fleet, now=NOON + 60, report=pytest.fail, notify=pytest.fail)
    assert all(d.calls == [("lock",)] for d in fleet.targets.values())


@pytest.mark.parametrize("contents", ["{invalid", '{"devices": []}'])
def test_corrupt_state_locks_every_device_and_reports_once_per_day(tmp_path, contents):
    fleet, path, reports = Fleet(), tmp_path / "s.json", []
    path.write_text(contents)
    out = ar.tick(path, fleet, now=NOON, report=reports.append, notify=pytest.fail)
    assert out["status"] == "error"
    assert all(d.calls == [("lock",)] for d in fleet.targets.values())
    assert len(reports) == 1 and "corrupt or unreadable" in reports[0]

    with pytest.raises(ValueError):
        ar.request("123456789", path, fleet, fetch=fetcher(app()), now=NOON + 1, report=pytest.fail)
    assert len(reports) == 1 and path.read_text() == contents
    ar.tick(path, fleet, now=NOON + ar.REPORT_INTERVAL - 1, report=pytest.fail, notify=pytest.fail)
    ar.tick(path, fleet, now=NOON + ar.REPORT_INTERVAL, report=reports.append, notify=pytest.fail)
    assert len(reports) == 2 and path.read_text() == contents
    assert all(all(call == ("lock",) for call in device.calls) for device in fleet.targets.values())


@pytest.mark.parametrize("device,target", [(None, mdm.IPHONE), ("iphone", mdm.IPHONE), ("ipad", mdm.IPAD),
                                           (mdm.IPAD, mdm.IPAD)])
def test_request_window_and_delivery_never_unlock_other_device(tmp_path, device, target):
    fleet, path, messages = Fleet(), tmp_path / "s.json", []
    ar.tick(path, fleet, now=NOON, report=pytest.fail, notify=pytest.fail)
    out = ar.request("123456789", path, fleet, device=device, fetch=fetcher(app()), now=NOON, report=pytest.fail)
    assert out["status"] == "approved"
    unlock_at = fresh_contact(fleet.targets[target], NOON)
    results = ar.tick(path, fleet, now=unlock_at, report=pytest.fail, notify=messages.append)["devices"]
    assert results[target]["status"] == "open" and results[target]["delivered"]
    other = next(did for did in fleet.device_ids if did != target)
    assert results[other]["status"] == "idle"
    assert fleet.targets[other].calls == [("lock",)]
    assert fleet.targets[target].calls == [("lock",), ("lock",), ("scan",), ("unlock", 15)]
    assert len(messages) == 1 and mdm.device_label(target) in messages[0]
    saved = json.loads(path.read_text())["devices"]
    assert saved[target]["window"]["snapshot"] == [f"com.existing.{target}"]
    assert saved[other]["window"] is None and saved[other]["history"] == []


def test_app_state_migration_preserves_phone_history_and_window_when_ipad_requested_first(tmp_path):
    path, fleet = tmp_path / "s.json", Fleet()
    old = {"history": [{"t": NOON - 60, "bundle": "com.old.app", "status": "approved"}],
           "window": {"bundles": ["com.old.app"], "until": NOON + 600, "snapshot": ["com.existing.phone"]},
           "nightly_day": "2026-11-15", "future_metadata": {"keep": True}}
    path.write_text(json.dumps(old))
    out = ar.request("123456789", path, fleet, device="ipad", fetch=fetcher(app()), now=NOON, report=pytest.fail)
    assert out["status"] == "approved"
    saved = json.loads(path.read_text())["devices"]
    assert saved[mdm.IPHONE] == old
    assert saved[mdm.IPAD]["history"][0]["bundle"] == "com.example.dict"
    assert saved[mdm.IPAD]["window"]["bundles"] == ["com.example.dict"]
    assert fleet.targets[mdm.IPHONE].calls == []


def test_expired_window_blacklists_only_that_devices_extra_apps(tmp_path):
    fleet, path = Fleet(), tmp_path / "s.json"
    for target in ("iphone", "ipad"):
        ar.request("123456789", path, fleet, device=target, fetch=fetcher(app()), now=NOON, report=pytest.fail)
    for target in fleet.targets.values():
        unlock_at = fresh_contact(target, NOON)
    ar.tick(path, fleet, now=unlock_at, report=pytest.fail, notify=lambda m: True)
    for did, target in fleet.targets.items():
        target.installed.add(f"com.extra.{did}")
    expiry = unlock_at + 900
    closing = ar.tick(path, fleet, now=expiry, report=pytest.fail, notify=pytest.fail)["devices"]
    assert all(result["status"] == "closing" for result in closing.values())
    for target in fleet.targets.values():
        checked_at = fresh_contact(target, expiry)
    results = ar.tick(path, fleet, now=checked_at, report=lambda m: None, notify=pytest.fail)["devices"]
    for did, target in fleet.targets.items():
        assert results[did]["blocked"] == [f"com.extra.{did}"]
        assert target.calls[-3:] == [("lock",), ("scan",), ("block", f"com.extra.{did}")]


def test_unreadable_ipad_stays_locked_while_phone_window_continues(tmp_path):
    fleet, path = Fleet(), tmp_path / "s.json"
    fleet.targets[mdm.IPAD].unreadable = True
    ar.request("123456789", path, fleet, device="iphone", fetch=fetcher(app()), now=NOON, report=pytest.fail)
    unlock_at = fresh_contact(fleet.targets[mdm.IPHONE], NOON)
    results = ar.tick(path, fleet, now=unlock_at, report=pytest.fail, notify=lambda m: True)["devices"]
    assert results[mdm.IPHONE]["status"] == "open" and results[mdm.IPHONE]["delivered"]
    assert results[mdm.IPAD]["status"] == "idle"
    assert fleet.targets[mdm.IPAD].calls == [("lock",)]
    assert not any(call[0] == "unlock" for call in fleet.targets[mdm.IPAD].calls)


def test_missing_device_during_pending_window_waits_only_for_that_device(tmp_path):
    fleet, path = Fleet(), tmp_path / "s.json"
    for did in fleet.device_ids:
        ar.request("123456789", path, fleet, device=did, fetch=fetcher(app()), now=NOON, report=pytest.fail)
    fleet.targets[mdm.IPAD].unreadable = True
    phone_unlock_at = fresh_contact(fleet.targets[mdm.IPHONE], NOON)
    reports = []
    out = ar.tick(path, fleet, now=phone_unlock_at, report=reports.append, notify=lambda m: True)
    assert out["devices"][mdm.IPHONE]["status"] == "open"
    assert out["devices"][mdm.IPAD]["status"] == "pending_device"
    assert len(reports) == 1 and "will retry" in reports[0]
    assert fleet.targets[mdm.IPAD].calls[-1] != ("lock",)
    assert fleet.targets[mdm.IPHONE].calls.count(("lock",)) == 1
    fleet.targets[mdm.IPAD].unreadable = False
    tablet_unlock_at = fresh_contact(fleet.targets[mdm.IPAD], NOON + 1)
    out = ar.tick(path, fleet, now=tablet_unlock_at, report=lambda m: None, notify=lambda m: True)
    assert out["devices"][mdm.IPAD]["status"] == "open"
    assert out["devices"][mdm.IPHONE]["status"] == "open"


def test_unconfigured_target_is_rejected_before_lookup_or_unlock(tmp_path):
    fleet = Fleet()
    with pytest.raises(ValueError, match="not configured"):
        ar.request("123456789", tmp_path / "s.json", fleet, device="999", fetch=pytest.fail, now=NOON)
    assert all(not target.calls for target in fleet.targets.values())


def test_main_request_accepts_device_and_status_reports_each_device(tmp_path, monkeypatch, capsys):
    fleet, seen = Fleet(), []
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "filter.db"))
    monkeypatch.setattr(mdm, "backend", lambda name: fleet)
    monkeypatch.setattr(ar, "request", lambda *a, **kw: seen.append(kw["device"]) or ar._out("review"))
    assert ar.main(["Dictionary", "--device", "ipad"]) == 3
    assert seen == ["ipad"]
    assert json.loads(capsys.readouterr().out)["device_id"] == mdm.IPAD
    assert ar.main(["--status"]) == 0
    assert set(json.loads(capsys.readouterr().out)["devices"]) == set(fleet.device_ids)


@pytest.mark.parametrize("device_data", [[], [{"device_id": mdm.IPAD, "managed_status": "2"}],
    [{"device_id": mdm.IPAD, "managed_status": "4", "last_contact_time": (NOON + 1) * 1000}],
    [{"device_id": mdm.IPAD, "managed_status": "2", "last_contact_time": "NaN"}]])
def test_unreadable_or_unmanaged_delivery_data_waits_without_closing_ipad(tmp_path, device_data):
    path, fleet = tmp_path / "s.json", Fleet()
    ar.request("123456789", path, fleet, device="ipad", fetch=fetcher(app()), now=NOON, report=pytest.fail)
    fleet.targets[mdm.IPAD].devices = lambda: device_data
    reports = []
    out = ar.tick(path, fleet, now=NOON + 1, report=reports.append, notify=pytest.fail)
    assert out["devices"][mdm.IPAD]["status"] == "pending_device"
    assert fleet.targets[mdm.IPAD].calls[-1] != ("lock",)
    assert json.loads(path.read_text())["devices"][mdm.IPAD]["window"]["bundles"] == ["com.example.dict"]
    assert len(reports) == 1 and "will retry" in reports[0]


def test_tick_and_request_serialize_the_whole_transaction(tmp_path, monkeypatch):
    path, backend = tmp_path / "s.json", FakeMDM(["com.existing"])
    locking, release, request_waiting = Event(), Event(), Event()
    real_lock, real_load = backend.lock, ar._load

    def slow_lock():
        locking.set()
        assert release.wait(5)
        real_lock()

    def checked_load(state_file, target=None):
        # A distinct descriptor (also in another process) must see the transaction's flock.
        with state_file.with_suffix(".json.lock").open("a") as probe:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return real_load(state_file, target)

    def fetch(url):
        request_waiting.set()
        return fetcher(app())(url)

    backend.lock = slow_lock
    monkeypatch.setattr(ar, "_load", checked_load)
    with ThreadPoolExecutor(max_workers=2) as pool:
        tick = pool.submit(ar.tick, path, backend, now=NOON, report=pytest.fail)
        try:
            assert locking.wait(5)
            request = pool.submit(ar.request, "123456789", path, backend, fetch=fetch,
                                  now=NOON, report=pytest.fail)
            assert request_waiting.wait(5)
            assert not request.done()
        finally:
            release.set()
        assert tick.result(timeout=5)["status"] == "idle"
        assert request.result(timeout=5)["status"] == "approved"
    saved = json.loads(path.read_text())["devices"]["7"]
    assert saved["window"]["bundles"] == ["com.example.dict"]
    assert saved["history"][-1]["status"] == "approved"
    assert backend.calls == [("lock",), ("lock",), ("scan",)]


def _closing_window(tmp_path):
    path, backend = _pending_window(tmp_path)
    expiry = ar.tick(path, backend, now=fresh_contact(backend, NOON), report=pytest.fail)["until"]
    assert ar.tick(path, backend, now=expiry, report=pytest.fail)["status"] == "closing"
    return path, backend, expiry


@pytest.mark.parametrize("previously_reported", [False, True])
def test_silent_device_reports_stalled_close_once_per_day(tmp_path, previously_reported):
    path, backend, expiry = _closing_window(tmp_path)
    first_report = expiry + ar.READ_GRACE
    if previously_reported:
        state = ar._load(path, backend)
        state["window"]["closing"]["read_failure_reported"] = True
        ar._save(path, state)
        first_report += ar.REPORT_INTERVAL

    reports = []
    for day in range(3):
        due = first_report + day * ar.REPORT_INTERVAL
        assert ar.tick(path, backend, now=due - 1, report=reports.append)["status"] == "closing"
        assert len(reports) == day
        for at in (due, due + ar.SCAN_INTERVAL):
            assert ar.tick(path, backend, now=at, report=reports.append)["status"] == "closing"
        assert len(reports) == day + 1 and "store stays locked" in reports[-1]
    assert ar._load(path, backend)["locked"]
    assert not any(action == "block" for action, *_ in backend.calls)


def test_closing_scan_backoff_caps_at_an_hour_and_resets_on_new_contact(tmp_path):
    path, backend, last_scan = _closing_window(tmp_path)
    report = lambda _line: None

    def scan_count():
        return backend.calls.count(("scan",))

    for minutes in (2, 4, 8, 16, 32, 60, 60):
        due = last_scan + minutes * 60
        scans = scan_count()
        assert ar.tick(path, backend, now=due - 1, report=report)["status"] == "closing"
        assert scan_count() == scans
        assert ar.tick(path, backend, now=due, report=report)["status"] == "closing"
        assert scan_count() == scans + 1
        last_scan = due

    backend.installed.clear()  # Contact can recover before the inventory does.
    scans = scan_count()
    at = fresh_contact(backend, last_scan)
    assert ar.tick(path, backend, now=at, report=report)["status"] == "closing"
    assert ar.tick(path, backend, now=last_scan + 119, report=report)["status"] == "closing"
    assert scan_count() == scans
    assert ar.tick(path, backend, now=last_scan + 120, report=report)["status"] == "closing"
    assert scan_count() == scans + 1
    # The same provider contact must not reset the timer again.
    assert ar.tick(path, backend, now=last_scan + 120 + 239, report=report)["status"] == "closing"
    assert scan_count() == scans + 1
    assert ar.tick(path, backend, now=last_scan + 120 + 240, report=report)["status"] == "closing"
    assert scan_count() == scans + 2


def test_closing_backoff_does_not_delay_normal_inventory_check(tmp_path):
    path, backend, expiry = _closing_window(tmp_path)
    assert ar.tick(path, backend, now=expiry + 120, report=pytest.fail)["status"] == "closing"
    scans = backend.calls.count(("scan",))
    backend.installed.add("com.extra")
    reports = []
    out = ar.tick(path, backend, now=fresh_contact(backend, expiry + 120), report=reports.append)
    assert out["status"] == "locked" and out["blocked"] == ["com.extra"]
    assert backend.calls.count(("scan",)) == scans
    saved = ar._load(path, backend)
    assert saved["window"] is None and saved["locked"]
    assert "closing_skips" not in saved


@pytest.mark.parametrize("hours, reported, contacted, reason", [
    (0, False, False, "at least 24 hours"),
    (23, True, False, "at least 24 hours"),
    (24, True, True, "newer contact"),
    (24, False, False, "already have been reported"),
])
def test_skip_closing_check_refuses_before_any_side_effect(tmp_path, monkeypatch, hours, reported, contacted, reason):
    path, backend, expiry = _closing_window(tmp_path)
    if reported:
        assert ar.tick(path, backend, now=expiry + ar.READ_GRACE, report=lambda _: True)["status"] == "closing"
    if contacted:
        backend.contact = expiry + 1
        assert ar.tick(path, backend, now=expiry + ar.READ_GRACE + 1, report=pytest.fail)["status"] == "closing"

    original = path.read_bytes()
    calls = backend.calls.copy()
    for method in ("devices", "installed_apps", "lock", "scan", "unlock", "block_app"):
        monkeypatch.setattr(backend, method, pytest.fail)
    monkeypatch.setattr(ar, "_ledger", pytest.fail)
    with pytest.raises(ValueError, match=reason):
        ar._skip_closing_check(path, backend, lambda: expiry + hours * 3600, pytest.fail)
    assert path.read_bytes() == original
    assert backend.calls == calls


def test_failed_stalled_report_does_not_make_skip_eligible(tmp_path):
    path, backend, expiry = _closing_window(tmp_path)
    now = expiry + 24 * 3600
    # The default reporter cannot write to the missing test ledger.
    assert ar.tick(path, backend, now=now)["status"] == "closing"
    assert "read_failure_reported_at" not in ar._load(path, backend)["window"]["closing"]
    with pytest.raises(ValueError, match="already have been reported"):
        ar._skip_closing_check(path, backend, lambda: now, pytest.fail)


def test_contact_survives_failed_post_lock_block(tmp_path, monkeypatch):
    path, backend, expiry = _closing_window(tmp_path)
    assert ar.tick(path, backend, now=expiry + ar.READ_GRACE, report=lambda _: True)["status"] == "closing"
    backend.installed.add("com.extra")
    now = fresh_contact(backend, expiry + 24 * 3600)

    def fail_block(_bundle):
        raise RuntimeError("block failed")

    monkeypatch.setattr(backend, "block_app", fail_block)
    assert ar.tick(path, backend, now=now, report=pytest.fail)["status"] == "error"
    assert ar._load(path, backend)["window"]["closing"]["last_contact_at"] == now
    with pytest.raises(ValueError, match="newer contact"):
        ar._skip_closing_check(path, backend, lambda: now, pytest.fail)


@pytest.mark.parametrize("contact_at_lock", [False, True])
def test_committee_skip_closing_check_keeps_lock_and_baseline_for_selected_device(tmp_path, monkeypatch, contact_at_lock):
    path, fleet = tmp_path / "app-requests.json", Fleet()
    for device in fleet.device_ids:
        ar.request("123456789", path, fleet, device=device, fetch=fetcher(app()), now=NOON, report=pytest.fail)
        unlock_at = fresh_contact(fleet.targets[device], NOON)
    ar.tick(path, fleet, now=unlock_at, report=pytest.fail)
    expiry = unlock_at + ar.WINDOW_MINUTES * 60
    ar.tick(path, fleet, now=expiry, report=pytest.fail)
    ar.tick(path, fleet, now=expiry + ar.READ_GRACE, report=lambda _: True)
    if contact_at_lock:
        target = fleet.targets[mdm.IPAD]
        state = ar._load(path, target)
        state["window"]["closing"]["last_contact_at"] = expiry
        ar._save(path, state)
    before = json.loads(path.read_text())["devices"]

    store = Store(ar.config.db_path())
    now = expiry + 24 * 3600
    committee = mcp_server.Committee(store, "committee", "tighten", clock=lambda: now,
                                     backend=fleet, app_state=path)
    calls = {did: dev.calls.copy() for did, dev in fleet.targets.items()}
    reports = []

    def report(line, *, required):
        assert required
        reports.append(line)
    monkeypatch.setattr(ar, "_ledger", report)

    for device in ("all", "not-configured"):
        with pytest.raises(ValueError):
            committee.skip_closing_check(device)
    assert json.loads(path.read_text())["devices"] == before and not reports
    assert {did: dev.calls for did, dev in fleet.targets.items()} == calls

    assert committee.skip_closing_check("ipad")["extra_app_check_skipped"]
    saved = json.loads(path.read_text())["devices"]
    assert saved[mdm.IPHONE] == before[mdm.IPHONE]
    ipad = saved[mdm.IPAD]
    window = before[mdm.IPAD]["window"]
    assert ipad["window"] is None and ipad["locked"]
    record, = ipad["closing_skips"]
    assert record == {"device_id": mdm.IPAD, "bundles": ["com.example.dict"], "snapshot": [f"com.existing.{mdm.IPAD}"],
                      "scan_requested_at": NOON,
                      "sent_at": unlock_at, "delivered_at": window["delivered_at"], "until": expiry,
                      "locked_at": expiry, "skipped_at": now}
    report_line, = reports
    assert "skipping the extra-app check" in report_line and json.loads(report_line.split("; ")[-1]) == record
    assert fleet.targets[mdm.IPHONE].calls == calls[mdm.IPHONE]
    assert fleet.targets[mdm.IPAD].calls == calls[mdm.IPAD] + [("lock",)]
    rows = store.audit_history(3)
    assert [row[1:5] for row in rows] == [
        ("committee", "skip-closing-check", mdm.IPAD, "applied"),
        ("committee", "skip-closing-check", mdm.IPAD, "skip-authorized"),
        ("committee", "skip-closing-check", mdm.IPAD, "attempted"),
    ]
    assert json.loads(rows[1][5]) == record

    with pytest.raises(ValueError, match="no install window"):
        committee.skip_closing_check("ipad")
    assert len(reports) == 1 and json.loads(path.read_text())["devices"] == saved


@pytest.mark.parametrize("failed_step, error", [
    ("lock", "failed lock"),
    ("ledger", "failed ledger"),
    ("missing ledger", "owner ledger unavailable"),
    ("committee audit", "failed committee audit"),
])
def test_skip_closing_check_keeps_record_on_failure(tmp_path, monkeypatch, failed_step, error):
    path, backend, expiry = _closing_window(tmp_path)
    assert ar.tick(path, backend, now=expiry + ar.READ_GRACE, report=lambda _: True)["status"] == "closing"
    original = path.read_text()
    store = Store(ar.config.db_path())
    committee = mcp_server.Committee(store, "agent", "tighten", clock=lambda: expiry + 24 * 3600,
                                     backend=backend, app_state=path)

    def fail(*_args, **_kwargs):
        raise RuntimeError("failed " + failed_step)

    if failed_step == "lock":
        monkeypatch.setattr(backend, "lock", fail)
    elif failed_step == "ledger":
        monkeypatch.setattr(ar, "_ledger", fail)
    elif failed_step == "missing ledger":
        monkeypatch.setattr(ar, "LEDGER", None)
    else:
        store._q("CREATE TRIGGER reject_skip BEFORE INSERT ON committee_audit "
                 "WHEN NEW.outcome='skip-authorized' BEGIN SELECT RAISE(ABORT, 'failed committee audit'); END")
    with pytest.raises(Exception, match=error):
        committee.skip_closing_check("7")
    assert path.read_text() == original
    expected = ["failed", "skip-authorized", "attempted"] if failed_step.endswith("ledger") else ["failed", "attempted"]
    assert [row[4] for row in store.audit_history()] == expected


def test_failed_closing_inventory_stays_queued_and_retries_after_grace(tmp_path):
    path, backend = _pending_window(tmp_path)
    reports = []
    expiry = ar.tick(path, backend, now=fresh_contact(backend, NOON), report=pytest.fail)["until"]
    assert ar.tick(path, backend, now=expiry, report=pytest.fail)["status"] == "closing"
    backend.installed.clear()  # An empty provider inventory is a read failure, never the end of the check.
    first_read = fresh_contact(backend, expiry)
    out = ar.tick(path, backend, now=first_read, report=pytest.fail)
    assert out["status"] == "closing" and "inventory unreadable" in out["reason"]
    deadline = expiry + ar.READ_GRACE
    for at in (deadline - 1, deadline, deadline + ar.SCAN_INTERVAL):
        assert ar.tick(path, backend, now=at, report=reports.append)["status"] == "closing"
        saved = ar._load(path, backend)
        assert saved["locked"] and saved["window"]["snapshot"] == ["com.existing"]
        assert not any(call[0] == "block" for call in backend.calls)
    assert len(reports) == 1 and "will retry" in reports[0]

    backend.installed.update({"com.existing", "com.extra"})
    out = ar.tick(path, backend, now=fresh_contact(backend, deadline + ar.SCAN_INTERVAL), report=reports.append)
    assert out["status"] == "locked" and out["blocked"] == ["com.extra"]
    assert ar._load(path, backend)["window"] is None


def test_failed_closing_scan_requires_contact_after_successful_retry(tmp_path, monkeypatch):
    path, backend = _pending_window(tmp_path)
    opened = ar.tick(path, backend, now=fresh_contact(backend, NOON), report=pytest.fail)
    expiry = opened["until"]
    real_scan = backend.scan

    def failed_scan():
        closing = ar._load(path, backend)["window"]["closing"]
        assert closing["locked_at"] == expiry and backend.calls[-1] == ("lock",)
        raise OSError("scan unavailable")

    monkeypatch.setattr(backend, "scan", failed_scan)
    out = ar.tick(path, backend, now=expiry, report=pytest.fail)
    assert out["status"] == "closing" and "scan failed" in out["reason"]
    monkeypatch.setattr(backend, "scan", real_scan)
    backend.installed.add("com.extra")
    assert ar.tick(path, backend, now=fresh_contact(backend, expiry), report=pytest.fail)["status"] == "closing"
    retry_at = expiry + ar.SCAN_INTERVAL
    assert ar.tick(path, backend, now=retry_at, report=pytest.fail)["status"] == "closing"
    out = ar.tick(path, backend, now=fresh_contact(backend, retry_at), report=lambda line: None)
    assert out["status"] == "locked" and out["blocked"] == ["com.extra"]


@pytest.mark.parametrize("failure", ["open", "flock"])
@pytest.mark.parametrize("device_lock_fails", [False, True])
def test_tick_state_lock_failure_still_locks_every_expired_device(tmp_path, monkeypatch, failure,
                                                                device_lock_fails):
    path, fleet = tmp_path / "s.json", Fleet()
    path.write_text(json.dumps({"devices": {
        did: {"history": [], "window": {"bundles": [], "snapshot": [], "until": NOON - 1}}
        for did in fleet.device_ids
    }}))
    original = path.read_text()
    lock_path, real_open = path.with_suffix(".json.lock"), type(path).open

    def failed_open(self, *args, **kwargs):
        if self == lock_path:
            raise PermissionError("state lock open failed")
        return real_open(self, *args, **kwargs)

    def failed_flock(*args):
        raise OSError("state flock failed")

    def failed_device_lock():
        fleet.targets[mdm.IPHONE].calls.append(("lock",))
        raise OSError("device lock failed")

    if failure == "open":
        monkeypatch.setattr(type(path), "open", failed_open)
    else:
        monkeypatch.setattr(fcntl, "flock", failed_flock)
    if device_lock_fails:
        monkeypatch.setattr(fleet.targets[mdm.IPHONE], "lock", failed_device_lock)

    out = ar.tick(path, fleet, now=NOON, report=pytest.fail, notify=pytest.fail)
    assert out["status"] == "error"
    assert all(result["status"] == "error" for result in out["devices"].values())
    assert all(device.calls == [("lock",)] for device in fleet.targets.values())
    assert path.read_text() == original  # retain expired windows for the next tick


@pytest.mark.parametrize("change", ["window", "denial"])
def test_slow_judge_allows_tick_and_rechecks_concurrent_state(tmp_path, monkeypatch, change):
    path, backend = _pending_window(tmp_path)
    judging, release = Event(), Event()
    peer_lines, lines = [], []
    at = NOON + ar.PENDING_MAX + 1

    def slow_judge(*args, **kwargs):
        judging.set()
        assert release.wait(5)
        return "approved", "AI approved"

    def concurrent_work():
        closed = ar.tick(path, backend, now=at, report=lambda line: None)
        assert closed["status"] == "locked"
        peer = app(trackName="Proxy Pro") if change == "denial" else app(bundleId="com.peer")
        return ar.request("123456789", path, backend, now=at, fetch=fetcher(peer), report=peer_lines.append)

    monkeypatch.setattr(ar.appjudge, "judge", slow_judge)
    with ThreadPoolExecutor(max_workers=2) as pool:
        requested = pool.submit(ar.request, "123456789", path, backend, now=at, ai_model="test",
                                fetch=fetcher(app(primaryGenreName="Games", genres=["Games"])),
                                report=lines.append)
        try:
            assert judging.wait(5)
            peer = pool.submit(concurrent_work).result(timeout=2)
            assert peer["status"] == ("denied" if change == "denial" else "approved")
        finally:
            release.set()
        out = requested.result(timeout=5)

    saved = json.loads(path.read_text())["devices"]["7"]
    assert len(saved["history"]) == 3
    if change == "denial":
        assert out["status"] == "denied" and "7 days" in out["reason"]
        assert saved["window"] is None and lines == []
    else:
        # no overlapping windows: the slower request goes to the committee instead of joining the peer's window
        assert out["status"] == "review" and "another install window" in out["reason"] and len(lines) == 1
        assert saved["window"]["bundles"] == ["com.peer"]
    assert not any(call[0] == "unlock" for call in backend.calls)


def test_read_outage_never_keeps_legacy_nightly_window_past_its_end(tmp_path):
    state, backend = tmp_path / "state.json", FakeMDM(["com.existing"])
    at = datetime(2026, 11, 16, 2, 5, tzinfo=ar.ISRAEL).timestamp()
    end = at + 25 * 60
    legacy_window(state, label="nightly updates", until=end, snapshot=[], sent_at=at, scan_at=at)

    def boom():
        raise RuntimeError("ManageEngine down")

    backend.devices = boom
    assert ar.tick(state, backend, lambda l: None, now=end - 60, notify=lambda m: None)["status"] == "pending_device"
    out = ar.tick(state, backend, lambda l: None, now=end, notify=lambda m: None)
    assert out["status"] == "locked" and ("lock",) in backend.calls


def test_read_outage_locks_legacy_request_window_at_expiry(tmp_path):
    state, backend = tmp_path / "state.json", FakeMDM(["com.existing"])
    legacy_window(state, until=NOON + 900, sent_at=NOON, scan_at=NOON)
    backend.devices = lambda: []
    out = ar.tick(state, backend, lambda l: None, now=NOON + 900, notify=lambda m: None)
    assert out["status"] == "locked" and ("lock",) in backend.calls


def test_read_outage_in_scan_phase_never_unlocks_and_expires_locked(tmp_path):
    state, backend = _pending_window(tmp_path)
    backend.devices = lambda: []
    for at in (NOON + 60, NOON + ar.PENDING_MAX - 1):
        assert ar.tick(state, backend, lambda l: None, now=at, notify=lambda m: None)["status"] == "pending_device"
    out = ar.tick(state, backend, lambda l: None, now=NOON + ar.PENDING_MAX, notify=lambda m: None)
    assert out["status"] == "locked" and ("lock",) in backend.calls
    assert not any(call[0] == "unlock" for call in backend.calls)
    assert json.loads(state.read_text())["devices"]["7"]["window"] is None


def test_contact_must_be_newer_than_the_scan_and_not_in_the_future(tmp_path):
    state, backend = _pending_window(tmp_path)
    for contact in (NOON, NOON - 1, NOON + 1, NOON + ar.CONTACT_MARGIN, NOON + 5000):
        backend.contact = contact
        out = ar.tick(state, backend, lambda l: None, now=NOON + ar.CONTACT_MARGIN, notify=pytest.fail)
        assert out["status"] == "pending_device"
    assert not any(call[0] == "unlock" for call in backend.calls)
    assert ar.tick(state, backend, report=pytest.fail, now=fresh_contact(backend, NOON))["status"] == "open"


def test_interrupted_scan_needs_a_fresh_contact_after_its_retry(tmp_path):
    path, backend = _pending_window(tmp_path)
    saved = ar._load(path, backend)
    saved["window"]["scan_confirmed_at"] = None
    ar._save(path, saved)
    backend.calls.clear()
    backend.contact = NOON + 1
    retry = NOON + ar.SCAN_INTERVAL
    assert ar.tick(path, backend, now=retry, report=pytest.fail)["status"] == "pending_device"
    assert backend.calls == [("scan",)]
    assert ar.tick(path, backend, now=retry + 1, report=pytest.fail)["status"] == "pending_device"
    assert ar.tick(path, backend, now=fresh_contact(backend, retry), report=pytest.fail)["status"] == "open"
    assert backend.calls == [("scan",), ("unlock", 15)]


@pytest.mark.parametrize("baseline", [None, "com.existing", [None]])
def test_tick_closes_window_with_untrusted_snapshot(tmp_path, baseline):
    state, backend = tmp_path / "s.json", FakeMDM(["com.a"])
    ar.request("123456789", state, backend, fetch=fetcher(app()), report=lambda l: None, now=NOON)
    assert ar.tick(state, backend, pytest.fail, now=fresh_contact(backend, NOON))["status"] == "open"
    data = json.loads(state.read_text())
    data["devices"]["7"]["window"]["snapshot"] = baseline
    state.write_text(json.dumps(data))
    backend.installed |= {"com.sneaky.game"}
    lines = []
    out = ar.tick(state, backend, lines.append, now=NOON + 10_000)
    assert out["status"] == "locked" and out["blocked"] == []
    assert ("lock",) in backend.calls and not any(c[0] == "block" for c in backend.calls)
    assert json.loads(state.read_text())["devices"]["7"]["window"] is None


def test_expired_window_without_unlock_timestamp_or_snapshot_still_closes(tmp_path):
    state, backend = tmp_path / "s.json", FakeMDM(["com.existing"])
    legacy_window(state, until=NOON, snapshot=None)
    reports = []
    out = ar.tick(state, backend, now=NOON, report=reports.append)
    assert out["status"] == "locked" and out["blocked"] == []
    assert backend.calls == [("lock",)] and len(reports) == 1


@pytest.mark.parametrize("baseline", [None, ["com.a"]])
def test_legacy_pending_window_never_refreshes_snapshot_or_blocks(tmp_path, baseline):
    state, backend = tmp_path / "s.json", FakeMDM(["com.a"])
    backend.contact = NOON - 3600
    legacy_window(state, bundles=["com.example.dict"], until=NOON + 900, snapshot=baseline, sent_at=NOON,
                  scan_at=NOON)
    backend.installed |= {"com.old.unseen"}
    backend.contact = NOON + 60
    assert ar.tick(state, backend, report=lambda l: None, now=NOON + 120, notify=lambda m: None)["status"] == "open"
    assert ar._load(state, backend)["window"]["snapshot"] == baseline
    backend.installed |= {"com.example.dict", "com.sneaky.new"}
    out = ar.tick(state, backend, report=lambda l: None, now=NOON + 60 + 901, notify=lambda m: None)
    assert out["status"] == "locked" and out["blocked"] == []  # no trusted baseline: never block extras
    assert ("lock",) in backend.calls


def test_stale_post_unlock_inventory_cannot_clear_the_window(tmp_path, monkeypatch):
    state, backend = _pending_window(tmp_path)
    opened = ar.tick(state, backend, now=fresh_contact(backend, NOON), report=pytest.fail)
    expiry = opened["until"]
    backend.installed.add("com.forbidden.after-unlock")
    backend.contact = expiry - 1
    inventory = backend.installed_apps
    assert inventory() == {"com.existing"}
    monkeypatch.setattr(backend, "installed_apps", lambda: pytest.fail("inventory read before fresh contact"))
    assert ar.tick(state, backend, now=expiry, report=pytest.fail)["status"] == "closing"
    assert backend.calls[-2:] == [("lock",), ("scan",)]
    saved = ar._load(state, backend)
    assert saved["locked"] and saved["window"]["closing"]["locked_at"] == expiry
    assert saved["window"]["snapshot"] == ["com.existing"]
    assert ar.status(state, backend)["status"] == "closing"
    for contact in (expiry - 1, expiry, expiry + ar.CONTACT_MARGIN):
        backend.contact = contact
        assert ar.tick(state, backend, now=expiry + ar.CONTACT_MARGIN, report=pytest.fail)["status"] == "closing"

    saved = ar._load(state, backend)
    reports = []
    request = ar.request("123456789", state, backend, fetch=fetcher(app(bundleId="com.other")),
                         report=reports.append, now=expiry + ar.CONTACT_MARGIN)
    assert request["status"] == "review" and "closing" in request["reason"]
    assert ar._load(state, backend)["window"] == saved["window"]
    monkeypatch.setattr(backend, "installed_apps", inventory)
    out = ar.tick(state, backend, now=fresh_contact(backend, expiry), report=reports.append)
    assert out["blocked"] == ["com.forbidden.after-unlock"]
    assert ar._load(state, backend)["window"] is None


def test_installed_approved_bundle_does_not_unlock(tmp_path):
    backend = FakeMDM(["COM.EXAMPLE.DICT"])
    out = ar.request("123456789", tmp_path / "installed.json", backend, fetch=fetcher(app()),
                     report=lambda line: None, now=NOON)
    assert out["status"] == "already_installed"
    assert backend.calls == []


def test_fresh_inventory_can_refuse_an_already_installed_app(tmp_path):
    path, backend = tmp_path / "installed.json", FakeMDM(["com.existing"])
    assert ar.request("123456789", path, backend, fetch=fetcher(app()), report=pytest.fail,
                      now=NOON)["status"] == "approved"
    backend.installed.add("com.example.dict")
    reports, messages = [], []
    out = ar.tick(path, backend, now=fresh_contact(backend, NOON), report=reports.append, notify=messages.append)
    assert out["status"] == "already_installed" and not out["delivered"]
    assert backend.calls == [("lock",), ("scan",), ("lock",)]
    assert ar.status(path, backend)["status"] == "idle"
    assert ar.tick(path, backend, now=backend.contact + 1, report=pytest.fail, notify=pytest.fail)["status"] == "idle"
    assert len(reports) == len(messages) == 1
    assert "Hebrew Dictionary already installed" in reports[0] and "כבר מותקן" in messages[0]


def test_fourth_install_window_in_24_hours_is_denied(tmp_path):
    path, backend = tmp_path / "limit.json", FakeMDM(["com.existing"])
    for offset in (0, 1100, 2200):
        out = ar.request("123456789", path, backend, fetch=fetcher(app()), report=lambda line: None,
                         now=NOON + offset)
        assert out["status"] == "approved"
        opened = ar.tick(path, backend, now=fresh_contact(backend, NOON + offset), report=pytest.fail)
        assert opened["status"] == "open"
        assert close_window(path, backend, opened["until"])["status"] == "locked"
    saved = ar._load(path, backend)
    saved["history"] = [{"status": "review", "t": NOON + 3000}] * 500
    ar._save(path, saved)
    out = ar.request("123456789", path, backend, fetch=fetcher(app()), report=lambda line: None,
                     now=NOON + 3600)
    assert out["status"] == "denied"
    assert "three install windows" in out["reason"]
    assert backend.calls.count(("scan",)) == 6
    other = app(bundleId="com.other")
    assert ar.request("123456789", path, backend, fetch=fetcher(other), report=pytest.fail,
                      now=NOON + 86400)["status"] == "approved"


@pytest.mark.parametrize("bundle,name", [("com.apple.TestFlight", "TestFlight"), ("com.dynamic", "Dynamic"),
                                          ("com.example.static", "Static")])
def test_night_rule_precedes_committee_and_testflight_allows(tmp_path, monkeypatch, bundle, name):
    monkeypatch.setitem(ar.COMMITTEE_APPROVED, "com.example.static", "test approval")
    from aifilter.store import Store

    monkeypatch.setattr(Store, "entity_verdict", lambda self, kind, key:
                        ("allow", "committee test") if key == "com.dynamic" else None)
    monkeypatch.setattr(ar.appjudge, "judge", lambda *args, **kwargs: pytest.fail("night review is mandatory"))
    three_am = datetime(2026, 11, 16, 3, 0, tzinfo=ZoneInfo("Asia/Jerusalem")).timestamp()
    approved = app(bundleId=bundle, trackName=name, primaryGenreName="Developer Tools", genres=["Developer Tools"])
    assert ar.decide(approved, NOON, [])[0] == "approved"
    backend, reports = FakeMDM(["com.existing"]), []
    out = ar.request("123456789", tmp_path / "night.json", backend, fetch=fetcher(approved),
                     report=reports.append, now=three_am, ai_model="test")
    assert out["status"] == "review" and "night request" in out["reason"]
    assert backend.calls == [] and len(reports) == 1


@pytest.mark.parametrize("phase", ["pending", "open"])
def test_request_cannot_join_or_extend_window(tmp_path, phase):
    path, backend = _pending_window(tmp_path)
    at = NOON
    if phase == "open":
        at = fresh_contact(backend, NOON)
        assert ar.tick(path, backend, now=at, report=pytest.fail)["status"] == "open"
    before = ar._load(path, backend)["window"]
    calls = backend.calls.copy()
    reports = []
    out = ar.request("123456789", path, backend, fetch=fetcher(app(bundleId="com.other")),
                     report=reports.append, now=at + 1)
    assert out["status"] == "review" and "another install window" in out["reason"]
    assert ar._load(path, backend)["window"] == before
    assert calls == backend.calls and len(reports) == 1


def test_old_approval_does_not_spare_app_in_another_window(tmp_path):
    path, backend = tmp_path / "old.json", FakeMDM(["com.existing"])
    ar.request("123456789", path, backend, fetch=fetcher(app()), report=lambda line: None, now=NOON)
    saved = json.loads(path.read_text())
    saved["devices"]["7"]["history"].insert(0, {
        "t": NOON - 30 * 86400, "bundle": "com.old.approval", "status": "approved"
    })
    path.write_text(json.dumps(saved))
    opened = ar.tick(path, backend, now=fresh_contact(backend, NOON), report=pytest.fail)
    backend.installed.add("com.old.approval")
    out = close_window(path, backend, opened["until"], lambda line: None)
    assert out["blocked"] == ["com.old.approval"]


def test_skip_refused_when_live_mdm_shows_contact_after_lock(tmp_path, monkeypatch):
    """Review P3: a contact no tick has recorded yet still blocks the skip."""
    path, backend, expiry = _closing_window(tmp_path)
    assert ar.tick(path, backend, now=expiry + ar.READ_GRACE, report=lambda _: True)["status"] == "closing"
    original = path.read_bytes()
    backend.contact = expiry + 3600  # the device checked in; no tick has seen it yet
    for method in ("installed_apps", "lock", "scan", "unlock", "block_app"):
        monkeypatch.setattr(backend, method, pytest.fail)
    monkeypatch.setattr(ar, "_ledger", pytest.fail)
    with pytest.raises(ValueError, match="contacted MDM since the lock"):
        ar._skip_closing_check(path, backend, lambda: expiry + 25 * 3600, pytest.fail)
    assert path.read_bytes() == original
