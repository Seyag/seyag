import json
import os
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
from mitmproxy.test import tflow

import addon
from aifilter.config import Config
from aifilter.schedules import SchedulePolicy, in_window, read_focus_file
from aifilter import ytgate
from aifilter.store import Store

TZ = ZoneInfo("Asia/Jerusalem")


def at(value):
    return datetime.fromisoformat(value).replace(tzinfo=TZ)


def focus(path: Path, blocks, mode=0o600):
    path.write_text(json.dumps({"blocks": blocks}), encoding="utf-8")
    path.chmod(mode)


def block(**changes):
    value = {"id": "one", "start": "2026-11-18T10:00:00+02:00",
             "end": "2026-11-18T12:00:00+02:00", "topic": "Example Project",
             "allow": ["work.example"], "confirmed_at": "2026-11-18T09:00:00+02:00"}
    value.update(changes)
    return value


def policy(tmp_path, raw=None):
    return SchedulePolicy(Config(raw or {"schedule": {"night": {"enabled": False}, "work": {"enabled": False}},
                                            "focus": {"enabled": True, "always_allow": [], "topics": {}}}),
                          focus_file=tmp_path / "focus.json", state_file=tmp_path / "state.json")


def test_window_boundaries_midnight_and_weekdays():
    assert in_window(at("2026-11-18T23:00"), "23:00", "06:00")
    assert in_window(at("2026-11-19T05:59:59"), "23:00", "06:00")
    assert not in_window(at("2026-11-19T06:00"), "23:00", "06:00")
    # Sunday through Thursday, with both endpoints half-open.
    weekdays = {6, 0, 1, 2, 3}
    assert in_window(at("2026-11-22T09:00"), "09:00", "17:00", weekdays)
    assert not in_window(at("2026-11-22T17:00"), "09:00", "17:00", weekdays)
    assert not in_window(at("2026-11-20T12:00"), "09:00", "17:00", weekdays)


def test_focus_file_rejects_bad_mode_malformed_and_overlong(tmp_path):
    path = tmp_path / "focus.json"
    focus(path, [block()], 0o644)
    assert read_focus_file(path) is None
    path.write_text("not json", encoding="utf-8")
    path.chmod(0o600)
    assert read_focus_file(path) is None
    focus(path, [block(allow=[f"h{i}.example" for i in range(51)])])
    assert read_focus_file(path) is None


def test_focus_file_rejects_wrong_owner(tmp_path, monkeypatch):
    path = tmp_path / "focus.json"
    focus(path, [block()])
    assert read_focus_file(path, owner=os.getuid() + 1) is None


def test_shortened_or_removed_active_block_cannot_loosen(tmp_path):
    item = policy(tmp_path)
    focus(item.focus_file, [block()])
    now = at("2026-11-18T11:00")
    assert "Example Project" in item.reason("other.example", now)
    focus(item.focus_file, [block(end="2026-11-18T11:01:00+02:00")])
    assert "12:00" in item.reason("other.example", at("2026-11-18T11:30"))
    focus(item.focus_file, [])
    assert "12:00" in item.reason("other.example", at("2026-11-18T11:45"))
    assert item.reason("other.example", at("2026-11-18T12:00")) is None


def test_night_essentials_pass_and_other_hosts_block(tmp_path):
    item = policy(tmp_path, {"focus": {"enabled": False}, "schedule": {
        "night": {"enabled": True, "start": "23:00", "end": "06:00"},
        "work": {"enabled": False}, "night_allow": ["apple.com", "whatsapp.net", "claude.ai"]}})
    for host in ("setup.apple.com", "mmg.whatsapp.net", "claude.ai"):
        assert item.reason(host, at("2026-11-18T23:00")) is None
    assert item.reason("example.com", at("2026-11-19T05:59")) == "מצב לילה עד 06:00"


def test_work_blocks_only_seeded_hosts(tmp_path):
    item = policy(tmp_path, {"focus": {"enabled": False}, "schedule": {
        "night": {"enabled": False}, "work": {"enabled": True, "start": "09:00", "end": "17:00"},
        "work_block": ["youtube.com", "ynet.co.il", "x.com"]}})
    assert item.reason("www.youtube.com", at("2026-11-18T09:00")) == "שעות עבודה עד 17:00"
    assert item.reason("example.com", at("2026-11-18T12:00")) is None


def test_work_exempt_devices_fail_closed(tmp_path):
    raw = {"focus": {"enabled": False}, "schedule": {
        "night": {"enabled": False, "start": "23:00", "end": "06:00"},
        "work": {"enabled": True, "start": "09:00", "end": "17:00"},
        "work_block": ["youtube.com"]}}
    item = policy(tmp_path, raw)
    work = at("2026-11-18T12:00")
    outside = at("2026-11-18T18:00")
    ipad, iphone = "192.0.2.10", "192.0.2.11"
    assert item.reason("youtube.com", work, client=ipad)  # default: everyone
    raw["schedule"]["work"]["exempt_devices"] = []
    assert item.reason("youtube.com", work, client=ipad)
    raw["schedule"]["work"]["exempt_devices"] = [ipad]
    assert item.reason("youtube.com", work, client=ipad) is None
    assert item.reason("youtube.com", work, client="::ffff:192.0.2.10") is None
    assert item.reason("youtube.com", work, client=iphone)
    assert item.reason("youtube.com", work, client="192.0.2.12")  # new/changed IP stays blocked
    assert item.reason("youtube.com", work)  # unidentified client stays blocked
    assert item.reason("youtube.com", work, client="not-an-ip")
    raw["schedule"]["work"]["exempt_devices"] = [ipad, "bad"]
    assert item.reason("youtube.com", work, client=ipad)  # a bad entry voids the list
    raw["schedule"]["work"]["exempt_devices"] = [ipad]
    assert item.reason("youtube.com", outside, client=iphone) is None
    assert item.reason("youtube.com", outside, client=ipad) is None
    raw["schedule"]["work"]["exempt_devices"] = ["fe80::1234%en0"]
    for scoped in ("fe80::1234%en0", "fe80::1234%en1", "fe80::1234"):
        assert item.reason("youtube.com", work, client=scoped)  # scoped addresses never exempt
    raw["schedule"]["work"]["exempt_devices"] = [ipad]
    assert item.reason("youtube.com", work, client="192.0.2.10%en0")


def _flow(url, client="26", user_agent="com.google.ios.youtubemusic/9.45.2"):
    value = tflow.tflow()
    value.request.url = url
    value.request.headers["x-youtube-client-name"] = client
    value.request.headers["user-agent"] = user_agent
    value.client_conn.sni = value.request.pretty_host
    value.server_conn.address = (value.request.pretty_host, 443)
    return value


def _work_filter(tmp_path, monkeypatch, *, allow_music, night=False):
    raw = {"focus": {"enabled": False}, "schedule": {
        "night": {"enabled": night, "start": "23:00", "end": "06:00"},
        "work": {"enabled": True, "start": "09:00", "end": "17:00", "allow_music": allow_music},
        "work_block": ["youtube.com", "youtubei.googleapis.com", "googlevideo.com", "ytimg.com"]}}
    gate = ytgate.Gate(channels_file=tmp_path / "channels.json", clock=lambda: 1_000)
    flt = addon.AIFilter(Config(raw), Store(tmp_path / "filter.db"), yt_gate=gate)
    real_reason = flt.schedules.reason
    fixed = at("2026-11-18T23:30" if night else "2026-11-18T12:00")
    monkeypatch.setattr(flt.schedules, "reason",
                        lambda host, **kwargs: real_reason(host, fixed, **kwargs))
    return flt


@pytest.mark.parametrize("allow_music,music_status", [(True, None), (False, 403)])
def test_work_music_exception_requires_music_client_and_authorized_stream(
        tmp_path, monkeypatch, allow_music, music_status):
    flt = _work_filter(tmp_path, monkeypatch, allow_music=allow_music)
    assert flt.yt.register_streams({"ei:musictok1"}, ytgate.MUSIC)
    flt.yt.music_enabled = True

    music = _flow("https://youtubei.googleapis.com/youtubei/v1/player?id=AAAAAAAAAAA")
    flt.request(music)
    assert (music.response.status_code if music.response else None) == music_status

    stream = _flow("https://r1.googlevideo.com/videoplayback?ei=musictok1")
    flt.request(stream)
    assert (stream.response.status_code if stream.response else None) == music_status

    regular = _flow("https://youtubei.googleapis.com/youtubei/v1/player?id=AAAAAAAAAAA",
                    client="5", user_agent="com.google.ios.youtube/21.45.4")
    flt.request(regular)
    assert regular.response.status_code == 403

    unapproved = _flow("https://r1.googlevideo.com/videoplayback?ei=unknown123")
    flt.request(unapproved)
    assert unapproved.response.status_code == 403


def test_work_music_exception_never_loosens_night(tmp_path, monkeypatch):
    flt = _work_filter(tmp_path, monkeypatch, allow_music=True, night=True)
    music = _flow("https://youtubei.googleapis.com/youtubei/v1/player?id=AAAAAAAAAAA")
    flt.request(music)
    assert music.response.status_code == 403


def test_night_music_only_for_music_client_when_enabled():
    from datetime import datetime
    from aifilter import schedules
    from aifilter.config import Config
    cfg = Config({"schedule": {"night_allow": [], "work_block": [], "night": {"enabled": True, "allow_music": True},
                               "work": {"enabled": False}}, "focus": {"enabled": False}})
    p = schedules.SchedulePolicy(cfg)
    night = datetime(2026, 11, 18, 23, 30, tzinfo=schedules.JERUSALEM)
    assert p.reason("youtubei.googleapis.com", night, allow_work_music=True) is None
    assert p.reason("youtubei.googleapis.com", night) is not None


def test_night_except_closes_icloud_web_shares_but_not_device_services():
    from datetime import datetime
    from aifilter import config, schedules
    cfg = config.load()
    cfg.raw.setdefault("focus", {})["enabled"] = False  # only the night rule is under test
    policy = schedules.SchedulePolicy(cfg)
    night = datetime(2026, 11, 19, 1, 0, tzinfo=schedules.JERUSALEM)
    for host in ("www.icloud.com", "share.icloud.com", "telesco.pe"):
        assert policy.reason(host, now=night), host
    for host in ("gsa.apple.com", "mdmenrollment.apple.com", "1-courier.push.apple.com",
                 "p25-ckdatabase.icloud.com", "cvws.icloud-content.com", "p23-sharedstreams.icloud.com"):
        assert policy.reason(host, now=night) is None, host
