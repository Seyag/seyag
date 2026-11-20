"""Shorts prefetch, its spend guard, check timing and the warm-up diagnostics (2026-11-19, "YouTube is very slow").

Prefetch only moves a completed check earlier. It never allows anything a real check would not, never keeps a
failed check, never delays a real check, and stops at its own per-answer, per-minute and daily limits.
"""
import asyncio
import json

import pytest
from mitmproxy import http

from aifilter import workers, ytcheck, ytprefetch
from test_ytcheck import CH, OTHER, VID, _addon, _field, _player_flow, _youtube_api_flow, fake_get, player_json, sheet_bytes
from test_youtube_smooth import WARMUP, free, start, upstream  # noqa: F401
from test_filter import store  # noqa: F401

IDS = ["aaaaaaaaaa1", "bbbbbbbbbb2", "ccccccccccc", "ddddddddd-4", "eeeeeeeee_5"]


def _sequence_json(ids):
    return json.dumps({"entries": [{"command": {"reelWatchEndpoint": {"videoId": v, "params": "x"}}} for v in ids],
                       "continuationEndpoint": {"continuationCommand": {"token": "t"}}}).encode()


class _Gate:
    """A worker pool whose answers the test releases one by one."""

    def __init__(self, answer=("ok", []), wait=False):
        self.answer, self.calls, self.requests = answer, 0, []
        self.release = asyncio.Event() if wait else None

    async def review(self, data, timeout):
        self.calls += 1
        self.requests.append(json.loads(data))
        if self.release is not None:
            await self.release.wait()
        answer = self.answer(json.loads(data)) if callable(self.answer) else self.answer
        return answer[0], list(answer[1])


def _cfg(**over):
    values = {"ai_check": True, "ai_model": "m", "prefetch": True, "prefetch_daily_max": 150, **over}
    return type("C", (), {"get": lambda self, sec, key, default=None: values.get(key, default)})()


def _prefetch_addon(tmp_path, main=("ok", ["main"]), pre=None, **cfg):
    a = _addon(tmp_path, "ok")
    a.cfg = _cfg(**cfg)
    a._yt_pool = _Gate(main)
    a._yt_prefetch_pool = pre or _Gate(lambda req: ("ok", [f"@channel={CH}", "@t=player:0.1,total:4.2", "model allow: men"]))
    return a


async def _settle(owner=None):
    """Let queued prefetch work run: until the drain task (which also reads/writes the budget file in a thread)
    is idle or blocked on a test gate."""
    for _ in range(20):
        await asyncio.sleep(0)
    p = getattr(owner, "_yt_prefetcher", owner) if owner is not None else None
    for _ in range(200):
        task = getattr(p, "_task", None)
        if task is None or task.done() or getattr(p, "_inflight", None):
            break
        await asyncio.sleep(0.01)
    for _ in range(20):
        await asyncio.sleep(0)


# Parsing --------------------------------------------------------------------------------------------------------

def test_sequence_json_lists_upcoming_ids_in_order_without_repeats():
    body = _sequence_json(IDS[:3] + IDS[:1])
    assert ytprefetch.upcoming_videos(body, ytprefetch.SEQUENCE_PATH) == IDS[:3]
    # Only Shorts endpoints count in a sequence: a loose videoId elsewhere is ignored.
    loose = json.dumps({"videoId": IDS[0], "x": {"watchEndpoint": {"videoId": IDS[1]}}}).encode()
    assert ytprefetch.upcoming_videos(loose, ytprefetch.SEQUENCE_PATH) == []


def test_next_json_reads_watch_endpoints_but_protobuf_next_is_not_read():
    body = json.dumps({"contents": [{"watchEndpoint": {"videoId": IDS[0]}},
                                    {"reelWatchEndpoint": {"videoId": IDS[1]}}]}).encode()
    assert ytprefetch.upcoming_videos(body, ytprefetch.NEXT_PATH + "?prettyPrint=false") == IDS[:2]
    proto = _field(1, _field(2, IDS[0].encode()))
    assert ytprefetch.upcoming_videos(proto, ytprefetch.NEXT_PATH) == []


def test_sequence_protobuf_reads_nested_id_fields():
    entry = lambda v: _field(1, _field(5, _field(1, v.encode()) + _field(3, b"params-that-are-longer")))
    body = b"".join(entry(v) for v in IDS[:4]) + _field(9, b"short")
    assert ytprefetch.upcoming_videos(body, ytprefetch.SEQUENCE_PATH) == IDS[:4]


@pytest.mark.parametrize("body", [
    b"", b"\xff\xff\xff", b"not json {", b"[]", b"null", b'{"entries": 5}', b'{"entries":[{"reelWatchEndpoint":{"videoId":7}}]}',
    b'{"entries":[{"reelWatchEndpoint":{"videoId":"../../etc/pa"}}]}', b'{"entries":[{"reelWatchEndpoint":{"videoId":"short"}}]}',
    b"[" * 5000 + b"]" * 5000, b"\x0a\xff\xff\xff\x0f" + b"x" * 20, b"x" * (3_000_001),
])
def test_junk_answers_give_no_ids(body):
    assert ytprefetch.upcoming_videos(body, ytprefetch.SEQUENCE_PATH) == []


def test_other_paths_are_never_read():
    assert ytprefetch.upcoming_videos(_sequence_json(IDS), "/youtubei/v1/player") == []
    assert ytprefetch.upcoming_videos(_sequence_json(IDS), "/youtubei/v1/reel/reel_item_watch") == []


def test_candidates_are_bounded():
    many = [f"{i:011d}" for i in range(40)]
    assert len(ytprefetch.upcoming_videos(_sequence_json(many), ytprefetch.SEQUENCE_PATH)) == ytprefetch.MAX_CANDIDATES


# Limits ---------------------------------------------------------------------------------------------------------

class _Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def _prefetcher(tmp_path, run=None, skip=lambda v: False, **kw):
    events = []

    async def default_run(video):
        return "ok", []
    p = ytprefetch.Prefetcher(run or default_run, skip, lambda k, d: events.append((k, d)),
                              budget_file=tmp_path / "budget.json", **kw)
    return p, events


def test_caps_per_answer_per_minute_and_pending(tmp_path):
    clock = _Clock()

    async def go():
        gate = asyncio.Event()

        async def run(video):
            await gate.wait()
            return "ok", []
        p, _ = _prefetcher(tmp_path, run, clock=clock)
        assert p.offer(IDS) == IDS[:3]  # 3 per answer
        assert p.offer(IDS) == IDS[3:5]  # already queued ones are skipped
        many = [f"{i:011d}" for i in range(12)]
        assert p.offer(many) == many[:1]  # 6 waiting at most
        await _settle(p)
        clock.now += 1
        gate.set()
        await _settle(p)
        assert p.offer(many[1:]) == many[1:4]
        assert p.offer(many[4:]) == many[4:5]  # 10 per minute
        assert p.offer(many[5:]) == []
        await _settle(p)  # the four queued ones ran
        clock.now += 61
        assert p.offer(many[5:]) == many[5:8]
        p._pending.clear()
    asyncio.run(go())


def test_known_videos_are_not_prefetched(tmp_path):
    async def go():
        p, _ = _prefetcher(tmp_path, skip=lambda v: v == IDS[0])
        assert p.offer(IDS[:2]) == IDS[1:2]
    asyncio.run(go())


def test_daily_cap_stops_prefetch_for_the_day_and_survives_a_restart(tmp_path):
    clock = _Clock()
    ran = []

    async def run(video):
        ran.append(video)
        return "ok", []

    async def go():
        p, events = _prefetcher(tmp_path, run, clock=clock, daily_max=2)
        p.offer(IDS[:3])
        await _settle(p)
        assert ran == IDS[:2]  # the third was dropped when the cap was reached
        assert p.offer(IDS[3:]) == [] and p.stopped() == "daily cap"
        assert p.offer(IDS[3:]) == []
        assert [e for e in events if e[0] == "yt-prefetch-capped"] and len(
            [e for e in events if e[0] == "yt-prefetch-capped"]) == 1
        p._save()
        q, _ = _prefetcher(tmp_path, run, clock=clock, daily_max=2)  # a filter restart keeps today's count
        q.offer(IDS[3:4])
        await _settle(q)
        assert ran == IDS[:2] and q.used == 2
        clock.now += 86400  # the next day starts fresh
        assert q.offer(IDS[4:5]) == IDS[4:5]
        await _settle(q)
        assert ran == IDS[:2] + IDS[4:5]
    asyncio.run(go())


def test_billing_error_pauses_prefetch_for_an_hour_with_one_event(tmp_path):
    clock = _Clock()
    ran = []

    async def run(video):
        ran.append(video)
        return "error", [ytprefetch.BILLING_LABEL]

    async def go():
        p, events = _prefetcher(tmp_path, run, clock=clock)
        p.offer(IDS[:3])
        await _settle(p)
        assert ran == IDS[:1]  # the queue is dropped at the first billing error
        assert p.stopped() == "paused" and p.offer(IDS[3:]) == []
        p.pause("again")  # still paused: no second event
        assert len([e for e in events if e[0] == "yt-prefetch-paused"]) == 1
        clock.now += ytprefetch.PAUSE_SECONDS + 1
        assert p.offer(IDS[3:4]) == IDS[3:4]
    asyncio.run(go())


def test_ytcheck_maps_402_and_credit_balance_to_billing_error():
    class Err(Exception):
        status_code = 402

    for exc in (Err("payment required"), RuntimeError("Your credit_balance is too low"), ValueError("credit balance low")):
        def ask(model, jpeg, details, exc=exc):
            raise exc
        r = ytcheck.VideoReviewer(get=fake_get(player_json(captions=False), sheet_bytes()), detect=lambda img: [],
                                  terms={}, model="m", ask=ask)
        with pytest.raises(ytcheck.BillingError):
            r.review(json.dumps({"video": VID, "channel": CH}).encode())

    def other(model, jpeg, details):
        raise RuntimeError("overloaded")
    r = ytcheck.VideoReviewer(get=fake_get(player_json(captions=False), sheet_bytes()), detect=lambda img: [],
                              terms={}, model="m", ask=other)
    with pytest.raises(RuntimeError) as info:
        r.review(json.dumps({"video": VID, "channel": CH}).encode())
    assert not isinstance(info.value, ytcheck.BillingError)


def test_worker_pool_reports_billing_error_by_name():
    from worker_fixtures import BillingReviewer

    assert ytcheck.BillingError.__name__ == ytprefetch.BILLING_LABEL

    async def go():
        pool = workers.ReviewPool(1, {}, factory=BillingReviewer)
        try:
            return await pool.review(b"{}", 60)
        finally:
            pool.close()
    assert asyncio.run(go()) == ("error", [ytprefetch.BILLING_LABEL])


# The worker ------------------------------------------------------------------------------------------------------

def test_prefetch_mode_reports_the_channel_it_read_and_stage_times():
    ok = lambda model, jpeg, details: {"verdict": "allow", "reason": "men"}
    r = ytcheck.VideoReviewer(get=fake_get(player_json(captions=False), sheet_bytes()), detect=lambda img: [],
                              terms={}, model="m", ask=ok)
    bad, labels = r.review(json.dumps({"video": VID, "channel": "", "prefetch": True, "meta": True}).encode())
    assert not bad and labels[0] == f"@channel={CH}" and labels[1].startswith("@t=player:")
    assert "model:" in labels[1] and labels[1].split(",")[-1].startswith("total:")
    # Without the meta flag the answer is exactly as before.
    assert r.review(json.dumps({"video": VID, "channel": CH}).encode()) == (False, ["no transcript", "model allow: men"])


def test_a_channel_less_request_needs_the_prefetch_flag():
    r = ytcheck.VideoReviewer(get=fake_get(player_json(), sheet_bytes()), detect=lambda img: [], terms={})
    assert r.review(json.dumps({"video": VID, "channel": ""}).encode()) == (True, ["bad request"])
    assert r.review(json.dumps({"video": VID, "channel": "", "prefetch": "yes"}).encode()) == (True, ["bad request"])


def test_prefetch_mode_without_a_readable_channel_reports_none():
    p = player_json(channel="not-a-channel")
    r = ytcheck.VideoReviewer(get=fake_get(p, sheet_bytes()), detect=lambda img: [], terms={})
    bad, labels = r.review(json.dumps({"video": VID, "channel": "", "prefetch": True, "meta": True}).encode())
    assert bad and not any(label.startswith("@channel") for label in labels)


# The addon -------------------------------------------------------------------------------------------------------

def _sequence_flow(ids, ua="com.google.ios.youtube/21.46.3 (iPhone16,2; U; CPU iOS 26_1 like Mac OS X;)"):
    p = _youtube_api_flow(_sequence_json(ids), ytprefetch.SEQUENCE_PATH)
    p.request.headers["user-agent"] = ua
    p.request.headers["x-youtube-client-name"] = "5"
    return p


def test_a_prefetched_verdict_lets_the_swipe_play_without_a_new_check(tmp_path):
    a = _prefetch_addon(tmp_path)

    async def go():
        a._yt_prefetch_from(_sequence_flow([VID, IDS[0]]))
        await _settle(a)
        assert [r["video"] for r in a._yt_prefetch_pool.requests] == [VID, IDS[0]]
        assert all(r["channel"] == "" and r["prefetch"] is True for r in a._yt_prefetch_pool.requests)
        p = _player_flow("prefetched1")
        await a._review_youtube_player(p)
        return p
    p = asyncio.run(go())
    assert p.response.status_code == 200 and a._yt_pool.calls == 0
    assert "(prefetched)" in a._store.rows[-1][2]
    assert a.yt.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=prefetched1&id=o-AB")


def test_a_prefetched_verdict_for_another_channel_is_never_used(tmp_path):
    pre = _Gate(lambda req: ("ok", [f"@channel={OTHER}", "model allow"]))
    a = _prefetch_addon(tmp_path, main=("bad", ["model block"]), pre=pre)

    async def go():
        a._yt_prefetch_from(_sequence_flow([VID]))
        await _settle(a)
        p = _player_flow("otherchan1")
        await a._review_youtube_player(p)
        return p
    p = asyncio.run(go())
    assert p.response.status_code == 403 and a._yt_pool.calls == 1


@pytest.mark.parametrize("answer", [
    ("error", ["RuntimeError"]), ("timeout", ["timeout"]), ("invalid", []), ("busy", ["queue"]),
    ("ok", ["model allow"]),  # completed but no channel label: not kept
    ("ok", ["@channel=UCbad", "model allow"]),
    ("ok", ["model allow", f"@channel={CH}"]),  # a label after the reasons is a reason, never meta
])
def test_a_failed_or_unattributed_prefetch_keeps_no_verdict(tmp_path, answer):
    a = _prefetch_addon(tmp_path, main=("bad", ["model block"]), pre=_Gate(answer))

    async def go():
        a._yt_prefetch_from(_sequence_flow([VID]))
        await _settle(a)
        assert not a.__dict__.get("_yt_verdicts")
        p = _player_flow("failed0001")
        await a._review_youtube_player(p)
        return p
    p = asyncio.run(go())
    assert p.response.status_code == 403 and a._yt_pool.calls == 1  # the real check decided


def test_a_prefetch_that_never_finishes_never_delays_a_real_check(tmp_path):
    pre = _Gate(wait=True)  # the prefetch worker is stuck
    a = _prefetch_addon(tmp_path, pre=pre)

    async def go():
        a._yt_prefetch_from(_sequence_flow([VID, IDS[0]]))
        await _settle(a)
        assert pre.calls == 1 and a._yt_prefetcher.inflight(VID) is not None
        p = _player_flow("realfirst1")
        await asyncio.wait_for(a._review_youtube_player(p), 2)  # the same video, while its prefetch runs
        q_ok, _ = await asyncio.wait_for(a._yt_ai_check(IDS[0], CH), 2)  # a queued one is dropped, checked now
        assert IDS[0] not in a._yt_prefetcher._pending
        pre.release.set()
        await _settle(a)
        return p, q_ok
    p, q_ok = asyncio.run(go())
    assert p.response.status_code == 200 and q_ok and a._yt_pool.calls == 2


def test_a_running_prefetch_that_finishes_first_decides_for_the_same_channel(tmp_path):
    pre = _Gate(lambda req: ("ok", [f"@channel={CH}", "model allow"]), wait=True)
    a = _prefetch_addon(tmp_path, pre=pre)
    a._yt_pool = _Gate(("ok", ["main"]), wait=True)  # the real worker is slower this time

    async def go():
        a._yt_prefetch_from(_sequence_flow([VID]))
        await _settle(a)
        task = asyncio.ensure_future(a._yt_ai_check(VID, CH))
        await _settle(a)
        pre.release.set()
        result = await asyncio.wait_for(task, 2)
        a._yt_pool.release.set()  # the real check still completes in the background
        await _settle(a)
        return result
    ok, reason = asyncio.run(go())
    assert ok and "(prefetched)" in reason


def test_prefetch_respects_config_music_app_and_source(tmp_path):
    async def go(a, flow):
        a._yt_prefetch_from(flow)
        await _settle(a)
        return a._yt_prefetch_pool.calls
    assert asyncio.run(go(_prefetch_addon(tmp_path, prefetch=False), _sequence_flow([VID]))) == 0
    assert asyncio.run(go(_prefetch_addon(tmp_path, ai_model=""), _sequence_flow([VID]))) == 0
    music = _sequence_flow([VID], ua="com.google.ios.youtubemusic/8.0")
    music.request.headers["x-youtube-client-name"] = "26"
    assert asyncio.run(go(_prefetch_addon(tmp_path), music)) == 0
    spoof = _sequence_flow([VID])
    spoof.client_conn.sni = "evil.example"
    assert asyncio.run(go(_prefetch_addon(tmp_path), spoof)) == 0
    failed = _sequence_flow([VID])
    failed.response = http.Response.make(500, _sequence_json([VID]), {})
    assert asyncio.run(go(_prefetch_addon(tmp_path), failed)) == 0


def test_billing_error_on_a_prefetch_pauses_prefetch_but_not_real_checks(tmp_path):
    a = _prefetch_addon(tmp_path, pre=_Gate(("error", [ytprefetch.BILLING_LABEL])))

    async def go():
        a._yt_prefetch_from(_sequence_flow(IDS[:3]))
        await _settle(a)
        a._yt_prefetch_from(_sequence_flow(IDS[3:]))
        await _settle(a)
        assert a._yt_prefetch_pool.calls == 1
        return await a._yt_ai_check(IDS[4], CH)
    ok, _ = asyncio.run(go())
    assert ok and a._yt_pool.calls == 1
    assert len([r for r in a._store.rows if r[0] == "yt-prefetch-paused"]) == 1


def test_billing_error_on_a_real_check_pauses_prefetch(tmp_path):
    a = _prefetch_addon(tmp_path, main=("error", [ytprefetch.BILLING_LABEL]))

    async def go():
        a._yt_prefetch_from(_sequence_flow([]))  # creates the prefetcher; nothing to queue
        ok, _ = await a._yt_ai_check(VID, CH)
        assert not ok
        a._yt_prefetch_from(_sequence_flow(IDS[:2]))
        await _settle(a)
    asyncio.run(go())
    assert a._yt_prefetch_pool.calls == 0 and a._yt_prefetcher.stopped() == "paused"


def test_check_times_are_logged_without_changing_the_kept_reason(tmp_path):
    a = _prefetch_addon(tmp_path, main=("ok", ["@t=player:0.3,words:0.5,total:4.9", "transcript", "model allow"]))
    ok, reason = asyncio.run(a._yt_ai_check(VID, CH))
    assert ok and reason == "transcript, model allow"
    assert ("yt-check-time", "youtubei.googleapis.com", f"video={VID} check player:0.3,words:0.5,total:4.9") in a._store.rows


# Warm-up diagnostics --------------------------------------------------------------------------------------------

def test_a_warmup_that_misses_the_local_answer_records_why_once(free, store):
    cfa = "YouTube/21.46.3 CFNetwork/3860.100.1 Darwin/26.1.0"
    flow = start(free, WARMUP, ua=cfa, headers={"cookie": "SID=secret"})
    assert flow.response is None  # unchanged: still goes upstream and is refused there
    assert upstream(free, flow).status_code == 403
    rows = [e for e in store.events() if e[1] == "yt-warmup-miss"]
    assert len(rows) == 1
    detail = json.loads(rows[0][3])
    assert detail["failed"] == ["client"] and detail["ua"] == cfa[:48] and detail["client"] == ""
    assert "secret" not in rows[0][3] and "cookie" not in rows[0][3]
    start(free, WARMUP, ua=cfa)  # rate limited
    assert len([e for e in store.events() if e[1] == "yt-warmup-miss"]) == 1


def test_a_matching_warmup_records_nothing(free, store):
    assert start(free, WARMUP).response.status_code == 204
    assert not [e for e in store.events() if e[1] == "yt-warmup-miss"]


def test_other_requests_never_record_a_warmup_miss(free, store):
    start(free, WARMUP.replace("0000000000001f13", "28ba4258d8867abc"), ua="YouTube/1 CFNetwork/1")
    assert not [e for e in store.events() if e[1] == "yt-warmup-miss"]


def test_corrupt_budget_state_keeps_prefetch_off(tmp_path):
    """Review P2 (#57): unreadable spend state is never read as zero spent."""
    f = tmp_path / "budget.json"
    f.write_text("{not json", encoding="utf-8")
    events = []
    p = ytprefetch.Prefetcher(lambda v: None, lambda v: False, lambda k, d: events.append(k), budget_file=f)
    p._load()
    assert p.stopped() == "budget state"
    assert "yt-prefetch-paused" in events


def test_missing_budget_file_starts_fresh(tmp_path):
    p = ytprefetch.Prefetcher(lambda v: None, lambda v: False, lambda k, d: None, budget_file=tmp_path / "none.json")
    p._load()
    assert p.stopped() == "" and p.used == 0


def test_clock_moved_back_never_refills_the_allowance(tmp_path):
    now = [1_800_000_000.0]
    p = ytprefetch.Prefetcher(lambda v: None, lambda v: False, lambda k, d: None, daily_max=2, clock=lambda: now[0],
                              budget_file=None)
    p.used = 2
    assert p.stopped() == "daily cap"
    now[0] -= 86400 * 2  # back two days
    assert p.stopped() == "daily cap"
    now[0] += 86400 * 3  # a real new day
    assert p.stopped() == ""


def test_later_day_on_disk_is_kept_when_clock_is_behind(tmp_path):
    f = tmp_path / "budget.json"
    f.write_text('{"day": "2999-01-01", "used": 150, "paused_until": 0}', encoding="utf-8")
    p = ytprefetch.Prefetcher(lambda v: None, lambda v: False, lambda k, d: None, budget_file=f)
    p._load()
    assert p.stopped() == "daily cap"


def test_unwritable_budget_stops_before_a_paid_check(tmp_path):
    import asyncio
    ran = []

    async def run(video):
        ran.append(video)
        return "ok", []

    p = ytprefetch.Prefetcher(run, lambda v: False, lambda k, d: None, budget_file=tmp_path / "missing-dir" / "b.json")

    async def go():
        p.offer(["aaaaaaaaaaa"])
        await p._task

    asyncio.run(go())
    assert ran == [] and p.stopped() == "budget state"


def test_directory_sync_failure_stops_before_a_paid_check(tmp_path, monkeypatch):
    """Re-review P2: a failed post-rename directory fsync must disable prefetch before the paid call."""
    import asyncio
    import os as _os
    ran = []

    async def run(video):
        ran.append(video)
        return "ok", []

    real_fsync, calls = _os.fsync, []

    def flaky_fsync(fd):
        calls.append(fd)
        if len(calls) == 2:  # 1st = temp file, 2nd = parent directory
            raise OSError("dir fsync failed")
        return real_fsync(fd)

    monkeypatch.setattr(ytprefetch.os, "fsync", flaky_fsync)
    p = ytprefetch.Prefetcher(run, lambda v: False, lambda k, d: None, budget_file=tmp_path / "b.json")

    async def go():
        p.offer(["aaaaaaaaaaa"])
        await p._task

    asyncio.run(go())
    assert ran == [] and p.stopped() == "budget state"
