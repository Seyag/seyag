import hashlib
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from aifilter import xgate

BASE = "https://video.twimg.com/amplify_video/123/"


def asset(body):
    return (hashlib.sha256(body).hexdigest(), body)


def test_canonical_url_keeps_query_and_drops_fragment():
    assert xgate.canonical_url(BASE + "a.mp4?tag=1#x") == BASE + "a.mp4?tag=1"
    assert xgate.canonical_url(BASE + "a.mp4?tag=2") != xgate.canonical_url(BASE + "a.mp4?tag=1")


def test_allowlist_is_exact_url_and_serves_checked_bytes():
    calls = []
    def check(url):
        calls.append(url)
        key = xgate.canonical_url(url)
        return True, [], {key: asset(b"checked mp4")}
    gate = xgate.Gate(checker=check)
    one, two = BASE + "a.mp4?format=1", BASE + "a.mp4?format=2"
    assert gate.allowed_sync(one) == (True, "checked", b"checked mp4", "123")
    assert gate.known(two) is None
    assert gate.allowed_sync(two)[0]
    assert calls == [one, two]


def test_unchecked_segment_and_range_target_fail_closed_without_check():
    gate = xgate.Gate(checker=lambda _url: (_ for _ in ()).throw(AssertionError()))
    assert gate.allowed_sync(BASE + "other.ts")[:3] == (False, "URL was not checked", None)


def test_pending_coalesces_same_url_not_same_media_id():
    entered = threading.Barrier(3)
    release = threading.Event()
    def check(url):
        entered.wait(); release.wait()
        return True, [], {xgate.canonical_url(url): asset(url.encode())}
    gate = xgate.Gate(checker=check, timeout=1)
    urls = [BASE + "a.mp4", BASE + "b.mp4"]
    out = []
    threads = [threading.Thread(target=lambda u=u: out.append(gate.allowed_sync(u))) for u in urls]
    for thread in threads: thread.start()
    entered.wait(); release.set()
    for thread in threads: thread.join()
    assert len(out) == 2
    assert len(gate._sync_pending) == 0


def test_hls_records_only_rewritten_master_chosen_variant_and_resources(tmp_path):
    master = b"#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=900\nhigh.m3u8\n#EXT-X-STREAM-INF:BANDWIDTH=100\nlow.m3u8\n"
    bodies = {
        BASE + "low.m3u8": b'#EXTM3U\n#EXT-X-MAP:URI="init.mp4"\nseg.ts\n',
        BASE + "init.mp4": b"init", BASE + "seg.ts": b"segment",
    }
    checker = xgate.VideoChecker(fetch=lambda url, _limit: bodies[url])
    checker._used = 0
    local, assets = checker._local_hls(BASE + "master.m3u8", master, tmp_path)
    assert set(assets) == {BASE + "master.m3u8", BASE + "low.m3u8", BASE + "init.mp4", BASE + "seg.ts"}
    assert b"low.m3u8" in assets[BASE + "master.m3u8"]
    assert b"high.m3u8" not in assets[BASE + "master.m3u8"]
    assert local.read_text().startswith("#EXTM3U")


def test_uniform_samples_plus_reverse_last_frame(monkeypatch):
    commands = []
    checker = xgate.VideoChecker(reviewer=SimpleNamespace(review=lambda _b: (False, [])), fetch=lambda _u, _l: b"video")
    def run(command, **_kwargs):
        commands.append(command)
        if command[0] == "ffprobe": return SimpleNamespace(stdout="4\n")
        Path(command[-1]).write_bytes(b"frame")
        return SimpleNamespace(stdout=None)
    checker._run = run
    assert checker.check(BASE + "a.mp4")[0]
    frame_commands = [c for c in commands if c[0] == "ffmpeg"]
    assert len(frame_commands) == 3  # two uniform samples plus final frame
    assert "-sseof" in frame_commands[-1] and "reverse" in frame_commands[-1]


def test_final_frame_extraction_failure_fails_check():
    checker = xgate.VideoChecker(reviewer=SimpleNamespace(review=lambda _b: (False, [])), fetch=lambda _u, _l: b"video")
    count = 0
    def run(command, **_kwargs):
        nonlocal count
        if command[0] == "ffprobe": return SimpleNamespace(stdout="1\n")
        count += 1
        if count == 1: Path(command[-1]).write_bytes(b"uniform")
        return SimpleNamespace(stdout=None)
    checker._run = run
    try: checker.check(BASE + "a.mp4")
    except ValueError as exc: assert "final frame" in str(exc)
    else: raise AssertionError("missing final frame was accepted")


def test_close_terminates_and_reaps_tracked_process():
    class Process:
        def __init__(self): self.terminated = self.waited = False
        def poll(self): return None if not self.terminated else -15
        def terminate(self): self.terminated = True
        def wait(self, timeout=None): self.waited = True; return -15
    checker, process = xgate.VideoChecker(), Process()
    checker._processes.add(process)
    started = time.monotonic(); checker.close()
    assert process.terminated and process.waited
    assert time.monotonic() - started < 2


def test_cache_has_a_byte_budget_and_rejects_oversized_graphs(monkeypatch):
    from aifilter import xgate
    monkeypatch.setattr(xgate, "MAX_CACHE_BYTES", 400)
    gate = xgate.Gate(checker=lambda url: (True, [], {}))
    for i in range(10):
        gate._save((True, [], {f"https://video.twimg.com/tweet_video/{i}/a.mp4": ("d", b"x" * 90)}))
    assert gate._bytes <= 400 and len(gate.verdicts) == 4
    assert gate._save((True, [], {"https://video.twimg.com/tweet_video/99/a.mp4": ("d", b"x" * 101)})) == (
        False, "too large to keep checked bytes")
    gate.close()


def test_download_budget_is_per_thread():
    import threading
    from aifilter import xgate
    checker = xgate.VideoChecker(fetch=lambda url, limit: b"y" * 10)
    checker._local.used = 0
    seen = []
    t = threading.Thread(target=lambda: seen.append(getattr(checker._local, "used", None)))
    t.start(); t.join()
    assert seen == [None]
