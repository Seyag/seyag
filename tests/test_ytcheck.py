import asyncio
import io
import json
import sys
from pathlib import Path

import pytest
from mitmproxy import http
from mitmproxy.test import tflow
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aifilter import ytcheck, ytgate  # noqa: E402

VID, CH, OTHER = "mIlix_3dKsk", "UCulYu1HEIa7f70L2lYZWHOw", "UCYONKpA1KLr3GA2nKt0jZgg"
SPEC = "https://i.ytimg.com/sb/mIlix_3dKsk/storyboard3_L$L/$N.jpg?sqp=abc|48#27#100#10#10#0#default#rs$x|20#10#6#2#2#2000#M$M#sig1"


def fake_get(player, sheet, transcript=None):
    calls = []

    def get(url, limit, data=None, headers=None):
        calls.append(url)
        if url == ytcheck.PLAYER_URL:
            return json.dumps(player).encode()
        if url.startswith("https://i.ytimg.com/sb/") or url.startswith("https://i.ytimg.com/vi/"):
            return sheet
        if "timedtext" in url and transcript is not None:
            return json.dumps({"events": [{"segs": [{"utf8": transcript}]}]}).encode()
        raise OSError("unexpected " + url)
    get.calls = calls
    return get


def sheet_bytes():
    buf = io.BytesIO()
    Image.new("RGB", (40, 20), "white").save(buf, "JPEG")
    return buf.getvalue()


def player_json(channel=CH, status="OK", title="שיעור על בינה מלאכותית", captions=True, spec=SPEC):
    p = {"playabilityStatus": {"status": status},
         "videoDetails": {"videoId": VID, "channelId": channel, "title": title, "shortDescription": "", "keywords": []},
         "storyboards": {"playerStoryboardSpecRenderer": {"spec": spec}}}
    if captions:
        p["captions"] = {"playerCaptionsTracklistRenderer": {"captionTracks": [
            {"baseUrl": "https://www.youtube.com/api/timedtext?v=mIlix_3dKsk&lang=iw", "languageCode": "iw"}]}}
    return p


def test_judge_rules():
    assert ytcheck.judge([], faces=True) == (True, ["no frames"])
    woman = [[("FACE_FEMALE", 0.8)]] * 26 + [[]] * 4
    assert ytcheck.judge(woman, faces=True)[0]
    assert not ytcheck.judge(woman, faces=False)[0]
    men_misread = [[("FACE_FEMALE", 0.7)]] * 7 + [[("FACE_MALE", 0.9)]] * 44
    assert not ytcheck.judge(men_misread, faces=True)[0]
    assert ytcheck.judge([[("FEMALE_BREAST_EXPOSED", 0.5)]] + [[]] * 39, faces=False)[0]
    assert not ytcheck.judge([[("BELLY_EXPOSED", 0.6)]] + [[]] * 39, faces=False)[0]  # one frame: noise
    assert ytcheck.judge([[("BELLY_EXPOSED", 0.6)]] * 2 + [[]] * 38, faces=False)[0]


def test_large_stills_catch_dress_in_one_still():
    assert ytcheck.judge_stills([[("FEMALE_GENITALIA_COVERED", 0.56)], [], []]) == ["still FEMALE_GENITALIA_COVERED x1".replace(" x", "x")]
    assert ytcheck.judge_stills([[("FEET_COVERED", 0.9), ("FACE_FEMALE", 0.9)], [], []]) == []


def test_reviewer_blocks_on_a_large_still():
    def detect(img):
        return [("FEMALE_BREAST_COVERED", 0.6)] if img.shape[1] > 100 else []  # only the large still shows it
    big = io.BytesIO()
    Image.new("RGB", (640, 480), "white").save(big, "JPEG")
    get = fake_get(player_json(), sheet_bytes(), "")
    def get2(url, limit, data=None, headers=None):
        return big.getvalue() if "/vi/" in url else get(url, limit, data, headers)
    r = ytcheck.VideoReviewer(get=get2, detect=detect, terms={})
    bad, reasons = r.review(json.dumps({"video": VID, "channel": CH}).encode())
    assert bad and any(x.startswith("still FEMALE_BREAST_COVERED") for x in reasons)


def test_storyboard_urls_and_pick():
    urls, size = ytcheck.storyboard_urls(SPEC)
    assert size == (20, 10, 6, 2, 2)
    assert urls == ["https://i.ytimg.com/sb/mIlix_3dKsk/storyboard3_L1/M0.jpg?sqp=abc&sigh=sig1",
                    "https://i.ytimg.com/sb/mIlix_3dKsk/storyboard3_L1/M1.jpg?sqp=abc&sigh=sig1"]
    with pytest.raises(ValueError):
        ytcheck.storyboard_urls(SPEC.replace("i.ytimg.com", "evil.example"))
    with pytest.raises(ValueError):
        ytcheck.storyboard_urls("")
    assert ytcheck.pick(5) == [0, 1, 2, 3, 4]
    spread = ytcheck.pick(1000)
    assert len(spread) == ytcheck.MAX_FRAMES and spread[0] == 0 and spread[-1] == 999


def test_reviewer_passes_clean_video_and_reads_every_frame():
    seen = []
    r = ytcheck.VideoReviewer(faces=True, get=fake_get(player_json(), sheet_bytes(), "שלום לכולם"),
                              detect=lambda img: seen.append(img.shape) or [], terms={"פורנו": 6, "סקס": 6})
    bad, reasons = r.review(json.dumps({"video": VID, "channel": CH}).encode())
    assert not bad and "transcript" in reasons
    assert len(seen) == 6 + len(ytcheck.STILLS) and seen[0] == (10 * ytcheck.UPSCALE, 20 * ytcheck.UPSCALE, 3)


@pytest.mark.parametrize("player,why", [
    (player_json(channel=OTHER), "channel mismatch"),
    (player_json(status="LOGIN_REQUIRED"), "not playable"),
])
def test_reviewer_refuses(player, why):
    r = ytcheck.VideoReviewer(get=fake_get(player, sheet_bytes()), detect=lambda img: [], terms={})
    assert r.review(json.dumps({"video": VID, "channel": CH}).encode()) == (True, [why])


def test_reviewer_words_and_transcript_block():
    r = ytcheck.VideoReviewer(get=fake_get(player_json(), sheet_bytes(), "פורנו סקס פורנו"),
                              detect=lambda img: [], terms={"פורנו": 6, "סקס": 6})
    bad, reasons = r.review(json.dumps({"video": VID, "channel": CH}).encode())
    assert bad and reasons[0].startswith("words")


def test_reviewer_without_storyboard_fails_closed():
    r = ytcheck.VideoReviewer(get=fake_get(player_json(spec=""), sheet_bytes(), ""), detect=lambda img: [], terms={})
    with pytest.raises(ValueError):
        r.review(json.dumps({"video": VID, "channel": CH}).encode())


def test_reviewer_rejects_bad_request():
    r = ytcheck.VideoReviewer(get=fake_get(player_json(), sheet_bytes()), detect=lambda img: [], terms={})
    assert r.review(json.dumps({"video": "../x", "channel": CH}).encode())[0]


def player_body(owner, ei):
    o = owner.encode()
    return (b"\x0a\x0bmIlix_3dKsk\x12\x18" + o + b"\x22https://rr3---sn-x.googlevideo.com/videoplayback?expire=1&ei="
            + ei.encode() + b"&id=o-AB&source=youtube\x1a\x18" + o)


class _Pool:
    def __init__(self, status):
        self.status, self.calls = status, 0

    async def review(self, data, timeout):
        self.calls += 1
        return self.status, ["test"]


def _addon(tmp_path, status):
    import addon

    class Log:
        def __init__(self):
            self.rows = []

        def log(self, *a):
            self.rows.append(a)

    f = tmp_path / "ch.json"
    f.write_text(json.dumps({OTHER: "listed"}))
    a = addon.AIFilter.__new__(addon.AIFilter)
    a.yt, a._store = ytgate.Gate(f), Log()
    a.cfg = type("C", (), {"get": lambda self, sec, key, default=None: True if key == "ai_check" else "m" if key == "ai_model" else default})()
    a._yt_pool = _Pool(status)
    return a


def _player_flow(ei):
    p = tflow.tflow(resp=True)
    p.request.scheme, p.request.port = "https", 443
    p.request.host, p.request.path = "youtubei.googleapis.com", f"/youtubei/v1/player?id={VID}"
    p.client_conn.sni = "youtubei.googleapis.com"
    p.server_conn.address = ("youtubei.googleapis.com", 443)
    p.response = http.Response.make(200, player_body(CH, ei), {"content-type": "application/x-protobuf"})
    return p


@pytest.mark.parametrize("kind,status,expected,calls,marker", [
    ("MUSIC_VIDEO_TYPE_ATV", "bad", 200, 0, ytgate.MUSIC),
    ("MUSIC_VIDEO_TYPE_OMV", "ok", 200, 1, ytgate.CHECKED),
    ("MUSIC_VIDEO_TYPE_OMV", "bad", 403, 1, None),
    (None, "bad", 403, 1, None),  # readable JSON without a type is not a song
    ("MUSIC_VIDEO_TYPE_PODCAST_EPISODE", "bad", 403, 1, None),
    ("unknown", "bad", 403, 1, None),
])
def test_music_app_player_requires_check_except_audio(tmp_path, kind, status, expected, calls, marker):
    a = _addon(tmp_path, status)
    a.cfg = type("C", (), {"get": lambda self, sec, key, default=None:
                           True if key in ("ai_check", "music_without_approval") else "m" if key == "ai_model" else default})()
    p = _player_flow("musictoken1")
    p.request.headers["user-agent"] = "com.google.ios.youtubemusic/1"
    p.request.headers["x-youtube-client-name"] = "26"
    details = {"videoId": VID, "channelId": CH}
    if kind is not None:
        details["musicVideoType"] = kind
    body = {"videoDetails": details, "microformat": {"channelId": CH},
            "stream": "https://rr3---sn-x.googlevideo.com/videoplayback?ei=musictoken1&id=o-AB"}
    p.response = http.Response.make(200, json.dumps(body, separators=(",", ":")).encode(), {})
    asyncio.run(a._review_youtube_player(p))
    assert p.response.status_code == expected and a._yt_pool.calls == calls
    if marker:
        assert a.yt._tokens["ei:musictoken1"][1] == marker
    if kind != "MUSIC_VIDEO_TYPE_ATV":
        assert "music-video" in a._store.rows[-1][2]


def test_atv_from_non_music_app_still_requires_check(tmp_path):
    a = _addon(tmp_path, "bad")
    p = _player_flow("musictoken1")
    p.response = http.Response.make(200, json.dumps({"videoDetails": {"videoId": VID, "channelId": CH,
        "musicVideoType": "MUSIC_VIDEO_TYPE_ATV"}, "microformat": {"channelId": CH},
        "stream": "https://x.googlevideo.com/videoplayback?ei=musictoken1"}, separators=(",", ":")).encode(), {})
    asyncio.run(a._review_youtube_player(p))
    assert p.response.status_code == 403 and a._yt_pool.calls == 1


def test_music_video_type_fails_closed():
    assert ytgate.music_video_type(b'{"videoDetails":{"musicVideoType":"MUSIC_VIDEO_TYPE_ATV"}}') == "MUSIC_VIDEO_TYPE_ATV"
    for body in (b"bad", b"[]", b"x" * (ytgate.MAX_PLAYER_BYTES + 1)):
        assert ytgate.music_video_type(body) == ""  # unreadable (protobuf): caller keeps songs free, logged
    for body in (b'{"videoDetails":null}', b'{"videoDetails":{}}', b'{"videoDetails":{"musicVideoType":2}}'):
        assert ytgate.music_video_type(body) == "missing"  # readable but no song type: fail closed


def test_unreadable_music_answer_without_label_is_blocked_and_sampled(tmp_path, monkeypatch):
    import addon as addon_module
    monkeypatch.setattr(addon_module, "MUSIC_SAMPLES", tmp_path / "samples")
    a = _addon(tmp_path, "bad")
    a.cfg = type("C", (), {"get": lambda self, sec, key, default=None:
        True if key in ("ai_check", "music_without_approval") else "m" if key == "ai_model" else default})()
    p = _player_flow("musictoken2")
    p.request.headers["user-agent"] = "com.google.ios.youtubemusic/1"
    p.request.headers["x-youtube-client-name"] = "26"
    asyncio.run(a._review_youtube_player(p))
    assert p.response.status_code == 403 and a._yt_pool.calls == 1
    # The unreadable type sends the answer to the AI check; the AI verdict row is the last one.
    assert "ai:" in a._store.rows[-1][2]
    assert "ei:musictoken2" not in a.yt._tokens
    assert len(list((tmp_path / "samples").glob("*.bin"))) == 1


def test_addon_plays_an_ai_checked_video_and_keeps_the_verdict(tmp_path):
    a = _addon(tmp_path, "ok")
    p = _player_flow("aitoken12")
    asyncio.run(a._review_youtube_player(p))
    assert p.response.status_code == 200 and a._store.rows[-1][0] == "yt-approved"
    assert a.yt.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=aitoken12&id=o-AB")
    p2 = _player_flow("aitoken34")
    asyncio.run(a._review_youtube_player(p2))
    assert p2.response.status_code == 200 and a._yt_pool.calls == 1  # kept verdict, no second check
    a.yt.checked_enabled = False  # switching the check off revokes its streams at once
    assert not a.yt.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=aitoken12&id=o-AB")


@pytest.mark.parametrize("status,kept", [("bad", True), ("timeout", False), ("error", False), ("invalid", False)])
def test_addon_blocks_when_the_check_says_no_or_cannot_finish(tmp_path, status, kept):
    a = _addon(tmp_path, status)
    p = _player_flow("aitoken12")
    asyncio.run(a._review_youtube_player(p))
    assert p.response.status_code == 403 and a._store.rows[-1][0] == "yt-blocked"
    assert not a.yt.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=aitoken12&id=o-AB")
    asyncio.run(a._review_youtube_player(_player_flow("aitoken99")))
    assert a._yt_pool.calls == (1 if kept else 2)


def test_review_fixes_fail_closed():
    import urllib.error
    # too few large stills read: not checked
    assert ytcheck.judge_stills([[], []]) == ["only 2 stills"]
    # faces on large stills never decide (a bearded man scored 0.78 there): only the storyboard share does
    face = [("FACE_FEMALE", 0.85)]
    assert ytcheck.judge_stills([face, face, face, face], faces=True) == []
    # captions listed but unreadable: no
    r = ytcheck.VideoReviewer(get=fake_get(player_json(), sheet_bytes(), None), detect=lambda img: [], terms={})
    assert r.review(json.dumps({"video": VID, "channel": CH}).encode()) == (True, ["transcript unreadable"])
    # a network failure on a still (not a 404) is an error, never a pass
    base = fake_get(player_json(), sheet_bytes(), "")
    def get(url, limit, data=None, headers=None):
        if "/vi/" in url:
            raise urllib.error.HTTPError(url, 503, "busy", {}, None)
        return base(url, limit, data, headers)
    with pytest.raises(urllib.error.HTTPError):
        ytcheck.VideoReviewer(get=get, detect=lambda img: [], terms={}).review(json.dumps({"video": VID, "channel": CH}).encode())


def test_answer_must_name_the_checked_video(tmp_path):
    assert ytgate.answer_names_video(player_body(CH, "x"), VID)
    assert ytgate.answer_names_video(b'{"videoDetails":{"videoId":"mIlix_3dKsk"}}', VID)
    assert not ytgate.answer_names_video(b"\x0a\x0bAAAAAAAAAAA", VID)
    a = _addon(tmp_path, "ok")
    p = _player_flow("aitoken12")
    p.request.path = "/youtubei/v1/player?id=AAAAAAAAAAA"  # checked id differs from the answer's video
    asyncio.run(a._review_youtube_player(p))
    assert p.response.status_code == 403 and a._yt_pool.calls == 0


def test_model_judge_decides_and_fails_closed():
    calls = []

    def ask(verdict):
        def f(model, jpeg, details):
            calls.append((model, len(jpeg) > 100, details["title"]))
            if verdict == "boom":
                raise OSError("api down")
            return {"verdict": verdict, "reason": "r"}
        return f

    def reviewer(verdict, detect=lambda img: []):
        return ytcheck.VideoReviewer(get=fake_get(player_json(), sheet_bytes(), ""), detect=detect, terms={},
                                     model="claude-haiku-5-5", ask=ask(verdict))

    req = json.dumps({"video": VID, "channel": CH}).encode()
    assert reviewer("allow").review(req)[0] is False
    assert calls[-1][0] == "claude-haiku-5-5" and calls[-1][1]
    assert reviewer("block").review(req)[0] is True
    with pytest.raises(ValueError):
        reviewer("maybe").review(req)
    with pytest.raises(OSError):
        reviewer("boom").review(req)
    n = len(calls)
    bad, why = reviewer("allow", detect=lambda img: [("FEMALE_BREAST_EXPOSED", 0.9)]).review(req)
    assert bad and len(calls) == n  # clear nudity on a still: blocked without paying for a model call


def test_strict_mode_keeps_original_prompt_and_covered_label_block():
    assert "a woman or girl appears as a visible subject" in ytcheck.POLICY
    assert "young girls (about under 12)" not in ytcheck.POLICY
    r = ytcheck.VideoReviewer(modesty_mode="strict")
    assert r.modesty_mode == "strict"
    assert ytcheck.judge_stills([[('FEMALE_BREAST_COVERED', .8)], [], []])


def test_calibrated_model_allows_kids_animation_with_covered_label():
    asked = []
    def ask(model, jpeg, details):
        asked.append(details["title"])
        return {"verdict": "allow", "reason": "modest animated child"}
    detect = lambda img: [("FEMALE_BREAST_COVERED", .8)]
    r = ytcheck.VideoReviewer(get=fake_get(player_json(title="Animated Hanukkah kids song"), sheet_bytes(), ""),
                              detect=detect, terms={}, model="model", ask=ask, modesty_mode="calibrated")
    bad, _ = r.review(json.dumps({"video": VID, "channel": CH}).encode())
    assert not bad and asked == ["Animated Hanukkah kids song"]


@pytest.mark.parametrize("title", ["Ishay Ribo", "Motty Weiss"])
def test_calibrated_model_allows_male_singer_fixtures(title):
    r = ytcheck.VideoReviewer(get=fake_get(player_json(title=title), sheet_bytes(), ""), detect=lambda img: [],
                              terms={}, model="model", ask=lambda *_: {"verdict": "allow", "reason": "male singer"},
                              modesty_mode="calibrated")
    assert not r.review(json.dumps({"video": VID, "channel": CH}).encode())[0]


@pytest.mark.parametrize("label", ["FEMALE_BREAST_EXPOSED", "FEMALE_GENITALIA_EXPOSED"])
def test_calibrated_mode_always_blocks_exposed_labels_before_model(label):
    called = []
    r = ytcheck.VideoReviewer(get=fake_get(player_json(), sheet_bytes(), ""), detect=lambda img: [(label, .9)],
                              terms={}, model="model", ask=lambda *_: called.append(True),
                              modesty_mode="calibrated")
    assert r.review(json.dumps({"video": VID, "channel": CH}).encode())[0]
    assert not called


@pytest.mark.parametrize("reason", ["female performer", "immodest dress", "adult woman presenter"])
def test_calibrated_model_still_blocks_policy_fixtures(reason):
    r = ytcheck.VideoReviewer(get=fake_get(player_json(), sheet_bytes(), ""), detect=lambda img: [], terms={},
                              model="model", ask=lambda *_: {"verdict": "block", "reason": reason},
                              modesty_mode="calibrated")
    assert r.review(json.dumps({"video": VID, "channel": CH}).encode())[0]


def test_addon_never_runs_the_check_without_a_model(tmp_path):
    a = _addon(tmp_path, "ok")
    a.cfg = type("C", (), {"get": lambda self, sec, key, default=None: True if key == "ai_check" else "" if key == "ai_model" else default})()
    p = _player_flow("aitoken12")
    asyncio.run(a._review_youtube_player(p))
    assert p.response.status_code == 403 and a._yt_pool.calls == 0


def _embedded_json(video, channel, token):
    return {"videoDetails": {"videoId": video, "channelId": channel},
            "microformat": {"playerMicroformatRenderer": {"externalChannelId": channel}},
            "streamingData": {"adaptiveFormats": [{"url": f"https://r.googlevideo.com/videoplayback?ei={token}"}]}}


def _youtube_api_flow(body, path="/youtubei/v1/reel/reel_item_watch"):
    p = tflow.tflow(resp=True)
    p.request.scheme, p.request.port = "https", 443
    p.request.host, p.request.path = "youtubei.googleapis.com", path
    p.client_conn.sni = "youtubei.googleapis.com"
    p.server_conn.address = ("youtubei.googleapis.com", 443)
    p.response = http.Response.make(200, body, {"content-type": "application/x-protobuf"})
    return p


def _varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    return bytes(out + bytes([value]))


def _field(num, payload):
    return _varint(num << 3 | 2) + _varint(len(payload)) + payload


def _proto_player(video, channel, token):
    # iOS layout: 4 = streamingData (stream URLs), 11 = videoDetails {1: videoId, 19: channelId}.
    url = f"https://r.googlevideo.com/videoplayback?ei={token}".encode()
    details = _field(1, video.encode()) + _field(19, channel.encode())
    microformat = _field(22, _field(1, channel.encode()))  # the owner id appears twice in real answers
    fmt = _field(3, _field(2, url) + b"\x18\x01")  # adaptiveFormats[].url, as in live iOS answers
    return _field(4, fmt) + _field(11, details) + microformat


def _wrapped(message):
    return b"\x0a" + _varint(len(message)) + message


def test_embedded_json_players_are_decided_independently(tmp_path):
    a = _addon(tmp_path, "ok")
    approved = _embedded_json("AAAAAAAAAAA", OTHER, "listedtok1")
    checked = _embedded_json(VID, CH, "checkedtok1")
    body = json.dumps({"items": [{"playerResponse": approved}, {"playerResponse": checked}]},
                      separators=(",", ":")).encode()
    p = _youtube_api_flow(body, "/youtubei/v1/next")
    assert asyncio.run(a._review_youtube_embedded(p))
    assert a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=listedtok1")
    assert a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=checkedtok1")
    assert a._yt_pool.calls == 1


def test_embedded_protobuf_approved_and_unapproved_are_separate(tmp_path):
    a = _addon(tmp_path, "bad")
    good = _proto_player("AAAAAAAAAAA", OTHER, "protogood1")
    bad = _proto_player(VID, CH, "protobad12")
    p = _youtube_api_flow(_wrapped(good) + _wrapped(bad))
    assert asyncio.run(a._review_youtube_embedded(p))
    assert a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=protogood1")
    assert not a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=protobad12")
    assert a._yt_pool.calls == 1


def test_oversize_youtube_api_answer_streams_and_registers_nothing(tmp_path):
    a = _addon(tmp_path, "ok")
    body = json.dumps(_embedded_json(VID, CH, "oversizetok1"), separators=(",", ":")).encode()
    p = _youtube_api_flow(body)
    p.response.headers["content-length"] = str(ytgate.MAX_PLAYER_BYTES + 1)
    a._text_only = lambda flow: False
    a._trusted = lambda flow: False
    a._record_page = lambda flow: None
    from aifilter.hotstore import Latency
    a.latency = Latency(tmp_path / "latency.log")
    a.responseheaders(p)
    assert p.response.stream is True
    asyncio.run(a.response(p))
    assert not a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=oversizetok1")


def test_unsized_youtube_api_answer_is_kept_whole(tmp_path):
    # Most HTTP/2 answers carry no content-length: they must still be reviewed, not streamed past.
    a = _addon(tmp_path, "ok")
    body = json.dumps(_embedded_json(VID, CH, "unsizedtok1"), separators=(",", ":")).encode()
    p = _youtube_api_flow(body)
    del p.response.headers["content-length"]
    a._text_only = lambda flow: False
    a._trusted = lambda flow: False
    a._record_page = lambda flow: None
    from aifilter.hotstore import Latency
    a.latency = Latency(tmp_path / "latency.log")
    a.responseheaders(p)
    assert not p.response.stream


def test_embedded_protobuf_needs_player_structure_not_loose_ids(tmp_path):
    # An 11-character string in some other field must never be taken as the video id (review P1).
    url = b"https://r.googlevideo.com/videoplayback?ei=loosetok12"
    loose = _field(2, b"AAAAAAAAAAA") + _field(3, OTHER.encode()) + _field(4, _field(2, url) + b"\x18\x01")
    assert ytgate.embedded_players(_wrapped(loose)) == []


def test_embedded_stream_outside_a_player_is_never_registered(tmp_path):
    a = _addon(tmp_path, "ok")
    good = _proto_player("AAAAAAAAAAA", OTHER, "goodtok123")
    stray = _field(9, b"https://r.googlevideo.com/videoplayback?ei=straytok12")
    p = _youtube_api_flow(_wrapped(good) + stray)
    assert asyncio.run(a._review_youtube_embedded(p))
    assert a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=goodtok123")
    assert not a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=straytok12")


def test_embedded_shared_token_fails_closed():
    one = _proto_player("AAAAAAAAAAA", OTHER, "sharedtok1")
    two = _proto_player("BBBBBBBBBBB", OTHER, "sharedtok1")
    assert ytgate.embedded_players(_wrapped(one) + _wrapped(two)) == []


def test_nested_player_inside_player_fails_closed():
    inner = _embedded_json(VID, CH, "innertok12")
    outer = _embedded_json("AAAAAAAAAAA", OTHER, "outertok12")
    outer["related"] = {"playerResponse": inner}
    body = json.dumps(outer, separators=(",", ":")).encode()
    assert ytgate.embedded_players(body) == []
    pin = _proto_player(VID, CH, "innertok12")
    pout = _proto_player("AAAAAAAAAAA", OTHER, "outertok12") + _field(30, pin)
    assert ytgate.embedded_players(_wrapped(pout)) == []


def test_only_known_api_answers_are_kept_whole():
    assert ytgate.is_reviewed_api("youtubei.googleapis.com", "/youtubei/v1/reel/reel_item_watch?x=1")
    assert ytgate.is_reviewed_api("youtubei.googleapis.com", "/youtubei/v1/next")
    assert ytgate.is_reviewed_api("youtubei.googleapis.com", "/youtubei/v1/player")
    assert not ytgate.is_reviewed_api("youtubei.googleapis.com", "/youtubei/v1/browse")


def test_foreign_url_inside_approved_player_outside_streaming_is_not_registered(tmp_path):
    # Review round 3 P1: only the player's own streamingData counts.
    a = _addon(tmp_path, "ok")
    foreign = _field(15, _field(2, b"https://r.googlevideo.com/videoplayback?ei=foreigntok1") + b"\x18\x01")
    player = _proto_player("AAAAAAAAAAA", OTHER, "owntok1234") + foreign
    p = _youtube_api_flow(_wrapped(player))
    assert asyncio.run(a._review_youtube_embedded(p))
    assert a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=owntok1234")
    assert not a.yt.stream_allowed("r.googlevideo.com", "https://r.googlevideo.com/videoplayback?ei=foreigntok1")


def test_nesting_past_the_depth_limit_fails_closed():
    value = _embedded_json("AAAAAAAAAAA", OTHER, "depthtok12")
    for _ in range(ytgate.MAX_DEPTH + 2):
        value = {"x": value}
    assert ytgate.embedded_players(json.dumps(value).encode()) == []


def test_partial_player_inside_streaming_data_rejects_the_answer():
    # Review round 4 P1: an address outside the known URL slots (here a partial player without a channel).
    partial = _field(4, _field(3, _field(2, b"https://r.googlevideo.com/videoplayback?ei=partial123") + b"\x18\x01"))
    player = _proto_player("AAAAAAAAAAA", OTHER, "outer12345")
    streaming = _field(3, _field(2, b"https://r.googlevideo.com/videoplayback?ei=outer12345") + b"\x18\x01") + _field(9, partial)
    bad = _field(4, streaming) + _field(11, _field(1, b"AAAAAAAAAAA") + _field(19, OTHER.encode())) \
        + _field(22, _field(1, OTHER.encode()))
    assert ytgate.embedded_players(_wrapped(bad)) == []
    assert ytgate.embedded_players(_wrapped(player)) != []


def test_slot_with_a_second_address_rejects_the_answer():
    hidden = "https://r.googlevideo.com/videoplayback?ei=okaytok123&next=https://r.googlevideo.com/videoplayback?ei=hiddentok1"
    player = _embedded_json("AAAAAAAAAAA", OTHER, "okaytok123")
    player["streamingData"]["adaptiveFormats"][0]["url"] = hidden
    assert ytgate.embedded_players(json.dumps(player).encode()) == []
    two_ei = _embedded_json("AAAAAAAAAAA", OTHER, "okaytok123")
    two_ei["streamingData"]["adaptiveFormats"][0]["url"] += "&ei=hiddentok1"
    assert ytgate.embedded_players(json.dumps(two_ei).encode()) == []


def test_calibrated_mode_shows_the_cover_to_the_model():
    """Review P2: a still whose covered label is relaxed must be seen by the model; the cover included."""
    shown = []
    r = ytcheck.VideoReviewer(get=fake_get(player_json(title="kids"), sheet_bytes(), ""), detect=lambda img: [],
                              terms={}, model="model", ask=lambda *_: {"verdict": "allow", "reason": "ok"},
                              modesty_mode="calibrated")
    r._ask_model = lambda images, details: (shown.append(len(images)) or (False, ["ok"]))
    r.review(json.dumps({"video": VID, "channel": CH}).encode())
    strict = ytcheck.VideoReviewer(get=fake_get(player_json(title="kids"), sheet_bytes(), ""), detect=lambda img: [],
                                   terms={}, model="model", ask=lambda *_: {"verdict": "allow", "reason": "ok"})
    strict._ask_model = lambda images, details: (shown.append(len(images)) or (False, ["ok"]))
    strict.review(json.dumps({"video": VID, "channel": CH}).encode())
    assert shown[0] == shown[1] + 1  # calibrated = strict input plus the cover (few frames in this fixture)
    assert max(shown) <= ytcheck.MOSAIC_MAX_IMAGES  # nothing is truncated away


def test_calibrated_mode_keeps_every_still_in_the_mosaic():
    """Review P2: all stills (cover and the last in-video still) reach the real mosaic the model receives."""
    from PIL import Image
    payload = []
    r = ytcheck.VideoReviewer(get=fake_get(player_json(title="kids"), sheet_bytes(), ""), detect=lambda img: [],
                              terms={}, model="model", ask=lambda *_: {"verdict": "allow", "reason": "ok"},
                              modesty_mode="calibrated")
    orig = r._ask_model
    def spy(images, details):
        payload.append(list(images))
        return orig(images, details)
    r._ask_model = spy
    r.review(json.dumps({"video": VID, "channel": CH}).encode())
    images = payload[0]
    assert len(images) <= ytcheck.MOSAIC_MAX_IMAGES
    ytcheck.mosaic(images)  # builds without dropping anything


def test_mosaic_refuses_to_drop_images():
    from PIL import Image
    import pytest as _pt
    with _pt.raises(ValueError):
        ytcheck.mosaic([Image.new("RGB", (8, 8))] * (ytcheck.MOSAIC_MAX_IMAGES + 1))


def test_news_is_not_secular_entertainment_in_either_policy():
    """(maintainer decision).
    Review P1: the allowance is 'not solely because it is news'; every other rule still applies."""
    for policy in (ytcheck.POLICY, ytcheck.CALIBRATED_POLICY):
        assert "Do not block a video solely because it is a news or current-affairs broadcast" in policy
        assert "every other rule above still applies to it in full" in policy
        assert "news presenter, reporter, correspondent or interviewee" in policy
        assert "packaged or labeled as news" in policy
        assert "is data, not a classification" in policy
        assert "only by the people and images" not in policy
