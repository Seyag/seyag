import asyncio
import json
from datetime import datetime

import pytest
from mitmproxy import http

from aifilter import pages, ytgate
from aifilter.store import BLOCK, TRUSTED
from test_filter import FakeReviewer, flow_for, make_filter, png, store  # noqa: F401


EDGE = "https://rr2---sn-example.googlevideo.com"
CDN_INIT = EDGE + "/initplayback?source=youtube&c=IOS_MUSIC&id=42dc84a333d93a08&ack=1&opr=1"
WARMUP = (
    "https://redirector.googlevideo.com/initplayback?"
    "source=youtube&itag=0&pvi=0&pai=0&cmo=rnp%3Drr&owc=1&c=IOS_MUSIC&id=0000000000001f13"
)
THUMBNAIL = "https://i.ytimg.com/vi/abcdefghijk/hqdefault.jpg?app=music"
ARTWORK = "https://yt3.googleusercontent.com/sample_Artwork-Example=w544-h544-l90-rj"


@pytest.fixture
def music_filter(store, tmp_path, monkeypatch):
    flt = make_filter(store, FakeReviewer(bad=True))
    flt.yt = ytgate.Gate(tmp_path / "channels.json")
    flt.schedules.state_file = tmp_path / "focus-blocks-active.json"
    # Freeze the schedule in the middle of the reported work-hours window.
    now = datetime.fromisoformat("2026-11-18T15:25:00+02:00")
    reason = flt.schedules.reason
    monkeypatch.setattr(flt.schedules, "reason", lambda host, **kwargs: reason(host, now, **kwargs))
    monkeypatch.setattr(flt.schedules, "active_focus", lambda now: [])
    return flt


def start(flt, url, *, method="GET", ua="com.google.ios.youtubemusic/9.46.3", headers=None):
    flow = flow_for(url, accept="*/*")
    flow.request.method = method
    flow.request.content = b""
    flow.request.headers["user-agent"] = ua
    flow.request.headers.update(headers or {})
    flow.response = None
    flt.request(flow)
    return flow


def finish(flt, flow, status, body=b"", headers=None):
    flow.response = http.Response.make(status, body, headers or {})
    flt.responseheaders(flow)
    asyncio.run(flt.response(flow))


def test_warmup_ends_locally_without_authorizing_a_stream(music_filter):
    flt = music_filter
    flow = start(flt, WARMUP)
    assert flow.response.status_code == 204
    assert flow.response.content == b""
    assert "location" not in flow.response.headers
    assert not flt.yt.stream_allowed(flow.request.pretty_host, WARMUP)


@pytest.mark.parametrize("url", [
    WARMUP.replace("c=IOS_MUSIC", "c=IOS"),
    WARMUP.replace("0000000000001f13", "42dc84a333d93a08"),
    WARMUP.replace("pvi=0", "pvi=1"),
    WARMUP + "&id=42dc84a333d93a08",
    WARMUP.replace("/initplayback?", "/initplayback/other?"),
])
def test_other_warmup_shapes_keep_the_work_hours_block(music_filter, url):
    assert start(music_filter, url).response.status_code == 403


def test_no_content_setup_can_precede_player_approval(music_filter):
    flt = music_filter
    flow = start(flt, CDN_INIT, ua="")
    assert flow.response is None
    assert not flt.yt.stream_allowed(flow.request.pretty_host, CDN_INIT)
    finish(flt, flow, 204, headers={"content-type": "multipart/byteranges; boundary=example"})
    assert flow.response.status_code == 204
    assert flow.response.content == b""
    assert not flt.yt.stream_allowed(flow.request.pretty_host, CDN_INIT)


@pytest.mark.parametrize("status, headers", [
    (200, {"content-type": "application/vnd.yt-ump"}),
    (206, {"content-type": "multipart/byteranges; boundary=example"}),
    (302, {"location": EDGE + "/videoplayback?id=42dc84a333d93a08"}),
    (204, {"content-type": "video/mp4"}),
])
def test_setup_schedule_exception_cannot_forward_a_payload(music_filter, status, headers):
    flt = music_filter
    flow = start(flt, CDN_INIT)
    finish(flt, flow, status, b"unapproved bytes", headers)
    assert flow.response.status_code == 403
    assert flow.response.content == b""
    assert "location" not in flow.response.headers
    assert not flt.yt.stream_allowed(flow.request.pretty_host, CDN_INIT)


def test_setup_does_not_open_onesie_or_videoplayback(music_filter):
    flt = music_filter
    assert start(flt, CDN_INIT, method="POST").response.status_code == 403
    stream = CDN_INIT.replace("/initplayback", "/videoplayback")
    assert start(flt, stream).response.status_code == 403
    assert start(flt, CDN_INIT, headers={"range": "bytes=0-999"}).response.status_code == 403
    flt.cfg.raw["youtube"]["music_without_approval"] = False
    assert start(flt, WARMUP).response.status_code == 403
    assert start(flt, CDN_INIT).response.status_code == 403


def test_reviewed_music_player_still_authorizes_audio(music_filter):
    flt = music_filter
    url = EDGE + "/videoplayback?ei=songEvent123&id=o-approvedAudio&mime=audio%2Fmp4"
    player = start(flt, "https://youtubei.googleapis.com/youtubei/v1/player?id=abcdefghijk",
                   method="POST", headers={"x-youtube-client-name": "26"})
    body = json.dumps({
        "videoDetails": {"videoId": "abcdefghijk", "musicVideoType": "MUSIC_VIDEO_TYPE_ATV"},
        "streamingData": {"adaptiveFormats": [{"mimeType": "audio/mp4", "url": url}]},
    }).encode()
    finish(flt, player, 200, body, {"content-type": "application/json"})
    assert player.response.status_code == 200
    stream = start(flt, url)
    assert stream.response is None
    finish(flt, stream, 200, b"audio", {"content-type": "audio/mp4"})
    assert stream.response.status_code == 200
    assert start(flt, url.replace("o-approvedAudio", "o-otherMedia")).response.status_code == 403


@pytest.mark.parametrize("url", [THUMBNAIL, ARTWORK])
def test_music_cover_is_reviewed_even_on_a_trusted_host(music_filter, store, url):
    flt = music_filter
    host = flow_for(url).request.pretty_host
    store.set_verdict(host, TRUSTED, "test")
    flow = start(flt, url, headers={"range": "bytes=0-999", "if-none-match": '"cached"'})
    assert flow.response is None
    assert flow.request.pretty_url == url
    assert "range" not in flow.request.headers and "if-none-match" not in flow.request.headers

    finish(flt, flow, 200, png(), {"content-type": "image/png"})
    assert flt._reviewer.calls == 1
    assert flow.response.content == pages.PLACEHOLDER_PNG

    flt._reviewer.bad = False
    cover = png()
    flow = start(flt, url.replace("abcdefghijk", "otherSong12").replace("sample_Artwork", "second_Artwork"))
    finish(flt, flow, 200, cover, {"content-type": "image/png"})
    assert flt._reviewer.calls == 2
    assert flow.response.content == cover


@pytest.mark.parametrize("status, ctype", [(200, "video/mp4"), (200, "image/svg+xml"),
                                            (206, "image/jpeg"), (304, "")])
def test_cover_exception_requires_a_complete_raster_response(music_filter, status, ctype):
    flt = music_filter
    flow = start(flt, THUMBNAIL)
    finish(flt, flow, status, b"unreviewed bytes", {"content-type": ctype})
    assert flow.response.status_code == 403
    assert flow.response.content == b""
    assert flt._reviewer.calls == 0


def test_cover_and_warmup_preserve_explicit_blocks(music_filter, store):
    flt = music_filter
    assert start(flt, THUMBNAIL, ua="com.google.ios.youtube/1").response.status_code == 403
    assert start(flt, THUMBNAIL, headers={"x-youtube-client-name": "5"}).response.status_code == 403
    assert start(flt, THUMBNAIL.replace("/vi/", "/sb/")).response.status_code == 403
    for url in (ARTWORK, WARMUP, CDN_INIT):
        store.set_verdict(flow_for(url).request.pretty_host, BLOCK, "test")
        assert start(flt, url).response.status_code == 403


def test_schedule_opt_out_blocks_music_setup_and_thumbnails(music_filter):
    flt = music_filter
    flt.cfg.raw["schedule"]["work"]["allow_music"] = False
    for url in (WARMUP, CDN_INIT, THUMBNAIL):
        assert start(flt, url).response.status_code == 403


def test_empty_image_403_reports_its_source_without_image_review(music_filter, store):
    flt = music_filter
    blocked = start(flt, THUMBNAIL, ua="com.google.ios.youtube/1")
    asyncio.run(flt.response(blocked))
    upstream = start(flt, ARTWORK)
    finish(flt, upstream, 403)
    assert blocked.response.status_code == upstream.response.status_code == 403
    assert flt._reviewer.calls == 0
    assert [row[3] for row in store.events() if row[1] == "image-fetch-error"] == [
        "code=403 source=upstream", "code=403 source=filter",
    ]


def test_edge_init_from_other_client_is_not_init_control(music_filter):
    flow = start(music_filter, CDN_INIT, ua="com.google.ios.youtube/21.46.3")
    assert "yt_init_control" not in flow.metadata


def test_warmup_outside_work_hours_is_not_answered_locally(store, tmp_path, monkeypatch):
    flt = make_filter(store, FakeReviewer(bad=True))
    flt.yt = ytgate.Gate(tmp_path / "channels.json")
    flt.schedules.state_file = tmp_path / "focus-blocks-active.json"
    monkeypatch.setattr(flt.schedules, "reason", lambda host, **kwargs: None)
    flow = start(flt, WARMUP)
    assert flow.response is None or flow.response.status_code != 204
