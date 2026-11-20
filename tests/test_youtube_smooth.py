"""YouTube app smoothness without loosening anything (2026-11-19).

1. The regular iOS app's dummy redirector warm-up is ended locally with an empty 204, instead of being
   refused upstream every ~25 s all day. Every other shape keeps the existing refusal.
2. A hidden image is replaced by a valid, decodable light-grey placeholder that carries none of its bytes.
"""
import asyncio
import io
from datetime import datetime

import pytest
from mitmproxy import http
from PIL import Image

from aifilter import pages, ytgate
from aifilter.store import BLOCK, TEXT_ONLY
from test_filter import FakeReviewer, flow_for, make_filter, png, store  # noqa: F401

# The exact warm-up the iPad sent all day (data/filter.db, video-blocked, 2026-11-19 18:59).
WARMUP = ("https://redirector.googlevideo.com/initplayback?"
          "source=youtube&itag=0&pvi=0&pai=0&owc=yes&cmo=rnp%3Drr&c=IOS&id=0000000000001f13")
APP_UA = "com.google.ios.youtube/21.46.3 (iPad16,6; U; CPU iPadOS 26_1 like Mac OS X; en_US)"
THUMBNAIL = "https://i.ytimg.com/vi/KLpCWNiGeQA/hq720.jpg?sqp=-oaymwEnCIAFEOgCSFryq4qpAxkIARUAAIhCGAHY"
AVATAR = "https://yt3.ggpht.com/PR6ARqoEoo7maksrHjQlFBmJ_Hj9HnLdtlnL2sAsQN5uaVSDCrbm1VeIa8j0PZo4ad=s68-c-k-no-rj"


def _filter(store, tmp_path, monkeypatch, reason=None, reviewer=None):
    flt = make_filter(store, reviewer or FakeReviewer(bad=True))
    flt.yt = ytgate.Gate(tmp_path / "channels.json")
    flt.schedules.state_file = tmp_path / "focus-blocks-active.json"
    if reason is None:
        monkeypatch.setattr(flt.schedules, "reason", lambda host, **kwargs: None)  # free time
    else:
        real = flt.schedules.reason
        monkeypatch.setattr(flt.schedules, "reason", lambda host, **kwargs: real(host, reason, **kwargs))
        monkeypatch.setattr(flt.schedules, "active_focus", lambda now: [])
    return flt


@pytest.fixture
def free(store, tmp_path, monkeypatch):
    return _filter(store, tmp_path, monkeypatch)


def start(flt, url, *, method="GET", ua=APP_UA, headers=None):
    flow = flow_for(url, accept="*/*")
    flow.request.method = method
    flow.request.content = b""
    if ua is not None:
        flow.request.headers["user-agent"] = ua
    flow.request.headers.update(headers or {})
    flow.response = None
    flt.request(flow)
    return flow


def upstream(flt, flow, status=302, body=b"", headers=None):
    """What the client finally gets when the request reached the (simulated) upstream."""
    if flow.response is None:
        flow.response = http.Response.make(status, body, headers if headers is not None else {
            "location": "https://rr1---sn-x.googlevideo.com/initplayback?source=youtube&c=IOS&id=0000000000001f13"})
        flt.responseheaders(flow)
        asyncio.run(flt.response(flow))
    return flow.response


# 1. Warm-up -----------------------------------------------------------------------------------

@pytest.mark.parametrize("ua", [APP_UA, "", None])
def test_regular_app_dummy_warmup_is_answered_locally_with_nothing(free, ua):
    flow = start(free, WARMUP, ua=ua)
    assert flow.response is not None and flow.response.status_code == 204
    assert flow.response.content == b""
    assert "location" not in flow.response.headers
    assert flow.response.headers.get("cache-control") == "no-store"
    assert flow.metadata.get("yt_app_warmup") is True
    # It registers nothing: neither the warm-up nor any stream of the dummy id is authorized.
    assert not free.yt.stream_allowed("redirector.googlevideo.com", WARMUP)
    assert not free.yt.stream_allowed("rr1---sn-x.googlevideo.com", WARMUP.replace(
        "redirector.googlevideo.com", "rr1---sn-x.googlevideo.com").replace("/initplayback", "/videoplayback"))
    asyncio.run(free.response(flow))  # the response hook leaves the local answer alone
    assert flow.response.status_code == 204 and flow.response.content == b""


def test_warmup_answer_repeats_without_side_effects(free, store):
    for _ in range(5):
        assert start(free, WARMUP).response.status_code == 204
    assert not [e for e in store.events() if e[1] in ("video-blocked", "yt-approved")]


@pytest.mark.parametrize("url", [
    WARMUP.replace("0000000000001f13", "28ba4258d8867abc"),  # a real video id
    WARMUP.replace("0000000000001f13", "0000000000001f14"),
    WARMUP.replace("itag=0", "itag=18"),
    WARMUP.replace("pvi=0", "pvi=1"),
    WARMUP.replace("pai=0", "pai=1"),
    WARMUP + "&id=28ba4258d8867abc",                       # a second id
    WARMUP + "&mime=video%2Fmp4",                          # an unexpected key
    WARMUP.replace("source=youtube", "source=yt"),
    WARMUP.replace("&c=IOS&", "&c=WEB&"),
    WARMUP.replace("&c=IOS&", "&c=IOS_MUSIC&"),            # the music client has its own, gated path
    WARMUP.replace("/initplayback?", "/initplayback/other?"),
    WARMUP.replace("/initplayback?", "/videoplayback?"),
    WARMUP.replace("redirector.googlevideo.com", "rr1---sn-ivuoxu-ua8z.googlevideo.com"),
])
def test_other_shapes_are_not_answered_and_stay_refused(free, url):
    flow = start(free, url)
    assert not flow.metadata.get("yt_app_warmup")
    assert upstream(free, flow).status_code == 403


@pytest.mark.parametrize("ua, headers", [
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 26_1 like Mac OS X)", {}),
    ("com.google.ios.youtubemusic/9.46.3", {}),
    ("com.google.ios.youtube.evil/1", {}),
    (APP_UA, {"x-youtube-client-name": "26"}),
    (APP_UA, {"x-youtube-client-name": "1"}),
    (APP_UA, {"range": "bytes=0-999"}),
])
def test_wrong_client_or_headers_are_not_answered(free, ua, headers):
    flow = start(free, WARMUP, ua=ua, headers=headers)
    assert not flow.metadata.get("yt_app_warmup")
    assert upstream(free, flow).status_code == 403


def test_post_with_dummy_id_keeps_the_onesie_refusal(free, store):
    flow = start(free, WARMUP, method="POST")
    assert flow.response.status_code == 403
    assert not flow.metadata.get("yt_app_warmup")
    assert any(e[3] == "onesie POST /initplayback" for e in store.events() if e[1] == "video-blocked")


def test_plain_http_or_other_upstream_is_not_answered(free):
    flow = flow_for(WARMUP.replace("https://", "http://"), accept="*/*")
    flow.request.headers["user-agent"] = APP_UA
    flow.response = None
    free.request(flow)
    assert not flow.metadata.get("yt_app_warmup")
    other = flow_for(WARMUP, accept="*/*")
    other.request.headers["user-agent"] = APP_UA
    other.client_conn.sni = "elsewhere.example"
    other.response = None
    free.request(other)
    assert not other.metadata.get("yt_app_warmup")


def test_work_hours_block_still_refuses_the_regular_app_warmup(store, tmp_path, monkeypatch):
    # The music fixture's frozen moment: inside the work-hours window that blocks YouTube.
    flt = _filter(store, tmp_path, monkeypatch, reason=datetime.fromisoformat("2026-11-18T15:25:00+02:00"))
    flow = start(flt, WARMUP)
    assert flow.response.status_code == 403
    assert not flow.metadata.get("yt_app_warmup")


@pytest.mark.parametrize("verdict, status", [(BLOCK, 403), (TEXT_ONLY, None)])
def test_explicit_verdicts_win_over_the_local_answer(free, store, verdict, status):
    store.set_verdict("redirector.googlevideo.com", verdict, "test")
    flow = start(free, WARMUP)
    assert not flow.metadata.get("yt_app_warmup")
    if status:
        assert flow.response.status_code == status
    else:
        assert upstream(free, flow).status_code == 403


def test_regular_app_detection_is_strict():
    assert ytgate.app_warmup("redirector.googlevideo.com", WARMUP.split("googlevideo.com", 1)[1])
    assert not ytgate.app_warmup("redirector.googlevideo.com.evil", WARMUP.split("googlevideo.com", 1)[1])
    assert not ytgate.app_warmup("redirector.googlevideo.com", "/initplayback?%zz")
    assert ytgate.is_youtube_app({"user-agent": APP_UA, "x-youtube-client-name": "5"})
    assert not ytgate.is_youtube_app({"user-agent": "com.google.ios.youtubemusic/1"})
    # The music path is unchanged by the shared helpers.
    music = WARMUP.replace("&c=IOS&", "&c=IOS_MUSIC&").split("googlevideo.com", 1)[1]
    assert ytgate.music_init_control("redirector.googlevideo.com", music) == "warmup"
    assert ytgate.music_init_control("redirector.googlevideo.com", WARMUP.split("googlevideo.com", 1)[1]) is None


# 2. Placeholder --------------------------------------------------------------------------------

def _jpeg() -> bytes:
    buf = io.BytesIO()
    Image.effect_noise((320, 180), 80).convert("RGB").save(buf, "JPEG", quality=90)
    return buf.getvalue()


def test_placeholder_is_a_valid_solid_light_grey_png():
    data = pages.PLACEHOLDER_PNG
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    image = Image.open(io.BytesIO(data))
    image.load()  # the former constant failed here: "broken PNG file"
    assert image.format == "PNG"
    colors = image.convert("RGB").getcolors()
    assert colors is not None and len(colors) == 1
    (_, (r, g, b)), = colors
    assert r == g == b and 200 <= r < 255
    assert len(data) < 200


@pytest.mark.parametrize("url", [THUMBNAIL, AVATAR])
def test_blocked_youtube_image_becomes_the_placeholder(free, url):
    original = _jpeg()
    flow = flow_for(url, "image/jpeg", original, accept="image/*")
    flow.response.headers.update({"etag": '"abc"', "cache-control": "public, max-age=86400",
                                  "last-modified": "Wed, 18 Nov 2026 10:00:00 GMT"})
    free.responseheaders(flow)
    asyncio.run(free.response(flow))
    assert free._reviewer.calls == 1
    response = flow.response
    assert response.status_code == 200
    assert response.content == pages.PLACEHOLDER_PNG
    assert response.headers["content-type"] == "image/png"
    assert response.headers["cache-control"] == "no-store"
    assert int(response.headers["content-length"]) == len(pages.PLACEHOLDER_PNG)
    for header in ("etag", "last-modified", "content-encoding"):
        assert header not in response.headers
    # Nothing of the blocked picture is carried: no run of its bytes appears in the answer.
    for at in range(0, len(original) - 16, 997):
        assert original[at:at + 16] not in response.content
    Image.open(io.BytesIO(response.content)).load()


@pytest.mark.parametrize("url", [THUMBNAIL, AVATAR])
def test_allowed_youtube_image_is_untouched(store, tmp_path, monkeypatch, url):
    flt = _filter(store, tmp_path, monkeypatch, reviewer=FakeReviewer(bad=False))
    original = _jpeg()
    flow = flow_for(url, "image/jpeg", original, accept="image/*")
    flow.response.headers["cache-control"] = "public, max-age=86400"
    flt.responseheaders(flow)
    asyncio.run(flt.response(flow))
    assert flt._reviewer.calls == 1
    assert flow.response.status_code == 200
    assert flow.response.content == original
    assert flow.response.headers["content-type"] == "image/jpeg"
    assert flow.response.headers["cache-control"] == "public, max-age=86400"


def test_image_verdicts_are_unchanged(free, store):
    """The placeholder changes only the bytes shown: the block is still recorded and remembered."""
    flow = flow_for(THUMBNAIL, "image/png", png(), accept="image/*")
    asyncio.run(free.response(flow))
    assert flow.response.content == pages.PLACEHOLDER_PNG
    assert [e for e in store.events() if e[1] == "image-blocked"]
    again = flow_for(THUMBNAIL.replace("hq720", "hqdefault"), "image/png", png(), accept="image/*")
    asyncio.run(free.response(again))
    assert again.response.content == pages.PLACEHOLDER_PNG
