import asyncio
import json
import sys
from pathlib import Path

import pytest
from mitmproxy import http
from mitmproxy.test import tflow

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aifilter import ytgate  # noqa: E402
from scripts import yt_channels  # noqa: E402

OK = "UCYONKpA1KLr3GA2nKt0jZgg"
OTHER = "UCulYu1HEIa7f70L2lYZWHOw"


def player(owner, ei, extra=b""):
    o = owner.encode()
    return (b"\x0a\x0bmIlix_3dKsk\x12\x18" + o + b"\x22https://rr3---sn-x.googlevideo.com/videoplayback?expire=1&ei="
            + ei.encode() + b"&id=o-AB&source=youtube\x10https://manifest.googlevideo.com/api/manifest/hls_variant/ei/"
            + ei.encode() + b"/id/98\x1a\x18" + o + extra)


@pytest.fixture
def gate(tmp_path):
    f = tmp_path / "ch.json"
    f.write_text(json.dumps({OK: "JEM"}))
    now = [1000.0]
    g = ytgate.Gate(f, clock=lambda: now[0])
    g.now = now
    return g


def test_player_channel_needs_a_clear_owner():
    assert ytgate.player_channel(player(OK, "tok123456")) == OK
    assert ytgate.player_channel(player(OK, "tok123456", OTHER.encode())) == OK  # endscreen mention once
    assert ytgate.player_channel(OK.encode() + OTHER.encode()) is None  # one each: unclear
    assert ytgate.player_channel((OK + OTHER) .encode() * 2) is None  # tie: unclear
    assert ytgate.player_channel(b"") is None


def test_stream_token_query_and_path():
    assert ytgate.stream_token("https://rr1---sn-a.googlevideo.com/videoplayback?expire=1&ei=AbC_-12345") == "AbC_-12345"
    assert ytgate.stream_token("https://manifest.googlevideo.com/api/manifest/hls_variant/ei/AbC_-12345/id/9") == "AbC_-12345"
    assert ytgate.stream_token("https://rr1---sn-a.googlevideo.com/videoplayback?expire=1") is None
    assert ytgate.stream_token("https://x.googlevideo.com/videoplayback?ei=aaaaaaaaaa&ei=bbbbbbbbbb") is None


def test_approved_channel_opens_only_its_streams(gate):
    ok, ch = gate.review_player(player(OK, "goodtoken1"))
    assert ok and ch == OK
    assert gate.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=goodtoken1&id=o-AB")
    assert gate.stream_allowed("manifest.googlevideo.com", "https://manifest.googlevideo.com/api/manifest/hls_variant/ei/goodtoken1/id/98")
    assert not gate.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=othertoken&id=o-AB")
    assert not gate.stream_allowed("evil.example", "https://evil.example/videoplayback?ei=goodtoken1")
    gate.now[0] += ytgate.TOKEN_TTL + 1
    assert not gate.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=goodtoken1")


def test_other_channel_registers_nothing(gate):
    ok, ch = gate.review_player(player(OTHER, "badtoken12"))
    assert not ok and ch == OTHER
    assert not gate.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=badtoken12")


def test_unreadable_list_approves_nothing(tmp_path):
    f = tmp_path / "ch.json"
    f.write_text("{not json")
    assert ytgate.Gate(f).review_player(player(OK, "goodtoken1")) == (False, OK)
    assert ytgate.Gate(tmp_path / "missing.json").review_player(player(OK, "goodtoken1")) == (False, OK)


def test_is_player_api():
    assert ytgate.is_player_api("youtubei.googleapis.com", "/youtubei/v1/player?id=abc")
    assert ytgate.is_player_api("www.youtube.com", "/youtubei/v1/player")
    assert not ytgate.is_player_api("youtubei.googleapis.com", "/youtubei/v1/player/heartbeat")
    assert not ytgate.is_player_api("youtube.com.evil.example", "/youtubei/v1/player")


def test_addon_gate_end_to_end(gate):
    import addon

    class Log:
        def __init__(self):
            self.rows = []

        def log(self, *a):
            self.rows.append(a)

        def verdict(self, host):
            return None

        def video_allowed(self, host, path):
            return False

    f = addon.AIFilter.__new__(addon.AIFilter)
    f.yt, f._store = gate, Log()
    f.cfg = type("C", (), {"get": lambda self, *a: a[-1]})()
    f._text_only = lambda flow: False
    f._trusted = lambda flow: False
    p = tflow.tflow(resp=True)
    p.request.scheme, p.request.port = "https", 443
    p.request.host, p.request.path = "youtubei.googleapis.com", "/youtubei/v1/player?id=mIlix_3dKsk"
    p.client_conn.sni = "youtubei.googleapis.com"
    p.server_conn.address = ("youtubei.googleapis.com", 443)
    p.response = http.Response.make(200, player(OTHER, "badtoken12"), {"content-type": "application/x-protobuf"})
    asyncio.run(f._review_youtube_player(p))
    assert p.response.status_code == 403 and f._store.rows[-1][0] == "yt-blocked"
    p.response = http.Response.make(200, player(OK, "goodtoken1"), {"content-type": "application/x-protobuf"})
    asyncio.run(f._review_youtube_player(p))
    assert p.response.status_code == 200 and f._store.rows[-1][0] == "yt-approved"
    s = tflow.tflow(resp=True)
    s.request.scheme, s.request.host, s.request.port = "https", "rr3---sn-x.googlevideo.com", 443
    s.request.path = "/videoplayback?expire=1&ei=goodtoken1"
    s.client_conn.sni = "rr3---sn-x.googlevideo.com"
    s.server_conn.address = ("rr3---sn-x.googlevideo.com", 443)
    assert f._video_allowed(s)
    s.request.path = "/videoplayback?expire=1&ei=badtoken12"
    assert not f._video_allowed(s)


def test_yt_channels_resolve_and_save(tmp_path):
    page = '<link rel="canonical" href="https://www.youtube.com/channel/%s"><meta property="og:title" content="JEM">' % OK
    assert yt_channels.resolve("@jem", fetch=lambda u: page) == (OK, "JEM")
    assert yt_channels.resolve(OK) == (OK, "")
    with pytest.raises(ValueError):
        yt_channels.resolve("https://evil.example/x", fetch=lambda u: page)
    f = tmp_path / "c.json"
    yt_channels.save({OK: "JEM"}, f)
    assert yt_channels.load(f) == {OK: "JEM"}


def test_description_cannot_claim_an_approved_owner(gate):
    desc = b"\x2a\x80\x01Subscribe! " + (OK.encode() + b" ") * 3
    ok, ch = gate.review_player(player(OTHER, "badtoken12", desc))
    assert not ok and ch == OTHER


def test_web_json_answer(gate):
    body = ('{"videoDetails":{"videoId":"mIlix_3dKsk","channelId":"%s","shortDescription":"%s %s %s"},'
            '"microformat":{"playerMicroformatRenderer":{"externalChannelId":"%s"}},'
            '"streamingData":{"serverAbrStreamingUrl":"https:\\/\\/rr1---sn-a.googlevideo.com\\/videoplayback?expire=1\\u0026ei=jsontoken1"}}'
            % (OK, OTHER, OTHER, OTHER, OK)).encode()
    assert gate.review_player(body) == (True, OK)
    assert gate.stream_allowed("rr1---sn-a.googlevideo.com", "https://rr1---sn-a.googlevideo.com/videoplayback?ei=jsontoken1")


def test_lookalike_stream_host_not_registered(gate):
    body = player(OK, "goodtoken1").replace(b"rr3---sn-x.googlevideo.com", b"x.evilgooglevideo.com") \
        .replace(b"manifest.googlevideo.com", b"manifest.evilgooglevideo.com")
    assert gate.review_player(body) == (False, OK)


def test_removing_a_channel_revokes_open_streams(gate, tmp_path):
    assert gate.review_player(player(OK, "goodtoken1"))[0]
    url = "https://rr3---sn-x.googlevideo.com/videoplayback?ei=goodtoken1"
    assert gate.stream_allowed("rr3---sn-x.googlevideo.com", url)
    import os
    gate._file.write_text("{}")
    os.utime(gate._file, (2000, 2000))
    assert not gate.stream_allowed("rr3---sn-x.googlevideo.com", url)


def test_spoofed_player_source_registers_nothing(gate):
    import addon

    class Log:
        rows = []

        def log(self, *a):
            self.rows.append(a)

        def verdict(self, host):
            return None

    f = addon.AIFilter.__new__(addon.AIFilter)
    f.yt, f._store = gate, Log()
    p = tflow.tflow(resp=True)
    p.request.scheme, p.request.host = "http", "attacker.example"
    p.request.headers["host"] = "www.youtube.com"
    p.request.path = "/youtubei/v1/player"
    p.response = http.Response.make(200, player(OK, "goodtoken1"), {})
    asyncio.run(f._review_youtube_player(p))
    assert p.response.status_code == 403
    assert not gate.stream_allowed("rr3---sn-x.googlevideo.com", "https://rr3---sn-x.googlevideo.com/videoplayback?ei=goodtoken1")


def test_initplayback_by_video_id_and_no_borrowed_token(gate):
    assert gate.review_player(player(OK, "goodtoken1"))[0]
    # the manifest path in the answer carries /id/98...; use a realistic hex id
    body = player(OK, "goodtoken2").replace(b"/id/98", b"/id/7117274744fdaabc")
    assert gate.review_player(body)[0]
    assert gate.stream_allowed("rr6---sn-x.googlevideo.com",
                               "https://rr6---sn-x.googlevideo.com/initplayback?source=youtube&c=IOS&id=7117274744fdaabc")
    # an unapproved stream cannot borrow an approved token: its own id is unknown
    assert not gate.stream_allowed("rr3---sn-x.googlevideo.com",
                                   "https://rr3---sn-x.googlevideo.com/videoplayback?ei=goodtoken1&id=o-UNKNOWN99")


def test_ios_server_abr_segments_keep_approved_event_across_track_and_cdn_changes(gate):
    """Replay the approved-player then changing-CDN sequence from the iPhone stall."""
    body = player(OK, "yaX8arSnEL6y8uMP3Zbn8Q0").replace(
        b"source=youtube", b"source=youtube&sabr=1")
    assert gate.review_player(body) == (True, OK)

    first = ("https://rr1---sn-ajua89-5x.googlevideo.com/videoplayback?"
             "source=youtube&sabr=1&ei=yaX8arSnEL6y8uMP3Zbn8Q0&id=o-FIRSTTRACK")
    fallback = ("https://r1---sn-u15hn5-58.googlevideo.com/videoplayback?"
                "source=youtube&sabr=1&ei=yaX8arSnEL6y8uMP3Zbn8Q0&id=o-LATERTRACK&range=1048576-2097151")
    assert gate.stream_allowed("rr1---sn-ajua89-5x.googlevideo.com", first)
    assert gate.stream_allowed("r1---sn-u15hn5-58.googlevideo.com", fallback)

    # The exception is not a general permission to borrow an approved ei.
    assert not gate.stream_allowed("r1---sn-u15hn5-58.googlevideo.com", fallback.replace("sabr=1&", ""))
    assert not gate.stream_allowed("r1---sn-u15hn5-58.googlevideo.com", fallback.replace("yaX8arSnEL6y8uMP3Zbn8Q0", "unapproved1"))
    assert not gate.stream_allowed("r1---sn-u15hn5-58.googlevideo.com", fallback.replace("/videoplayback", "/initplayback"))
    gate.now[0] += ytgate.TOKEN_TTL + 1
    assert not gate.stream_allowed("r1---sn-u15hn5-58.googlevideo.com", fallback)


def test_allowed_ump_redirect_registers_new_sabr_identity_without_buffering(gate):
    """The first allowed SABR response may reload onto a new event and media id."""
    import addon

    class Store:
        def log(self, *args):
            pass

        def verdict(self, host):
            return None

    flt = addon.AIFilter.__new__(addon.AIFilter)
    flt.yt, flt._store = gate, Store()
    flt.cfg = type("C", (), {"get": lambda self, *args: args[-1]})()
    flt._text_only = lambda flow: False
    flt._trusted = lambda flow: False
    initial_ei = "Dtf8aurGI_Xbp-oPwqT36Ag"
    approved = player(OK, initial_ei).replace(
        b"source=youtube", b"source=youtube&sabr=1")
    assert gate.review_player(approved) == (True, OK)

    flow = tflow.tflow(resp=True)
    host = "rr2---sn-ivuoxu-ua8s.googlevideo.com"
    flow.request.scheme, flow.request.host, flow.request.port = "https", host, 443
    flow.request.path = f"/videoplayback?sabr=1&ei={initial_ei}&id=o-FIRST"
    flow.client_conn.sni = host
    flow.server_conn.address = (host, 443)
    flow.response = http.Response.make(200, b"", {"content-type": "application/vnd.yt-ump"})
    flt.responseheaders(flow)
    assert callable(flow.response.stream)  # media is still streamed, never retained whole

    redirected = (b"https://r2---sn-u1ua85-5i.googlevideo.com/videoplayback?"
                  b"sabr=1&rn=2&fallback_count=1&ei=Dtf8arquMqunp-oPlbCz4Q8&id=o-AD5PsFNU")
    framed = b"\x12" + bytes([len(redirected)]) + redirected + b"\x18\x01"
    assert flow.response.stream(framed[:50]) == framed[:50]
    assert flow.response.stream(framed[50:]) == framed[50:]
    followup = redirected.decode()
    assert gate.stream_allowed("r2---sn-u1ua85-5i.googlevideo.com", followup)

    blocked = tflow.tflow(resp=True)
    blocked.request.scheme, blocked.request.host, blocked.request.port = "https", host, 443
    blocked.request.path = "/videoplayback?sabr=1&ei=unapprovedEvent&id=o-UNKNOWNTRACK"
    blocked.client_conn.sni = host
    blocked.server_conn.address = (host, 443)
    blocked.response = http.Response.make(200, framed, {"content-type": "application/vnd.yt-ump"})
    flt.responseheaders(blocked)
    assert blocked.response.status_code == 403
    assert not callable(blocked.response.stream)  # a blocked response is never an authority

    # Delegation inherits the original player's deadline rather than extending
    # approval whenever another CDN response is received.
    gate.now[0] += ytgate.TOKEN_TTL + 1
    assert not gate.stream_allowed("r2---sn-u1ua85-5i.googlevideo.com", followup)


def test_ump_redirect_parser_rejects_partial_and_non_googlevideo_urls():
    good = (b"https://r2---sn-u1ua85-5i.googlevideo.com/videoplayback?"
            b"sabr=1&ei=redirectEvent1&id=o-REDIRECT")
    assert ytgate.ump_redirect_keys(good[:60]) == set()
    assert ytgate.ump_redirect_keys(good + b"\x00") == {
        "ei:redirectEvent1", "id:o-REDIRECT", "sabr:redirectEvent1"
    }
    evil = good.replace(b"googlevideo.com", b"googlevideo.com.evil.example")
    assert ytgate.ump_redirect_keys(evil + b"\x00") == set()


def test_ios_music_audio_keeps_approved_id_across_event_and_cdn_changes(gate):
    """The Music app renews ei after ten seconds but keeps the approved media id."""
    approved = player(OK, "playerEvent1").replace(b"id=o-AB", b"id=o-AF_approvedAudio")
    assert gate.review_player(approved) == (True, OK)

    followup = ("https://rr5---sn-ivuoxu-ua86.googlevideo.com/videoplayback?"
                "expire=1&ei=nextEvent22&id=o-AF_approvedAudio&mime=audio%2Fmp4&range=0-999")
    fallback = followup.replace("rr5---sn-ivuoxu-ua86", "r1---sn-u1ua85-5i")
    assert gate.stream_allowed("rr5---sn-ivuoxu-ua86.googlevideo.com", followup)
    assert gate.stream_allowed("r1---sn-u1ua85-5i.googlevideo.com", fallback)

    # Neither a borrowed player event nor a different media id opens a song.
    assert not gate.stream_allowed("r1---sn-u1ua85-5i.googlevideo.com",
                                   followup.replace("o-AF_approvedAudio", "o-AF_unapprovedSong"))
    assert not gate.stream_allowed("r1---sn-u1ua85-5i.googlevideo.com",
                                   followup.replace("nextEvent22", "playerEvent1")
                                   .replace("o-AF_approvedAudio", "o-AF_unapprovedSong"))


def test_music_app_plays_without_approval_only_while_enabled(gate):
    assert ytgate.is_music_app({"user-agent": "com.google.ios.youtubemusic/9.45.2 (iPhone16,1)", "x-youtube-client-name": "26"})
    assert not ytgate.is_music_app({"user-agent": "com.google.ios.youtube/21.45.4", "x-youtube-client-name": "26"})
    assert not ytgate.is_music_app({"user-agent": "com.google.ios.youtubemusic/9.45.2", "x-youtube-client-name": "5"})
    gate.music_enabled = True
    assert gate.review_player(player(OTHER, "musictok1"), music=True) == (True, OTHER)
    url = "https://rr3---sn-x.googlevideo.com/videoplayback?ei=musictok1"
    assert gate.stream_allowed("rr3---sn-x.googlevideo.com", url)
    gate.music_enabled = False
    assert not gate.stream_allowed("rr3---sn-x.googlevideo.com", url)
    assert gate.review_player(player(OTHER, "musictok2"), music=False)[0] is False


def test_streams_survive_a_restart_but_still_follow_the_list(tmp_path):
    f = tmp_path / "ch.json"
    f.write_text(json.dumps({OK: "JEM"}))
    tok = tmp_path / "tokens.json"
    now = [1000.0]
    g = ytgate.Gate(f, clock=lambda: now[0], tokens_file=tok)
    assert g.review_player(player(OK, "goodtoken1"))[0]
    url = "https://rr3---sn-x.googlevideo.com/videoplayback?ei=goodtoken1&id=o-AB"
    g2 = ytgate.Gate(f, clock=lambda: now[0], tokens_file=tok)  # the filter restarted
    assert g2.stream_allowed("rr3---sn-x.googlevideo.com", url)
    f.write_text("{}")
    import os
    os.utime(f, (5000, 5000))
    assert not g2.stream_allowed("rr3---sn-x.googlevideo.com", url)  # removed channel: revoked as before
    tok.write_text(json.dumps({"ei:forged1234": [now[0] + 10 * ytgate.TOKEN_TTL, OK]}))
    assert ytgate.Gate(f, clock=lambda: now[0], tokens_file=tok)._tokens == {}  # beyond the lifetime: dropped
    tok.write_text("{broken")
    assert ytgate.Gate(f, clock=lambda: now[0], tokens_file=tok)._tokens == {}


def test_is_youtube_api():
    assert ytgate.is_youtube_api("youtubei.googleapis.com", "/youtubei/v1/reel/reel_item_watch?x=1")
    assert not ytgate.is_youtube_api("evil.example", "/youtubei/v1/next")


from test_filter import store  # noqa: E402,F401


def test_onesie_initplayback_post_is_refused(store):
    from test_filter import flow_for, make_filter
    flt = make_filter(store)
    flow = flow_for("https://rr2---sn-ivuoxu-ua8s.googlevideo.com/initplayback?source=youtube&c=IOS&id=0b4a72f30881097c")
    flow.request.method = "POST"
    flow.response = None
    flt.request(flow)
    assert flow.response is not None and flow.response.status_code == 403
    # GET initplayback (server selection) is not refused here.
    get = flow_for("https://redirector.googlevideo.com/initplayback?source=youtube&itag=0")
    get.response = None
    flt.request(get)
    assert get.response is None or get.response.status_code != 403
