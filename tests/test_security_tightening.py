"""Acceptance coverage for the 2026-11 passthrough and Music tightening."""
import json
import re
import tomllib
from pathlib import Path

from aifilter import ytgate

ROOT = Path(__file__).resolve().parent.parent


def test_passthrough_and_night_allow_entries_are_justified(policy_config_path):
    text = policy_config_path.read_text()
    for section, key in (("passthrough", "hosts"), ("schedule", "night_allow")):
        block = re.search(rf"\[{section}\].*?\b{key}\s*=\s*\[(.*?)\n\]", text, re.S).group(1)
        for line in block.splitlines():
            if re.search(r'"[^"\n]+"', line):
                assert re.search(r"#\s*(?:pins|reason):", line), line


def test_unreviewed_media_hosts_are_not_passthrough_or_night_allowed(policy_config_path):
    cfg = tomllib.loads(policy_config_path.read_text())
    passed = cfg["passthrough"]["hosts"]
    night = cfg["schedule"]["night_allow"]
    for host in ("t.me", "telegram.me", "telesco.pe", "oaiusercontent.com"):
        assert host not in passed
    assert "icloud-content.com" in passed  # device backup and Photos sync; Apple pins it (coordinator, PR #49)
    for host in ("t.me", "telegram.me", "telesco.pe", "oaiusercontent.com"):
        assert host not in night
    assert {"chatgpt.com", "openai.com", "oaistatic.com"} <= set(passed)
    assert {"whatsapp.net", "manageengine.com", "bank-1.example"} <= set(passed)


# Pinned Apple services stay opaque: decrypting any of them breaks the supervised iPhone/iPad.
PINNED_APPLE = ("gsa.apple.com", "identity.apple.com", "mdmenrollment.apple.com", "deviceenrollment.apple.com",
                "albert.apple.com", "iprofiles.apple.com", "1-courier.push.apple.com", "init.ess.apple.com",
                "iosapps.itunes.apple.com", "mesu.apple.com", "p25-ckdatabase.icloud.com", "gateway.icloud.com",
                "setup.icloud.com", "p42-fmip.icloud.com", "api.apple-cloudkit.com", "cvws.icloud-content.com",
                "p23-sharedstreams.icloud.com")  # Shared Albums device sync (Photos app), pinned
OPEN_MEDIA = ("www.icloud.com", "share.icloud.com", "ckdatabasews.icloud.com", "p31-ckdatabasews.icloud.com",
              "images.openai.com", "files.oaiusercontent.com",
              "sdmntprwestus.oaiusercontent.com", "t.me", "telesco.pe")


def _filter(tmp_path):
    from aifilter.store import Store
    from test_filter import make_filter
    return make_filter(Store(tmp_path / "t.db"))


def test_pinned_apple_services_stay_passthrough(tmp_path):
    flt = _filter(tmp_path)
    for host in PINNED_APPLE:
        assert flt._passthrough_name(host), host
        assert flt._static_passthrough(host), host


def test_open_media_hosts_are_inspected(tmp_path):
    flt = _filter(tmp_path)
    for host in OPEN_MEDIA:
        assert not flt._passthrough_name(host), host


def test_inspect_hosts_beat_a_runtime_passthrough_row(tmp_path):
    flt = _filter(tmp_path)
    flt.store.add_passthrough("icloud.com", "test")
    flt.store.add_passthrough("www.icloud.com", "test")
    assert not flt._passthrough_name("www.icloud.com")
    assert not flt._passthrough_name("p7-ckdatabasews.icloud.com")
    assert flt._passthrough_name("p7-sharedstreams.icloud.com")
    assert flt._passthrough_name("p7-ckdatabase.icloud.com")


def test_inspect_patterns_are_exact_and_stay_inside_one_label():
    from aifilter.schedules import host_listed
    patterns = ["www.icloud.com", "*-sharedstreams.icloud.com"]
    assert host_listed("WWW.iCloud.com.", patterns)
    assert host_listed("p123-sharedstreams.icloud.com", patterns)
    assert not host_listed("x.www.icloud.com", patterns)
    assert not host_listed("a.p1-sharedstreams.icloud.com", patterns)
    assert not host_listed("icloud.com", patterns)
    assert not host_listed("gsa.apple.com", patterns)


def test_removing_a_carve_out_counts_as_loosening():
    from scripts.check_config_loosening import loosenings
    old = {"passthrough": {"inspect_hosts": ["www.icloud.com"]}, "schedule": {"night_except": ["share.icloud.com"]}}
    new = {"passthrough": {"inspect_hosts": []}, "schedule": {"night_except": []}}
    assert loosenings(old, new) == ["passthrough.inspect_hosts-=www.icloud.com",
                                    "schedule.night_except-=share.icloud.com"]
    assert loosenings(new, old) == []


def test_tls_watch_reports_but_never_auto_passes_an_inspected_host(tmp_path, monkeypatch, policy_config_path):
    import sys
    sys.path.insert(0, str(ROOT / "scripts"))
    import tls_watch
    from aifilter import config
    from aifilter.store import Store
    policy = config.load(policy_config_path)
    monkeypatch.setattr(tls_watch, "static_passthrough", lambda: policy.get("passthrough", "hosts", []))
    monkeypatch.setattr(tls_watch, "inspect_hosts", lambda: policy.get("passthrough", "inspect_hosts", []))
    store = Store(tmp_path / "f.db")
    for _ in range(3):
        store.record_tls_failure("p9-ckdatabasews.icloud.com")
        store.record_tls_failure("gateway.icloud.com")
    reports = []
    out = tls_watch.run(store, tmp_path / "state.json", dig=lambda *a: ["a.ns.apple.com"],
                        report=lambda h, c: reports.append(h))
    assert out["auto"] == [] and reports == ["p9-ckdatabasews.icloud.com"]
    assert "icloud.com" not in store.passthrough_hosts()


# All formats of one answer share the event (`ei`) and content (`id`) keys, so the grant cannot rely on them.
EI, ID = "sharedevent1", "sharedcontent1"
BASE = f"https://r1.googlevideo.com/videoplayback?ei={EI}&id={ID}"
AUDIO = BASE + "&itag=140&mime=audio%2Fmp4"
VIDEO = BASE + "&itag=137&mime=video%2Fmp4"


def _audio_grant():
    gate = ytgate.Gate(ROOT / "data/youtube-channels.json", tokens_file=None)
    gate.music_enabled = True
    body = json.dumps({"streamingData": {"adaptiveFormats": [
        {"itag": 137, "mimeType": "video/mp4", "url": VIDEO},
        {"itag": 140, "mimeType": "audio/mp4", "url": AUDIO},
    ]}}).encode()
    assert gate.review_player(body, music=True, audio_only=True)[0]
    assert gate._tokens[f"ei:{EI}"][1] == ytgate.MUSIC_AUDIO
    return gate


def test_unknown_music_json_registers_only_audio_format():
    gate = _audio_grant()
    assert gate.stream_authorization("r1.googlevideo.com", AUDIO)[0] == ytgate.MUSIC_AUDIO
    assert gate.stream_authorization("r1.googlevideo.com", VIDEO) is None


def test_audio_grant_bypasses_are_denied():
    gate = _audio_grant()
    host = "r1.googlevideo.com"
    assert gate.stream_authorization(host, BASE + "&itag=137") is None  # no mime at all
    path_video = f"https://{host}/videoplayback/ei/{EI}/id/{ID}/itag/137/mime/video%2Fmp4/"
    assert gate.stream_authorization(host, path_video) is None  # path-form video mime
    path_audio = f"https://{host}/videoplayback/ei/{EI}/id/{ID}/itag/140/mime/audio%2Fmp4/"
    assert gate.stream_authorization(host, path_audio)
    assert gate.stream_authorization(host, path_audio + "?mime=video%2Fmp4") is None  # mixed labels
    assert gate.stream_authorization(host, VIDEO + "&sabr=1") is None  # server ABR with a video label
    assert gate.stream_authorization(host, BASE + "&sabr=1")  # SABR: the UMP guard checks every header
    gate.music_enabled = False
    assert gate.stream_authorization(host, AUDIO) is None


def test_music_marker_never_authorizes_video_mime():
    gate = ytgate.Gate(ROOT / "data/youtube-channels.json", tokens_file=None)
    gate.music_enabled = True
    assert gate.register_streams({f"ei:{EI}"}, ytgate.MUSIC)
    assert gate.stream_authorization("r1.googlevideo.com", f"https://r1.googlevideo.com/videoplayback?ei={EI}"
                                                           "&mime=audio%2Fmp4")
    assert gate.stream_authorization("r1.googlevideo.com", f"https://r1.googlevideo.com/videoplayback?ei={EI}"
                                                           "&mime=video%2Fmp4") is None


def test_audio_grant_response_must_be_audio(tmp_path):
    from mitmproxy import http
    from aifilter.store import Store
    from test_filter import flow_for, make_filter
    flt = make_filter(Store(tmp_path / "t.db"))
    flt.yt._tokens_file = None  # never write the repository's live data/yt-tokens.json
    flt.yt.music_enabled = True
    assert flt.yt.register_streams({f"ei:{EI}", f"id:{ID}"}, ytgate.MUSIC_AUDIO)
    for ctype, blocked in (("video/mp4", True), ("application/octet-stream", True), ("audio/mp4", False)):
        f = flow_for(AUDIO, ctype, b"\0" * 64)
        f.metadata["yt_stream_authorization"] = flt.yt.stream_authorization("r1.googlevideo.com", AUDIO)
        flt.responseheaders(f)
        assert (f.response.status_code == 403) is blocked, ctype
        assert isinstance(f.response, http.Response)


def test_unknown_music_protobuf_registers_only_audio_itag():
    def field(number, value):
        assert len(value) < 128
        return bytes((number << 3 | 2, len(value))) + value

    audio_url = AUDIO.encode()
    video_url = VIDEO.encode()
    audio_format = field(1, b"audio/mp4") + field(2, audio_url)
    video_format = field(1, b"video/mp4") + field(2, video_url)
    answer = field(1, audio_format) + field(1, video_format)
    assert ytgate.audio_stream_tokens(answer) == {f"ei:{EI}", f"id:{ID}"}
    # The keys are shared, so the video format is stopped by the request and response mime gates instead.
    gate = ytgate.Gate(ROOT / "data/youtube-channels.json", tokens_file=None)
    gate.music_enabled = True
    assert gate.register_streams(ytgate.audio_stream_tokens(answer), ytgate.MUSIC_AUDIO)
    assert gate.stream_authorization("r1.googlevideo.com", VIDEO) is None
    assert gate.stream_authorization("r1.googlevideo.com", AUDIO)


def test_inspect_hosts_and_night_except_final_lists(policy_config_path):
    cfg = tomllib.loads(policy_config_path.read_text())
    assert cfg["passthrough"]["inspect_hosts"] == ["www.icloud.com", "share.icloud.com", "ckdatabasews.icloud.com",
                                                   "*-ckdatabasews.icloud.com", "images.openai.com"]
    assert cfg["schedule"]["night_except"] == ["www.icloud.com", "share.icloud.com"]


def test_icloud_web_share_pages_are_blocked_by_path(tmp_path):
    from aifilter.store import Store
    from test_filter import flow_for, make_filter
    flt = make_filter(Store(tmp_path / "t.db"))
    for url in ("https://www.icloud.com/sharedalbum/#B0abcDEF", "https://www.icloud.com/photos/#0aBcD",
                "https://www.icloud.com/iclouddrive/0abc#file", "https://WWW.icloud.com//Photos/",
                "https://www.icloud.com/%2573haredalbum/", "https://share.icloud.com/photos/0aBcD"):
        f = flow_for(url)
        f.response = None
        flt.request(f)
        assert f.response is not None and f.response.status_code == 403, url
    for url in ("https://www.icloud.com/", "https://www.icloud.com/find", "https://www.icloud.com/mail/"):
        f = flow_for(url)
        f.response = None
        flt.request(f)
        assert f.response is None or f.response.status_code != 403, url


class _Hello:
    def __init__(self, sni, dest=None):
        from types import SimpleNamespace
        server = SimpleNamespace(address=(dest, 443), _aifilter_host=dest) if dest else None
        self.context = SimpleNamespace(client=SimpleNamespace(sni=sni, peername=("203.0.113.10", 1)), server=server)
        self.ignore_connection = False


def test_sni_and_connect_target_must_both_be_passthrough(tmp_path):
    flt = _filter(tmp_path)
    for sni, dest, opaque in (("gsa.apple.com", "gsa.apple.com", True),
                              ("gsa.apple.com", "mdmenrollment.apple.com", True),
                              ("gsa.apple.com", "www.icloud.com", False),        # inspected CONNECT target
                              ("www.icloud.com", "gsa.apple.com", False),        # inspected SNI
                              ("gsa.apple.com", "evil.example", False),
                              ("gsa.apple.com", "8.8.8.8", False),
                              ("p3-ckdatabasews.icloud.com", None, False)):
        hello = _Hello(sni, dest)
        flt.tls_clienthello(hello)
        assert hello.ignore_connection is opaque, (sni, dest)


def test_raw_tcp_refused_for_inspected_hosts(tmp_path):
    from types import SimpleNamespace
    from mitmproxy import connection
    flt = _filter(tmp_path)
    for host, allowed in (("www.icloud.com", False), ("p5-ckdatabasews.icloud.com", False),
                          ("images.openai.com", False), ("gsa.apple.com", True), ("p5-sharedstreams.icloud.com", True)):
        killed = []
        flow = SimpleNamespace(server_conn=connection.Server(address=(host, 443)), kill=lambda: killed.append(True))
        flt.tcp_start(flow)
        assert bool(killed) is not allowed, host


def test_community_list_hit_beats_an_inspected_host_but_not_a_pinned_parent(tmp_path, monkeypatch):
    flt = _filter(tmp_path)
    monkeypatch.setattr(flt.store, "listed", lambda name: True)
    assert flt._passthrough_blocked({"www.icloud.com"})        # inspected: the static exception does not protect it
    assert flt._passthrough_blocked({"images.openai.com"})
    assert not flt._passthrough_blocked({"gsa.apple.com"})     # curated passthrough still wins over a broad list


# --- YouTube Music SABR/UMP (Opus round 2): the iPhone app streams only via POST /videoplayback?sabr=1 ---
FORMATS = json.loads((ROOT / "tests/fixtures/music_sabr_formats.json").read_text())["formats"]
AUDIO_ITAGS = {f["itag"] for f in FORMATS if f["mime"].startswith("audio/")}
SABR = f"https://rr1---sn-test.googlevideo.com/videoplayback?sabr=1&ei={EI}&id={ID}&c=IOS_MUSIC"


def _pb(number, value):
    def var(v):
        out = bytearray()
        while True:
            out.append(v & 0x7f | (0x80 if v > 0x7f else 0))
            v >>= 7
            if not v:
                return bytes(out)
    if isinstance(value, int):
        return var(number << 3) + var(value)
    return var(number << 3 | 2) + var(len(value)) + value


def _sabr_answer() -> bytes:
    """The real answer's format table (fixture) in its real layout: field 4 > field 3 per format {1 itag,
    2 url, 5 mime}, plus the server-ABR URL. URLs are synthetic."""
    formats = b"".join(_pb(3, _pb(1, f["itag"]) + _pb(2, (BASE + f"&itag={f['itag']}&mime="
                                                             + f["mime"].split(";")[0].replace("/", "%2F")).encode())
                               + _pb(5, f["mime"].encode())) for f in FORMATS)
    return _pb(4, formats + _pb(19, SABR.encode()))


def _uvar(v):
    if v < 128:
        return bytes([v])
    if v < 1 << 14:
        return bytes([0x80 | v & 0x3f, v >> 6])
    if v < 1 << 21:
        return bytes([0xc0 | v & 0x1f, v >> 5 & 0xff, v >> 13])
    if v < 1 << 28:
        return bytes([0xe0 | v & 0x0f, v >> 4 & 0xff, v >> 12 & 0xff, v >> 20])
    return b"\xf0" + v.to_bytes(4, "little")


def _part(kind, payload):
    return _uvar(kind) + _uvar(len(payload)) + payload


def _segment(header_id, itag, size=300, format_id=True):
    header = _pb(1, header_id) + _pb(2, b"vid12345678") + _pb(3, itag) + (_pb(13, _pb(1, itag)) if format_id else b"")
    return (_part(20, header) + _part(21, bytes([header_id]) + bytes([0x41 + header_id % 20]) * size)
            + _part(22, bytes([header_id])))


def test_ump_varint_matches_googlevideo_encoding():
    for value in (0, 5, 127, 128, 300, 16383, 16384, 20000, (1 << 21) + 7, (1 << 28) + 9):
        assert ytgate._ump_varint(_uvar(value), 0) == (value, len(_uvar(value))), value
    assert ytgate._ump_varint(_uvar(20000)[:2], 0) is None


def test_real_music_sabr_answer_grants_server_abr_with_audio_itags():
    assert AUDIO_ITAGS == {139, 140, 141, 249, 250, 251, 774}
    answer = _sabr_answer()
    assert ytgate.audio_format_itags(answer) == AUDIO_ITAGS
    gate = ytgate.Gate(ROOT / "data/youtube-channels.json", tokens_file=None)
    gate.music_enabled = True
    assert gate.review_player(answer, music=True, audio_only=True)[0]
    assert gate.stream_authorization("rr1---sn-test.googlevideo.com", SABR)[0] == ytgate.MUSIC_AUDIO
    assert gate.audio_itags(SABR) == AUDIO_ITAGS
    assert gate.stream_authorization("rr1---sn-test.googlevideo.com", SABR + "&mime=video%2Fmp4") is None


def test_ump_guard_passes_audio_and_stops_at_the_first_video_header():
    audio = _segment(1, 251, 20000) + _segment(2, 140)
    guard = ytgate.UmpAudioGuard(AUDIO_ITAGS)
    for i in range(0, len(audio), 7):  # arbitrary chunking, headers split across chunks
        assert guard.feed(audio[i:i + 7])
    assert guard.itags == [251, 251, 140, 140]
    guard = ytgate.UmpAudioGuard(AUDIO_ITAGS)
    assert guard.feed(_segment(3, 251))
    assert not guard.feed(_segment(4, 137))  # video itag mid-stream
    assert not guard.feed(_segment(5, 251))  # stays stopped
    assert not ytgate.UmpAudioGuard(AUDIO_ITAGS).feed(_part(20, _pb(1, 6) + _pb(2, b"vid")))  # no itag
    assert not ytgate.UmpAudioGuard(AUDIO_ITAGS).feed(_part(20, b"x" * 20000))  # oversized header
    assert not ytgate.UmpAudioGuard(set()).feed(_segment(8, 251))


def _sabr_flow(flt, body=b""):
    from mitmproxy import http
    from mitmproxy.test import tflow
    flow = tflow.tflow(resp=True)
    host = "rr1---sn-test.googlevideo.com"
    flow.request.scheme, flow.request.host, flow.request.port = "https", host, 443
    flow.request.method = "POST"
    flow.request.path = SABR.split(host, 1)[1]
    flow.client_conn.sni = host
    flow.server_conn.address = (host, 443)
    flow.response = http.Response.make(200, body, {"content-type": "application/vnd.yt-ump"})
    flow.metadata["yt_stream_authorization"] = flt.yt.stream_authorization(host, SABR)
    return flow


def test_music_sabr_ump_stream_audio_passes_video_is_cut(tmp_path):
    from aifilter.store import Store
    from test_filter import make_filter
    flt = make_filter(Store(tmp_path / "t.db"))
    flt.yt._tokens_file = None  # never write the repository's live data/yt-tokens.json
    flt.yt.music_enabled = True
    assert flt.yt.review_player(_sabr_answer(), music=True, audio_only=True)[0]

    flow = _sabr_flow(flt)
    flt.responseheaders(flow)
    assert flow.response.status_code == 200 and callable(flow.response.stream)
    audio = _segment(1, 251) + _segment(2, 251)
    assert flow.response.stream(audio[:100]) == audio[:100]
    assert flow.response.stream(audio[100:]) == audio[100:]
    assert flow.error is None

    video = _segment(3, 137)
    assert flow.response.stream(video) == b""        # the chunk carrying the video header is dropped
    assert flow.response.stream(_segment(4, 251)) == b""  # and everything after it
    assert flow.error is not None and not flow.killable
    assert flow.metadata.get("aifilter_blocked")

    other = _sabr_flow(flt)
    other.response.headers["content-type"] = "video/mp4"
    flt.responseheaders(other)
    assert other.response.status_code == 403


def test_icloud_share_paths_resolve_dot_segments_and_cover_iwork(tmp_path):
    from aifilter.store import Store
    from test_filter import flow_for, make_filter
    flt = make_filter(Store(tmp_path / "t.db"))
    for url in ("https://www.icloud.com/find/../sharedalbum/#B0x", "https://www.icloud.com/./x/%2e%2e/photos/",
                "https://www.icloud.com/keynote/0abc#deck", "https://www.icloud.com/pages/0abc",
                "https://www.icloud.com/numbers/0abc", "https://www.icloud.com/freeform/0abc"):
        f = flow_for(url)
        f.response = None
        flt.request(f)
        assert f.response is not None and f.response.status_code == 403, url
    f = flow_for("https://www.icloud.com/photos/../find")
    f.response = None
    flt.request(f)
    assert f.response is None or f.response.status_code != 403


# --- Opus round 3: compressed UMP and a positive header-id check ---
def test_ump_guard_requires_an_approved_header_id_for_every_media_part():
    ok = ytgate.UmpAudioGuard(AUDIO_ITAGS)
    legit = _segment(1, 251) + _segment(2, 140, 20000) + _segment(1, 251)
    for i in range(0, len(legit), 5):
        assert ok.feed(legit[i:i + 5])
    assert ok.header_ids == {1, 2}
    assert not ytgate.UmpAudioGuard(AUDIO_ITAGS).feed(_part(21, b"\x01" + b"A" * 50))  # media without header
    unknown = ytgate.UmpAudioGuard(AUDIO_ITAGS)
    assert unknown.feed(_segment(1, 251))
    assert not unknown.feed(_part(21, b"\x07" + b"A" * 50))  # media naming an unknown header id
    video_then_media = ytgate.UmpAudioGuard(AUDIO_ITAGS)
    assert not video_then_media.feed(_segment(3, 137))
    no_id = ytgate.UmpAudioGuard(AUDIO_ITAGS)
    assert not no_id.feed(_part(20, _pb(3, 251)) + _part(21, b"\x00" + b"A" * 10))  # header without id
    assert not ytgate.UmpAudioGuard(AUDIO_ITAGS).feed(_part(21, b""))  # empty media part


def test_compressed_music_ump_is_refused_and_accept_encoding_is_stripped(tmp_path):
    import gzip
    from aifilter.store import Store
    from test_filter import flow_for, make_filter
    flt = make_filter(Store(tmp_path / "t.db"))
    flt.yt._tokens_file = None
    flt.yt.music_enabled = True
    assert flt.yt.review_player(_sabr_answer(), music=True, audio_only=True)[0]

    request = flow_for(SABR)
    request.response = None
    request.request.headers["accept-encoding"] = "gzip, deflate, br"
    flt.request(request)
    assert "accept-encoding" not in request.request.headers

    for encoding in ("gzip", "br", "deflate", "x-unknown"):
        flow = _sabr_flow(flt, gzip.compress(_segment(1, 137)))
        flow.response.headers["content-encoding"] = encoding
        flt.responseheaders(flow)
        assert flow.response.status_code == 403, encoding
        assert not callable(flow.response.stream)
    plain = _sabr_flow(flt)
    plain.response.headers["content-encoding"] = "identity"
    flt.responseheaders(plain)
    assert plain.response.status_code == 200 and callable(plain.response.stream)
    assert plain.response.stream(_segment(1, 251)) == _segment(1, 251)
