"""YouTube by approved channels only (maintainer decision).

How it holds: the app first asks YouTube's API for a video (`/youtubei/v1/player?id=<video>`). That answer
names the video's channel (its `UC...` id, repeated) and carries the video's stream addresses, all stamped with
one event token (`ei`). When the channel is on the committee's list we remember that token for a few hours;
the video gate then lets through only googlevideo.com streams whose `ei` we remember. Anything else (other
channels, Shorts and feed previews that never came through an approved player answer, streams without a
token) stays blocked by the normal video rule. Fails closed: an unclear channel or a missing token is a no.

The list lives in data/youtube-channels.json ({"UC...": "name"}), edited with scripts/yt_channels.py.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

CHANNELS_FILE = Path(__file__).resolve().parent.parent / "data" / "youtube-channels.json"
TOKENS_FILE = Path(__file__).resolve().parent.parent / "data" / "yt-tokens.json"  # survives a filter restart
TOKEN_TTL = 6 * 3600  # stream addresses expire after about 6 hours
MAX_TOKENS = 5000
MAX_PLAYER_BYTES = 3_000_000  # a real player answer is ~40 KB
MAX_TOKENS_PER_ANSWER = 24
MAX_UMP_INSPECT_BYTES = 256 * 1024  # redirects are control messages near the start, never media-sized

# Only structured owner fields count, never free text (a description could quote an approved id):
# protobuf: a 24-byte string field (length byte 0x18); JSON: "channelId" / "externalChannelId" values.
_CHANNEL = re.compile(rb"(?:(?<=\x18)|(?<=\"channelId\":\")|(?<=\"externalChannelId\":\"))(UC[A-Za-z0-9_-]{22})")
MUSIC = "music-app"  # registration marker: a YouTube Music app answer, admitted while music is enabled
# Registration marker for a Music answer whose song type is unreadable: only its explicitly audio-labelled
# formats are registered. A request passes with an explicit audio/ mime (never mime-less), or as server-ABR whose
# UMP response is checked header by header against the answer's audio itags (UmpAudioGuard).
MUSIC_AUDIO = "music-audio"
CHECKED = "ai-checked"  # registration marker: a video the AI check passed (aifilter/ytcheck.py), admitted while that check is on
_CHANNEL_ID = re.compile(r"UC[A-Za-z0-9_-]{22}")
_STREAM_URL = re.compile(rb"https://[A-Za-z0-9.-]+/[\x21\x23-\x26\x28-\x5b\x5d-\x7e]{0,2000}")  # stops at quotes and backslashes
_EI = re.compile(r"^[A-Za-z0-9_-]{8,96}$")
_VIDEO_ID = re.compile(r"[A-Za-z0-9_-]{11}")
_MUSIC_WARMUP_ID = "0000000000001f13"
_GOOGLEVIDEO_EDGE = re.compile(r"r{1,2}\d+---sn-[a-z0-9-]+\.googlevideo\.com")
_YTIMG_COVER = re.compile(r"/vi(?:_webp)?/[A-Za-z0-9_-]{11}/[a-zA-Z0-9_-]+\.(?:jpg|webp)")
_MUSIC_ALBUM_ART = re.compile(r"/[A-Za-z0-9_-]+(?:=[A-Za-z0-9_-]+)?")
YT_IMAGE_HOSTS = {"i.ytimg.com", "i9.ytimg.com", "yt3.googleusercontent.com"}
MAX_EMBEDDED = 16  # players reviewed in one answer; more fails closed


def is_player_api(host: str, path: str) -> bool:
    host = (host or "").lower().rstrip(".")
    api = host == "youtubei.googleapis.com" or host == "youtube.com" or host.endswith(".youtube.com")
    return api and urlsplit(path or "").path.rstrip("/") == "/youtubei/v1/player"


def answer_names_video(body: bytes, video: str) -> bool:
    """The player answer itself names this video in a structured field (protobuf: an 11-byte string field;
    JSON: "videoId"). Binds an AI check of `video` to the answer whose streams get registered."""
    v = (video or "").encode()
    return len(v) == 11 and (b"\x0b" + v in body or b'"videoId":"' + v + b'"' in _unescape(body))


def music_video_type(body: bytes) -> str:
    """Read the structured type from a bounded JSON player response, or fail closed."""
    try:
        if not body or len(body) > MAX_PLAYER_BYTES:
            return ""
        details = json.loads(body)["videoDetails"]
    except (ValueError, TypeError, KeyError, UnicodeDecodeError, RecursionError):
        return ""  # not a readable JSON answer (protobuf): the caller decides
    value = details.get("musicVideoType") if isinstance(details, dict) else None
    # A readable answer without a song type is not a song: fail closed.
    return value if isinstance(value, str) and value else "missing"


def is_youtube_api(host: str, path: str) -> bool:
    host = (host or "").lower().rstrip(".")
    api = host == "youtubei.googleapis.com" or host == "youtube.com" or host.endswith(".youtube.com")
    return api and urlsplit(path or "").path.startswith("/youtubei/v1/")


# Answers kept whole for review: the player itself and the answers known to embed player responses.
# Every other youtubei answer streams as before (bounded buffering, review round 2 P2).
REVIEWED_API = ("/youtubei/v1/player", "/youtubei/v1/next", "/youtubei/v1/reel/")


def is_reviewed_api(host: str, path: str) -> bool:
    if not is_youtube_api(host, path):
        return False
    p = urlsplit(path or "").path.rstrip("/")
    return any(p == r.rstrip("/") or (r.endswith("/") and p.startswith(r)) for r in REVIEWED_API)


def is_music_app(headers) -> bool:
    """The iOS YouTube Music app (client IOS_MUSIC = 26, its own User-Agent). Both must agree."""
    ua = (headers.get("user-agent") or "").lower()
    return ua.startswith("com.google.ios.youtubemusic/") and (headers.get("x-youtube-client-name") or "") in ("26", "IOS_MUSIC")


def music_cover(host: str, path: str, headers) -> bool:
    """Recognize raster cover requests on the two YouTube image CDNs used by iOS Music."""
    if not (headers.get("user-agent") or "").lower().startswith("com.google.ios.youtubemusic/"):
        return False
    # CDN requests can omit the API client header; an explicit other client is never Music.
    if headers.get("x-youtube-client-name", "") not in ("", "26", "IOS_MUSIC"):
        return False
    if host not in YT_IMAGE_HOSTS:
        return False
    pattern = _MUSIC_ALBUM_ART if host == "yt3.googleusercontent.com" else _YTIMG_COVER
    return bool(pattern.fullmatch(path))


_WARMUP_KEYS = {"c", "source", "id", "itag", "pai", "pvi", "cmo", "owc"}


def _initplayback_query(target: str, client: str) -> dict | None:
    """The single-valued query of a GET /initplayback from one named client, or None."""
    try:
        parts = urlsplit(target)
        if parts.path != "/initplayback":
            return None
        query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=48)
    except (ValueError, UnicodeError):
        return None
    if (query.get("c") != [client] or query.get("source") != ["youtube"]
            or any(len(values) != 1 for values in query.values())):
        return None
    return query


def _is_warmup(host: str, query: dict) -> bool:
    """The periodic redirector probe with the reserved dummy id: it names no video and asks for no format."""
    return (host == "redirector.googlevideo.com" and query.get("id") == [_MUSIC_WARMUP_ID]
            and query.get("itag") == ["0"] and query.get("pai") == query.get("pvi") == ["0"]
            and query.keys() <= _WARMUP_KEYS)


def is_youtube_app(headers) -> bool:
    """The regular iOS YouTube app, or a CDN request without identification. An explicit other client never is."""
    ua = (headers.get("user-agent") or "").lower()
    return ((not ua or ua.startswith("com.google.ios.youtube/"))
            and (headers.get("x-youtube-client-name") or "") in ("", "5", "IOS"))


def app_warmup(host: str, target: str) -> bool:
    """The regular iOS YouTube app's dummy redirector warm-up (c=IOS, id=0000000000001f13).

    Upstream it can only be refused (no player answer names the dummy id), so the app retried it every ~25 s
    all day (2026-11-19). It is answered locally with an empty 204: no media, no redirect, no stream key."""
    query = _initplayback_query(target, "IOS")
    return query is not None and _is_warmup(host, query)


def music_init_control(host: str, target: str) -> str | None:
    """Identify iOS Music setup GETs that can be handled without granting any media access."""
    query = _initplayback_query(target, "IOS_MUSIC")
    if query is None:
        return None
    video_id = query.get("id", [""])[0]
    no_prefetch = query.get("pai") == query.get("pvi") == ["0"]
    if host == "redirector.googlevideo.com":
        if _is_warmup(host, query):
            return "warmup"
    elif (_GOOGLEVIDEO_EDGE.fullmatch(host) and video_id != _MUSIC_WARMUP_ID
          and _EI.fullmatch(video_id) and (no_prefetch or ("ack" in query and query.get("opr") == ["1"]))):
        return "edge"
    return None


def is_stream_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return host == "googlevideo.com" or host.endswith(".googlevideo.com")


def player_channel(body: bytes) -> str | None:
    """The channel that owns the video in a player answer (JSON or protobuf), or None when unclear.
    The owner's id appears at least twice (details + microformat); other ids (an endscreen, a card) at most once."""
    counts = Counter(_CHANNEL.findall(_unescape(body))).most_common(2)
    if not counts or counts[0][1] < 2 or (len(counts) > 1 and counts[1][1] >= counts[0][1]):
        return None
    return counts[0][0].decode()


def _unescape(body: bytes) -> bytes:
    """Web JSON escapes '&' and '/' inside strings; protobuf is left as is."""
    return (body or b"").replace(b"\\u0026", b"&").replace(b"\\/", b"/")


def stream_keys(url: str) -> set[str]:
    """Every identifying value of a googlevideo.com address: its `ei` event token and its `id` (query or
    path form, e.g. `/ei/<token>/`, `/id/<hex>/`). A stream passes only when all of them were registered."""
    try:
        parts = urlsplit(url)
        query = parse_qs(parts.query)
    except ValueError:
        return set()
    segs = parts.path.split("/")
    keys = set()
    for name in ("ei", "id"):
        vals = list(query.get(name) or [])
        vals += [segs[i + 1] for i, seg in enumerate(segs[:-1]) if seg == name]
        keys |= {f"{name}:{v}" for v in vals if _EI.fullmatch(v)}
    return keys


def request_mimes(parts, query) -> list[str]:
    """Every mime label of a googlevideo request, query (`mime=`) and path (`/mime/<value>/`) forms."""
    segs = parts.path.split("/") if parts else []
    vals = list(query.get("mime") or []) + [segs[i + 1] for i, seg in enumerate(segs[:-1]) if seg == "mime"]
    return [unquote(v).lower() for v in vals]


def audio_only_request(parts, query) -> bool:
    """A MUSIC_AUDIO grant admits a request labelled audio/ in every mime field, or a server-ABR request
    (no video label) whose UMP response is then checked header by header against the audio itags."""
    mimes = request_mimes(parts, query)
    if any(not m.startswith("audio/") for m in mimes):
        return False
    sabr = bool(parts) and parts.path == "/videoplayback" and query.get("sabr") == ["1"]
    return sabr or bool(mimes)


def stream_token(url: str) -> str | None:  # kept for callers that want the event token alone
    eis = {k[3:] for k in stream_keys(url) if k.startswith("ei:")}
    return eis.pop() if len(eis) == 1 else None


def _protobuf_fields(data: bytes):
    """Parse protobuf fields enough to inspect nested length-delimited format messages."""
    out = []
    pos = 0

    def varint(at):
        value = 0
        for shift in range(0, 70, 7):
            if at >= len(data):
                raise ValueError
            byte = data[at]
            at += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, at
        raise ValueError
    try:
        while pos < len(data):
            key, pos = varint(pos)
            wire = key & 7
            if not key >> 3 or wire in (3, 4):
                return None
            if wire == 0:
                _, pos = varint(pos)
            elif wire == 1:
                pos += 8
            elif wire == 2:
                size, pos = varint(pos)
                if pos + size > len(data):
                    return None
                out.append((key >> 3, data[pos:pos + size]))
                pos += size
            elif wire == 5:
                pos += 4
            else:
                return None
            if pos > len(data):
                return None
        return out
    except ValueError:
        return None


def audio_stream_tokens(body: bytes) -> set[str]:
    """Return capabilities from formats explicitly labelled audio-only.

    Unknown iOS Music protobuf answers are never allowed to promote their video
    formats to MUSIC. JSON is decoded structurally; protobuf is handled
    conservatively by accepting only URLs whose enclosing length-delimited
    format message itself carries an ``audio/`` MIME label and no ``video/``
    label.
    """
    data = _unescape(body)
    out: set[str] = set()
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
        parsed = None

    def json_formats(value):
        if isinstance(value, dict):
            mime = value.get("mimeType")
            url = value.get("url")
            if isinstance(mime, str) and mime.lower().startswith("audio/") and isinstance(url, str):
                yield url
            for child in value.values():
                yield from json_formats(child)
        elif isinstance(value, list):
            for child in value:
                yield from json_formats(child)

    urls = list(json_formats(parsed)) if parsed is not None else []
    if parsed is None:
        # Walk nested protobuf messages and use only the smallest message that
        # binds an audio MIME string to a googlevideo URL. An outer container
        # holding both audio and video formats is deliberately rejected.
        def protobuf_formats(value: bytes, depth: int = 0):
            if depth > 12:
                return []
            fields = _protobuf_fields(value)
            children = []
            for _, child in fields or []:
                children.extend(protobuf_formats(child, depth + 1))
            if children:
                return children
            low = value.lower()
            if b"audio/" in low and b"video/" not in low:
                return [raw.decode("ascii", "ignore") for raw in _STREAM_URL.findall(value)]
            return []

        urls = protobuf_formats(data)
    for url in urls:
        try:
            if is_stream_host(urlsplit(url).hostname or ""):
                out |= stream_keys(url)
        except ValueError:
            continue
    return out


def _pb_fields(data: bytes):
    """All top-level protobuf fields as (number, wire, value), or None when the bytes are not one message."""
    out, pos = [], 0

    def varint(at):
        value = 0
        for shift in range(0, 70, 7):
            if at >= len(data):
                raise ValueError
            byte = data[at]
            at += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, at
        raise ValueError
    try:
        while pos < len(data):
            key, pos = varint(pos)
            number, wire = key >> 3, key & 7
            if not number:
                return None
            if wire == 0:
                value, pos = varint(pos)
            elif wire == 1:
                value, pos = data[pos:pos + 8], pos + 8
            elif wire == 2:
                size, pos = varint(pos)
                value, pos = data[pos:pos + size], pos + size
            elif wire == 5:
                value, pos = data[pos:pos + 4], pos + 4
            else:
                return None
            if pos > len(data):
                return None
            out.append((number, wire, value))
        return out
    except ValueError:
        return None


def audio_format_itags(body: bytes) -> set[int]:
    """itags of the formats an answer labels audio/ (JSON `itag`+`mimeType`; protobuf format field 1 + field 5)."""
    out: set[int] = set()
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
        parsed = None
    if parsed is not None:
        stack = [parsed]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                mime, itag = value.get("mimeType"), value.get("itag")
                if isinstance(mime, str) and mime.lower().startswith("audio/") and isinstance(itag, int):
                    out.add(itag)
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        return out

    def walk(data: bytes, depth: int):
        fields = _pb_fields(data)
        if not fields or depth > 12:
            return
        mimes = [v for n, w, v in fields if n == 5 and w == 2 and v[:6].lower() in (b"audio/", b"video/")]
        if mimes:
            itags = [v for n, w, v in fields if n == 1 and w == 0]
            if len(itags) == 1 and all(m[:6].lower() == b"audio/" for m in mimes):
                out.add(itags[0])
            return
        for _, wire, value in fields:
            if wire == 2 and len(value) > 2:
                walk(value, depth + 1)
    walk(body or b"", 0)
    return out


UMP_MEDIA_HEADER = 20
UMP_MEDIA = 21
MAX_UMP_HEADER_BYTES = 16 * 1024


def _ump_varint(buf, pos: int):
    """googlevideo UMP variable-length integer: (value, next position), or None while incomplete."""
    if pos >= len(buf):
        return None
    first = buf[pos]
    size = 1 if first < 128 else 2 if first < 192 else 3 if first < 224 else 4 if first < 240 else 5
    if pos + size > len(buf):
        return None
    if size == 1:
        return first, pos + 1
    rest = int.from_bytes(bytes(buf[pos + 1:pos + size]), "little")
    if size == 5:
        return rest, pos + 5
    low_bits = 8 - size  # 6, 5 or 4 value bits in the first byte
    return (first & ((1 << low_bits) - 1)) + (rest << low_bits), pos + size


class UmpAudioGuard:
    """Follows a SABR/UMP response and admits media only under an approved audio MEDIA_HEADER.

    Positive check: a MEDIA_HEADER (part 20) must carry its header id (field 1) and only allowed itags
    (field 3, format_id.itag); a MEDIA part (21) must start with the id of such a header. A header
    precedes its media, so the caller drops the chunk that fails and everything after it: media of a
    forbidden or unlabelled format is never released. The caller must refuse compressed responses,
    whose encoded bytes would hide the parts."""

    def __init__(self, allowed):
        self.allowed = frozenset(allowed)
        self.ok = bool(self.allowed)
        self.itags: list[int] = []
        self.header_ids: set[int] = set()
        self._pending = bytearray()  # part type/size bytes not yet complete
        self._kind = None
        self._collect = bytearray()  # MEDIA_HEADER payload, or the leading header id of a MEDIA part
        self._left = 0               # payload bytes of the current part still to read

    def _check_header(self, payload: bytes) -> bool:
        fields = _pb_fields(payload) or []
        ids = [v for n, w, v in fields if n == 1 and w == 0]
        itags = [v for n, w, v in fields if n == 3 and w == 0]
        for n, w, v in fields:
            if n == 13 and w == 2:  # format_id { itag = 1 }
                itags += [x for m, ww, x in (_pb_fields(v) or []) if m == 1 and ww == 0]
        self.itags += itags
        if len(ids) != 1 or not itags or not all(i in self.allowed for i in itags):
            return False
        self.header_ids.add(ids[0])
        return True

    def _media_id(self):
        """(header id, complete) from the collected start of a MEDIA part (protobuf varint)."""
        value = 0
        for i, byte in enumerate(self._collect[:10]):
            value |= (byte & 0x7f) << (7 * i)
            if not byte & 0x80:
                return value, True
        return None, len(self._collect) >= 10

    def _fail(self) -> bool:
        self.ok = False
        return False

    def feed(self, chunk: bytes) -> bool:
        """Consume the next response bytes; False once the stream must be stopped."""
        if not self.ok:
            return False
        pos, end = 0, len(chunk)
        while pos < end:
            if self._kind is None:
                self._pending.append(chunk[pos])
                pos += 1
                kind = _ump_varint(self._pending, 0)
                size = kind and _ump_varint(self._pending, kind[1])
                if not size:
                    if len(self._pending) > 10:
                        return self._fail()
                    continue
                self._pending.clear()
                self._kind, self._left = kind[0], size[0]
                if self._kind == UMP_MEDIA_HEADER and not 0 < self._left <= MAX_UMP_HEADER_BYTES:
                    return self._fail()
                if self._kind == UMP_MEDIA and not self._left:
                    return self._fail()
                if not self._left:
                    self._kind = None
                continue
            step = min(self._left, end - pos)
            if self._kind == UMP_MEDIA_HEADER:
                self._collect += chunk[pos:pos + step]
            elif self._kind == UMP_MEDIA and self._collect is not None:
                take = min(step, 10 - len(self._collect))
                self._collect += chunk[pos:pos + take]
                header_id, done = self._media_id()
                if done:
                    if header_id is None or header_id not in self.header_ids:
                        return self._fail()  # media with no prior approved header, or an unknown id
                    self._collect = None
            self._left -= step
            pos += step
            if not self._left:
                if self._kind == UMP_MEDIA_HEADER and not self._check_header(bytes(self._collect)):
                    return self._fail()
                if self._kind == UMP_MEDIA and self._collect is not None:
                    return self._fail()  # media part ended before its header id was readable
                self._kind, self._collect = None, bytearray()
        return self.ok


def stream_tokens(body: bytes) -> set[str]:
    out = set()
    for raw in _STREAM_URL.findall(_unescape(body)):
        url = raw.decode("ascii", "ignore")
        if is_stream_host(urlsplit(url).hostname or ""):
            out |= stream_keys(url)
            # iOS server-ABR uses one player-authorised event (`ei`) while choosing
            # new track ids and even new CDN hosts as playback progresses.  Keep a
            # separate capability for that endpoint; an ordinary URL which merely
            # borrows the event token must not gain this privilege.
            ei = stream_token(url)
            try:
                parts = urlsplit(url)
                query = parse_qs(parts.query)
            except ValueError:
                continue
            if (ei and parts.path == "/videoplayback" and query.get("sabr") == ["1"]):
                out.add(f"sabr:{ei}")
    return out


def ump_redirect_keys(body: bytes, final: bool = False) -> set[str]:
    """Extract complete googlevideo URLs from a bounded prefix of a UMP response.

    UMP parts are protobuf-framed, so a URL is followed by a control byte (or by
    the end of the response).  Requiring that terminator prevents a network
    chunk boundary from registering a truncated URL before its ``ei``/``id``
    parameters have arrived.
    """
    data = _unescape((body or b"")[:MAX_UMP_INSPECT_BYTES])
    # Any byte outside the URL alphabet ends the protobuf string. This includes
    # multi-byte varint tags (>= 0x80), not just small control-byte field tags.
    suffix = rb"(?=[^\x21\x23-\x26\x28-\x5b\x5d-\x7e])" if not final \
        else rb"(?=[^\x21\x23-\x26\x28-\x5b\x5d-\x7e]|$)"
    urls = re.findall(rb"https://[A-Za-z0-9.-]+/[\x21\x23-\x26\x28-\x5b\x5d-\x7e]{1,2000}" + suffix, data)
    keys: set[str] = set()
    for raw in urls:
        url = raw.decode("ascii", "ignore")
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        if not is_stream_host(parts.hostname or "") or parts.path not in ("/videoplayback", "/initplayback"):
            continue
        got = stream_keys(url)
        if got:
            keys |= got
            ei = stream_token(url)
            query = parse_qs(parts.query)
            if ei and parts.path == "/videoplayback" and query.get("sabr") == ["1"]:
                keys.add(f"sabr:{ei}")
    return keys if len(keys) <= MAX_TOKENS_PER_ANSWER else set()


def _protobuf_fields(data: bytes) -> list[tuple[int, bytes]] | None:
    """The length-delimited fields (number, bytes) of a well-formed protobuf message, else None."""
    out, pos = [], 0

    def varint(at):
        value, shift = 0, 0
        while at < len(data) and shift < 70:
            byte = data[at]
            at += 1
            value |= (byte & 0x7f) << shift
            if not byte & 0x80:
                return value, at
            shift += 7
        raise ValueError

    try:
        while pos < len(data):
            key, pos = varint(pos)
            field, wire = key >> 3, key & 7
            if not field or wire in (3, 4):
                return None
            if wire == 0:
                _, pos = varint(pos)
            elif wire == 1:
                pos += 8
            elif wire == 2:
                size, pos = varint(pos)
                if pos + size > len(data):
                    return None
                out.append((field, data[pos:pos + size]))
                pos += size
            elif wire == 5:
                pos += 4
            else:
                return None
            if pos > len(data):
                return None
    except (ValueError, IndexError):
        return None
    return out


def _proto_player_identity(message: bytes) -> tuple[str, str, bytes] | None:
    """(video, channel) when *message* is an iOS player response by structure, else None.
    Layout read from live iOS answers (2026-11-16): field 4 = streamingData (googlevideo URLs),
    field 11 = videoDetails {1: videoId, 19: channelId}. Exactly one of each, or no identity."""
    fields = _protobuf_fields(message)
    if not fields:
        return None
    streaming = [v for f, v in fields if f == 4]
    details = [v for f, v in fields if f == 11]
    if len(streaming) != 1 or len(details) != 1 or not stream_tokens(streaming[0]):
        return None
    inner = _protobuf_fields(details[0]) or []
    vids = [v for f, v in inner if f == 1]
    chans = [v for f, v in inner if f == 19]
    if len(vids) != 1 or len(chans) != 1:
        return None
    video, channel = vids[0].decode("ascii", "ignore"), chans[0].decode("ascii", "ignore")
    if not (_VIDEO_ID.fullmatch(video) and _CHANNEL_ID.fullmatch(channel)):
        return None
    return video, channel, streaming[0]


def _json_player_identity(value) -> tuple[str, str, bytes] | None:
    """(video, channel) when *value* is a player response dict by structure, else None."""
    if not isinstance(value, dict) or not isinstance(value.get("streamingData"), dict):
        return None
    details = value.get("videoDetails")
    if not isinstance(details, dict):
        return None
    video, channel = details.get("videoId"), details.get("channelId")
    if not (isinstance(video, str) and _VIDEO_ID.fullmatch(video)
            and isinstance(channel, str) and _CHANNEL_ID.fullmatch(channel)):
        return None
    streaming = json.dumps(value["streamingData"], separators=(",", ":"), ensure_ascii=True).encode()
    return video, channel, streaming


MAX_DEPTH = 24  # nesting deeper than this makes the whole answer ambiguous
# Where a stream address may sit inside streamingData (review round 4). Read from live iOS answers
# 2026-11-16: 3.2 = adaptiveFormats[].url, 5/7/15 = manifest and server-ABR URLs; 2.2 = formats[].url.
_PROTO_URL_SLOTS = {(2, 2), (3, 2), (5,), (7,), (15,)}
_JSON_URL_LISTS = ("formats", "adaptiveFormats")
_JSON_URL_KEYS = ("hlsManifestUrl", "dashManifestUrl", "serverAbrStreamingUrl")


def _streaming_keys(streaming: bytes, is_json: bool) -> set[str] | None:
    """Stream keys from the known URL slots of one streamingData, or None when any googlevideo address
    sits anywhere else (a nested or partial player, an unknown layout): the answer is then ambiguous."""
    urls: list[bytes] = []
    if is_json:
        try:
            data = json.loads(streaming)
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
            return None
        if not isinstance(data, dict):
            return None
        for name in _JSON_URL_LISTS:
            for fmt in data.get(name) or []:
                if isinstance(fmt, dict) and isinstance(fmt.get("url"), str):
                    urls.append(fmt["url"].encode("ascii", "ignore"))
        for name in _JSON_URL_KEYS:
            if isinstance(data.get(name), str):
                urls.append(data[name].encode("ascii", "ignore"))
    else:
        for field, value in _protobuf_fields(streaming) or []:
            if (field,) in _PROTO_URL_SLOTS and value.startswith(b"https://"):
                urls.append(value)
            elif any(slot[0] == field and len(slot) == 2 for slot in _PROTO_URL_SLOTS):
                for inner, v in _protobuf_fields(value) or []:
                    if (field, inner) in _PROTO_URL_SLOTS and v.startswith(b"https://"):
                        urls.append(v)
    marker = b"googlevideo.com"
    if _unescape(streaming).count(marker) != sum(u.count(marker) for u in urls):
        return None  # an address outside the known slots
    keys: set[str] = set()
    for u in urls:
        url = u.decode("ascii", "ignore")
        if u.count(b"https://") != 1 or u.count(b"http://") or u.lower().count(b"%3a%2f%2f"):
            return None  # a slot holding a second address (review round 5)
        if is_stream_host(urlsplit(url).hostname or ""):
            got = stream_keys(url)
            if sum(k.startswith("ei:") for k in got) > 1 or sum(k.startswith("id:") for k in got) > 1:
                return None  # one stream names one event token and one id
            keys |= got
    return keys


class _Ambiguous(Exception):
    pass


def embedded_players(body: bytes) -> list[tuple[str, str, set[str]]]:
    """Player responses embedded in another YouTube API answer, as (video, channel, stream keys).

    Simple rule (review rounds 1-3): a stream key counts only when it sits inside the streamingData of a
    player recognised by structure (iOS protobuf 4 = streamingData, 11 = videoDetails {1: id, 19: channel};
    JSON streamingData + videoDetails). Keys anywhere else are never registered. A player inside another
    player, a key shared by two players, too many players or nesting past MAX_DEPTH return [] for the
    whole answer.
    """
    if not body or len(body) > MAX_PLAYER_BYTES:
        return []
    found: list[tuple[str, str, bytes]] = []

    def json_walk(value, depth, inside):
        if depth > MAX_DEPTH:
            raise _Ambiguous
        ident = _json_player_identity(value)
        if ident:
            if inside:
                raise _Ambiguous  # a player nested in a player
            found.append(ident)
        children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        for child in children:
            json_walk(child, depth + 1, inside or bool(ident))

    def proto_walk(message, depth, inside):
        if depth > MAX_DEPTH:
            raise _Ambiguous
        ident = _proto_player_identity(message)
        if ident:
            if inside:
                raise _Ambiguous
            found.append(ident)
        for _, child in _protobuf_fields(message) or []:
            proto_walk(child, depth + 1, inside or bool(ident))

    is_json = True
    try:
        try:
            value = json.loads(body)
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
            is_json = False
            proto_walk(body, 0, False)
        else:
            json_walk(value, 0, False)
    except (_Ambiguous, RecursionError):
        return []
    if not found or len(found) > MAX_EMBEDDED:
        return []
    out, seen = [], set()
    for video, channel, streaming in found:
        keys = _streaming_keys(streaming, is_json)
        if not keys or len(keys) > MAX_TOKENS_PER_ANSWER or seen & keys:
            return []
        seen |= keys
        out.append((video, channel, keys))
    return out


class Gate:
    def __init__(self, channels_file: Path = CHANNELS_FILE, clock=time.time, tokens_file: Path | None = None):
        self._file, self._clock = Path(channels_file), clock
        self._lock = threading.Lock()
        self._tokens: dict[str, tuple[float, str]] = {}  # token -> (expiry, channel)
        # Registered streams are kept on disk, so a filter restart does not cut videos that are playing.
        # Each kept stream is still re-checked against the current channel list on every request.
        self._tokens_file = Path(tokens_file) if tokens_file else None
        self._load_tokens()
        self._channels: dict[str, str] = {}
        self._mtime = None
        self.music_enabled = False  # set by the addon from config [youtube] music_without_approval
        self.checked_enabled = False  # set by the addon from config [youtube] ai_check

    def channels(self) -> dict[str, str]:
        try:
            mtime = self._file.stat().st_mtime
        except OSError:
            mtime = None
        if mtime != self._mtime:
            data = {}
            if mtime is not None:
                try:
                    raw = json.loads(self._file.read_text(encoding="utf-8"))
                    data = {k: str(v) for k, v in raw.items() if _CHANNEL_ID.fullmatch(k)} if isinstance(raw, dict) else {}
                except (OSError, ValueError):
                    data = {}  # unreadable list: nothing approved (fail closed)
            self._channels, self._mtime = data, mtime
        return self._channels

    def review_player(self, body: bytes, music: bool = False, checked: bool = False,
                      audio_only: bool = False) -> tuple[bool, str | None]:
        """(approved, channel id). Approved answers register their stream tokens.
        music=True: the YouTube Music app with music allowed without approvals (maintainer decision).
        checked=True: the AI check passed this one video (its channel is not on the list)."""
        if len(body or b"") > MAX_PLAYER_BYTES:
            return False, None
        channel = player_channel(body)
        if not (music or checked) and (not channel or channel not in self.channels()):
            return False, channel
        itags: set[int] = set()
        if audio_only:
            # SABR answers stream every format through one server-ABR endpoint; keep that capability, and
            # bind it to the answer's audio-labelled itags, which the UMP stream guard enforces per header.
            tokens = audio_stream_tokens(body)
            itags = audio_format_itags(body)
            sabr = {k for k in stream_tokens(body) if k.startswith("sabr:")}
            if itags:
                tokens |= sabr | {"ei:" + k[5:] for k in sabr}
            tokens |= {f"aitags:{k[3:]}" for k in tokens if k.startswith("ei:")} if itags else set()
        else:
            tokens = stream_tokens(body)
        if not tokens or len(tokens) > MAX_TOKENS_PER_ANSWER:
            return False, channel
        now = self._clock()
        with self._lock:
            if len(self._tokens) + len(tokens) > MAX_TOKENS:
                self._tokens = {t: v for t, v in self._tokens.items() if v[0] > now}
                if len(self._tokens) + len(tokens) > MAX_TOKENS:
                    return False, channel  # full: refuse rather than grow
            for t in tokens:
                marker = (MUSIC_AUDIO if audio_only else MUSIC) if music else CHECKED if checked else channel
                if t.startswith("aitags:"):
                    marker = ",".join(str(i) for i in sorted(itags))
                self._tokens[t] = (now + TOKEN_TTL, marker)
            self._save_tokens(now)
        return True, channel

    def register_streams(self, keys: set[str], marker: str, expires_at: float | None = None,
                         audio_itags=None) -> bool:
        """Register stream keys already attributed to one approved video (a listed channel id or CHECKED).
        A MUSIC_AUDIO delegation (SABR redirect) must carry the itag allow-list of its source grant."""
        if marker == MUSIC_AUDIO and audio_itags:
            keys = set(keys) | {f"aitags:{k[3:]}" for k in keys if k.startswith("ei:")}
        if not keys or len(keys) > MAX_TOKENS_PER_ANSWER or not (
                marker in (MUSIC, MUSIC_AUDIO, CHECKED) or _CHANNEL_ID.fullmatch(marker)):
            return False
        now = self._clock()
        expiry = min(now + TOKEN_TTL, expires_at) if expires_at is not None else now + TOKEN_TTL
        if expiry <= now:
            return False
        with self._lock:
            if len(self._tokens) + len(keys) > MAX_TOKENS:
                self._tokens = {t: v for t, v in self._tokens.items() if v[0] > now}
                if len(self._tokens) + len(keys) > MAX_TOKENS:
                    return False
            for k in keys:
                self._tokens[k] = (expiry, ",".join(str(i) for i in sorted(audio_itags))
                                   if k.startswith("aitags:") else marker)
            self._save_tokens(now)
        return True

    def audio_itags(self, url: str) -> frozenset[int]:
        """The audio itags an audio-only (MUSIC_AUDIO) grant allows on this stream's event; empty = none."""
        ei = stream_token(url)
        if not ei:
            return frozenset()
        with self._lock:
            expiry, value = self._tokens.get(f"aitags:{ei}", (0, ""))
        if expiry <= self._clock():
            return frozenset()
        try:
            return frozenset(int(v) for v in value.split(",") if v)
        except ValueError:
            return frozenset()

    def _load_tokens(self):
        if not self._tokens_file:
            return
        try:
            raw = json.loads(self._tokens_file.read_text(encoding="utf-8"))
            now = self._clock()
            self._tokens = {str(k): (float(v[0]), str(v[1])) for k, v in list(raw.items())[:MAX_TOKENS]
                            if isinstance(v, list) and len(v) == 2 and now < float(v[0]) <= now + TOKEN_TTL}
        except (OSError, ValueError, TypeError):
            self._tokens = {}

    def _save_tokens(self, now: float):
        """Caller holds the lock. Best effort: a failed save never changes a decision."""
        if not self._tokens_file:
            return
        try:
            live = {k: [v[0], v[1]] for k, v in self._tokens.items() if v[0] > now}
            tmp = self._tokens_file.with_suffix(".tmp")
            tmp.write_text(json.dumps(live), encoding="utf-8")
            os.replace(tmp, self._tokens_file)
        except OSError:
            pass

    def stream_authorization(self, host: str, url: str) -> tuple[str, float] | None:
        """Return the approval marker and expiry authorising this exact stream request."""
        if not is_stream_host(host):
            return None
        keys = stream_keys(url)
        if not keys:
            return None
        now, approved = self._clock(), self.channels()
        with self._lock:
            found = [self._tokens.get(k, (0, "")) for k in keys]
            # A serverAbrStreamingUrl is an event-scoped endpoint: later range/
            # track requests retain `ei` and `sabr=1`, but YouTube may replace
            # `id` while falling back to another googlevideo CDN.  Admit the new
            # id only on that exact endpoint shape and only when the approved
            # player response registered the matching server-ABR capability.
            try:
                parts, query = urlsplit(url), parse_qs(urlsplit(url).query)
            except ValueError:
                parts, query = None, {}
            ei = stream_token(url)
            abr = self._tokens.get(f"sabr:{ei}", (0, "")) if ei else (0, "")
            event = self._tokens.get(f"ei:{ei}", (0, "")) if ei else (0, "")
        mimes = request_mimes(parts, query)
        audio_request = audio_only_request(parts, query)
        valid = lambda item: item[0] > now and (item[1] in approved
                                                or (item[1] == MUSIC and self.music_enabled
                                                    and all(m.startswith("audio/") for m in mimes))
                                                or (item[1] == MUSIC_AUDIO and self.music_enabled and audio_request)
                                                or (item[1] == CHECKED and self.checked_enabled))
        # MUSIC is an audio capability, never a way to admit an explicitly
        # video-labelled request even if it reuses an audio event token.
        # MUSIC_AUDIO is stricter: all formats of one answer share `ei`/`id`, so
        # the grant holds only for requests explicitly labelled audio/ (query or
        # path form) or server-ABR requests; the response must be audio/, or UMP
        # whose every MEDIA_HEADER names an audio itag (addon.responseheaders).
        # iOS Music renews the event (`ei`) while an audio-only stream is in
        # progress.  The signed media `id`, however, remains the one returned by
        # the approved player response.  Treat that registered id as the content
        # capability instead of requiring an unrelated, short-lived event to
        # remain unchanged.  This is deliberately one-way: a known ei paired
        # with an unknown id is still denied, so an unapproved stream cannot
        # borrow an approved event token.
        ids = [self._tokens.get(k, (0, "")) for k in keys if k.startswith("id:")]
        if ids and all(valid(item) for item in ids) and len({item[1] for item in ids}) == 1:
            return ids[0][1], min(item[0] for item in ids)
        if (parts and parts.path == "/videoplayback" and query.get("sabr") == ["1"]
                and ei and valid(abr)):
            # The ordinary ei registration and the ABR capability must describe
            # the same approval.  This also prevents stale/mixed persisted state.
            if valid(event) and event[1] == abr[1]:
                return event[1], min(event[0], abr[0])
            return None
        # Every key must be known and live; removing a channel (or an unreadable list) revokes at once.
        if all(valid(item) for item in found) and len({item[1] for item in found}) == 1:
            return found[0][1], min(item[0] for item in found)
        return None

    def stream_allowed(self, host: str, url: str) -> bool:
        return self.stream_authorization(host, url) is not None
