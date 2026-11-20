"""mitmproxy addon: the filter itself.

Run with:  mitmdump -s addon.py --listen-port 8080
Every request passes the site verdict check; images are reviewed by the local
AI model and pages from unknown sites by the text reviewer.
"""

import asyncio
import base64
import binascii
import hashlib
import html
import io
import json
import queue
import re
import sys
import threading
import time
from collections import OrderedDict
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, unquote

from mitmproxy import http, tls
from mitmproxy.net.http.headers import infer_content_encoding
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aifilter import bodies, config, pages, schedules, selfguard, text  # noqa: E402
from aifilter.hotstore import Latency, ProxyStore  # noqa: E402
from aifilter.timing import timed  # noqa: E402
from aifilter.dns import protected  # noqa: E402
from aifilter import image_url, safesearch, xgate, ytcheck, ytgate, ytprefetch  # noqa: E402
from aifilter.store import BLOCK, TEXT_ONLY, TRUSTED, Store, registrable  # noqa: E402

IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif", ".heic", ".bmp")
VIDEO_TYPES = ("video/", "application/vnd.apple.mpegurl", "application/x-mpegurl", "application/dash+xml",
               "application/vnd.yt-ump")  # YouTube's newer stream format (2026-11-15: played past the video gate)
VIDEO_EXTS = (".mp4", ".m4v", ".m4s", ".m3u8", ".mpd", ".webm", ".mov", ".ts", ".mkv")
TEXT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

INLINE_IMAGE = re.compile(rb"data:(?:image/[a-zA-Z0-9.+-]+|application/octet-stream)(?:;[a-zA-Z0-9=._-]+)*;base64,([a-zA-Z0-9+/=\t\r\n\f ]+)(?=[\"'<>)]|$)", re.I)
LARGE_PLAIN_BYTES = 8 * 1024 * 1024   # retained for callers; text never skips review by size
WS_KEEP = 20  # websocket messages kept per connection
GIANT_TEXT_BYTES = 64 * 1024 * 1024  # declared non-HTML text above this streams like any other download
IMAGE_DECODE_BYTES = 32 * 1024 * 1024
CONTENT_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="aifilter-content")
INLINE_SCAN_BYTES = 2 * 1024 * 1024   # HTML scanned for inline images; larger pages lose data: images
INLINE_REVIEW_MAX = 16                # distinct inline images reviewed per page; the rest are hidden
NO_INLINE_CSP = "img-src http: https:; media-src http: https:"
INLINE_PLACEHOLDER = b"data:image/png;base64," + base64.b64encode(pages.PLACEHOLDER_PNG)


async def _content_work(func, *args):
    return await asyncio.get_running_loop().run_in_executor(CONTENT_EXECUTOR, func, *args)


def _image_digest(policy, data):
    digest = hashlib.sha256(repr(policy).encode() + b"\0")
    digest.update(data)
    return digest.hexdigest()


def _inline_urls(data):
    """Decode HTML entities for detection, retaining offsets into original markup."""
    chunks, ends, deltas, cursor, size = [], [0], [0], 0, 0
    for entity in re.finditer(rb"&(?:#[xX][0-9a-fA-F]+;?|#[0-9]+;?|[a-zA-Z][a-zA-Z0-9]*;?)", data):
        decoded = html.unescape(entity[0].decode("ascii")).encode("utf-8")
        chunks.extend((data[cursor:entity.start()], decoded))
        size += entity.start() - cursor + len(decoded)
        ends.append(size)
        deltas.append(entity.end() - size)
        cursor = entity.end()
    chunks.append(data[cursor:])
    normalized = b"".join(chunks)
    for match in INLINE_IMAGE.finditer(normalized):
        start = match.start() + deltas[bisect_right(ends, match.start()) - 1]
        end = match.end() + deltas[bisect_right(ends, match.end()) - 1]
        yield start, end, re.sub(rb"\s+", b"", match[1])


def _tiny_inline(data):
    if len(data) > 2048:
        return False
    try:
        with Image.open(io.BytesIO(data)) as image:
            return image.width <= 4 and image.height <= 4 and getattr(image, "n_frames", 1) == 1
    except Exception:
        return False


import ipaddress
# Raw-IP CONNECT targets allowed to tunnel: Apple services, and the locked DoH resolver (the profile pins its IPs).
PASS_IP_NETS = [ipaddress.ip_network(n) for n in ("17.0.0.0/8", "1.1.1.3/32", "1.0.0.3/32",
                                                    "2606:4700:4700::1113/128", "2606:4700:4700::1003/128")]

from aifilter import probe  # noqa: E402

RECENT_HOSTS = Path(__file__).with_name("data") / "recent-hosts.log"
YT_CAPTURE_HOSTS = {"youtubei.googleapis.com", "www.youtube.com", "m.youtube.com", "youtube.com"}
YT_CAPTURE_VALUE_KEYS = {"c", "itag", "opr", "sabr", "pvi", "pai"}
YT_CAPTURE_MAX = 600
YT_COVER_TYPES = {"image/jpeg", "image/webp", "image/png"}


def _suffix_match(host: str, suffixes) -> bool:
    host = host.lower()
    return any(host == s or host.endswith("." + s) for s in suffixes)


def _youtube_capture_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host in YT_CAPTURE_HOSTS or host.endswith(".googlevideo.com")


def _youtube_capture_detail(flow: http.HTTPFlow, phase: str, route: str = "http") -> str:
    """Return a deliberately allow-listed diagnostic record; never include headers or raw URLs."""
    try:
        parts = urlsplit(flow.request.path)
        query = parse_qs(parts.query, keep_blank_values=True)
    except (ValueError, UnicodeError):
        parts, query = urlsplit("/"), {}
    response = flow.response
    content = response.raw_content if response is not None else None
    length = None
    if response is not None:
        try:
            length = int(response.headers.get("content-length", ""))
        except ValueError:
            length = len(content) if content is not None else None
        if length is None and content is not None:
            length = len(content)
    detail = {
        "phase": phase, "route": route, "method": flow.request.method, "path": parts.path,
        "query_keys": sorted(query),
        "query_values": {key: query[key][:4] for key in sorted(query) if key in YT_CAPTURE_VALUE_KEYS},
        "client": {"name": flow.request.headers.get("x-youtube-client-name", ""),
                   "version": flow.request.headers.get("x-youtube-client-version", "")},
        "status": response.status_code if response is not None else None,
        "content_type": response.headers.get("content-type", "") if response is not None else "",
        "response_length": length,
        "reviewed": bool(flow.metadata.get("aifilter_reviewed")),
        "registered": bool(flow.metadata.get("aifilter_registered")),
        "blocked": bool(flow.metadata.get("aifilter_blocked")),
    }
    return json.dumps(detail, separators=(",", ":"), sort_keys=True)


def _split_meta(labels) -> tuple[dict, list[str]]:
    """Leading "@key=value" labels from the YouTube check worker (timing, a prefetch's channel), and the reasons."""
    meta, reasons = {}, []
    for label in labels or []:
        label = str(label)
        if label.startswith("@") and "=" in label and not reasons:
            key, _, value = label[1:].partition("=")
            meta.setdefault(key, value)
        else:
            reasons.append(label)
    return meta, reasons


WARMUP_MISS_EVERY = 600  # seconds between two yt-warmup-miss records
WARMUP_UA_PREFIX = 48


def _warmup_misses(flow: http.HTTPFlow, host: str) -> list[str]:
    """Which conditions of the local warm-up answer fail for a request of the exact dummy shape ([] = none)."""
    request = flow.request
    checks = (("method", request.method == "GET"), ("scheme", request.scheme == "https"),
              ("port", request.port == 443), ("hosts", _hosts(flow) == {host}),
              ("body", not request.raw_content), ("range", "range" not in request.headers),
              ("client", ytgate.is_youtube_app(request.headers)))
    return [name for name, ok in checks if not ok]


def _looks_like_image(flow: http.HTTPFlow) -> bool:
    """Image by header, or a mislabelled body (octet-stream) the browser will still show."""
    ctype = flow.response.headers.get("content-type", "").lower()
    if ctype.startswith("image/"):
        return True
    if ctype and not ctype.startswith(("application/octet-stream", "binary/", "text/plain")):
        return False
    path = urlsplit(flow.request.pretty_url).path.lower()
    return path.endswith(IMAGE_EXTS) or flow.request.headers.get("accept", "").startswith("image/")


def _looks_like_video(flow: http.HTTPFlow) -> bool:
    ctype = flow.response.headers.get("content-type", "").lower()
    path = urlsplit(flow.request.pretty_url).path.lower()
    host = flow.request.pretty_host.lower()
    # YouTube's stream server: whatever content-type it labels, /videoplayback is video.
    youtube_stream = (host == "googlevideo.com" or host.endswith(".googlevideo.com")) \
        and path.startswith(("/videoplayback", "/initplayback"))
    return ctype.startswith(VIDEO_TYPES) or path.endswith(VIDEO_EXTS) or youtube_stream


PAGE_ONLY_SUFFIXES = (
    "google.com", "google.co.il", "bing.com", "duckduckgo.com", "yahoo.com",
    "wikipedia.org", "youtube.com", "apple.com", "microsoft.com",
    # Telegram web hosts: a bad page or picture must never AI-block the whole host (chat links).
    "t.me", "telegram.me", "telegram.dog", "telesco.pe",
)
TELEGRAM_WEB_HOSTS = ("t.me", "telegram.me", "telegram.dog")


def _telegram_public_feed(host: str, target: str) -> bool:
    """t.me/s/<channel> (any case, encoding or extra slashes, any subdomain) is an open public picture feed."""
    h = (host or "").lower().rstrip(".")
    if not any(h == s or h.endswith("." + s) for s in TELEGRAM_WEB_HOSTS):
        return False
    raw = (target or "").split("?", 1)[0].split("#", 1)[0]
    for _ in range(3):  # decode nested percent-encoding
        decoded = unquote(raw)
        if decoded == raw:
            break
        raw = decoded
    parts = [p for p in raw.lower().split("/") if p and p != "."]
    return bool(parts) and parts[0] == "s"


ICLOUD_WEB_HOSTS = ("www.icloud.com", "share.icloud.com")
ICLOUD_SHARE_PATHS = ("sharedalbum", "photos", "iclouddrive", "keynote", "pages", "numbers", "freeform")


def _icloud_web_share(host: str, target: str) -> bool:
    """iCloud web share pages (/sharedalbum/, /photos/, /iclouddrive/, iWork and Freeform) on the inspected web hosts.

    The pictures themselves come from cvws*.icloud-content.com, which stays passthrough because it also
    carries the device's own backup and Photos sync; the gate is therefore page-level (decision on #49)."""
    if (host or "").lower().rstrip(".") not in ICLOUD_WEB_HOSTS:
        return False
    raw = (target or "").split("?", 1)[0].split("#", 1)[0]
    for _ in range(3):  # decode nested percent-encoding
        decoded = unquote(raw)
        if decoded == raw:
            break
        raw = decoded
    parts: list[str] = []
    for part in raw.lower().split("/"):  # resolve "." and ".." as the server would
        if part == "..":
            if parts:
                parts.pop()
        elif part and part != ".":
            parts.append(part)
    return bool(parts) and parts[0] in ICLOUD_SHARE_PATHS


WA_FLAG = Path(__file__).with_name("data") / "whatsapp-text-only"   # exists = mode on (scripts/whatsapp-text-only)
_wa_state = [0.0, False]


def _wa_text_only() -> bool:
    now = time.monotonic()
    if now - _wa_state[0] > 5:
        _wa_state[:] = [now, WA_FLAG.exists()]
    return _wa_state[1]


def _wa_media_host(host: str) -> bool:
    """WhatsApp's media download/upload hosts (not chat, calls, login or profile)."""
    h = host.lower().rstrip(".")
    if not h.endswith(".whatsapp.net"):
        return False
    label = h.split(".")[0]
    return label in ("mmg", "scontent") or label.startswith("media")


class _UninitializedStore:
    def __getattr__(self, name):
        raise RuntimeError("policy must be initialized by running() before serving")

    def __bool__(self):
        return False


_UNINITIALIZED_STORE = _UninitializedStore()


SITE_JUDGED_FILE = Path(__file__).with_name("data") / "site-judged.json"
# A few raw YouTube Music player answers whose song/video type could not be read (protobuf), kept locally so the
# type field can be found and the music-video check closed for the app too (PR #4 follow-up). At most 5 files.
EMBEDDED_TIMEOUT = 20  # seconds a Shorts/next answer may wait for its players' checks
MUSIC_SAMPLES = Path(__file__).with_name("data") / "yt-music-samples"


def _load_site_judged() -> dict:
    try:
        raw = json.loads(SITE_JUDGED_FILE.read_text(encoding="utf-8"))
        now = time.time()
        return {str(h): v for h, v in raw.items() if isinstance(v, list) and len(v) == 3 and float(v[0]) > now}
    except (OSError, ValueError, TypeError):
        return {}


def _save_site_judged(judged: dict):
    try:
        if len(judged) > 20000:
            for h in sorted(judged, key=lambda k: judged[k][0])[:len(judged) - 20000]:
                judged.pop(h)
        tmp = SITE_JUDGED_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(judged), encoding="utf-8")
        tmp.replace(SITE_JUDGED_FILE)
    except OSError:
        pass


def _page_only_host(host: str) -> bool:
    """Hosts whose AI text hits must never become a whole-site block."""
    h = host.lower().rstrip(".")
    return safesearch.google_search(h) or any(h == s or h.endswith("." + s) for s in PAGE_ONLY_SUFFIXES)


def _is_text(flow: http.HTTPFlow) -> bool:
    ctype = flow.response.headers.get("content-type", "").lower()
    return not ctype or ctype.startswith(TEXT_TYPES)


def _hosts(flow: http.HTTPFlow) -> set[str]:
    """Every name this request is really for: Host header, TLS SNI and the upstream address.

    An app can send a harmless Host header over a connection to a blocked site, so
    a verdict must hold for all of them.
    """
    hosts = {flow.request.pretty_host.lower()}
    if flow.client_conn and flow.client_conn.sni:
        hosts.add(flow.client_conn.sni.lower())
    if flow.server_conn and flow.server_conn.address:
        hosts.add(str(getattr(flow.server_conn, "_aifilter_host", flow.server_conn.address[0])).lower())
    return {h for h in hosts if h}


NOTIFY = True  # tests turn this off so they never post to Telegram


class _Notifier:
    """One background worker with a small bounded queue: the proxy's event loop never
    spawns processes or writes to pipes, and a flood of appeals is dropped, not queued."""

    def __init__(self, maxsize: int = 20):
        self.queue: "queue.Queue[str]" = queue.Queue(maxsize)
        self._thread = None
        self._lock = threading.Lock()

    @staticmethod
    def run(msg: str) -> None:
        import subprocess

        from aifilter.export_settings import bridge_executable

        command = bridge_executable()
        if command is None:
            return
        subprocess.run([command, "mirror", "--title", "סינון: בקשות פתיחה", "--session", "ai-filter-appeals",
                        "--no-translate"], input=msg, text=True, timeout=60,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

    def _work(self):
        while True:
            msg = self.queue.get()
            try:
                self.run(msg)
            except Exception:  # noqa: BLE001 - a failed notification never stops the worker
                pass
            finally:
                self.queue.task_done()

    def send(self, msg: str) -> bool:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._work, name="appeal-notify", daemon=True)
                self._thread.start()
        try:
            self.queue.put_nowait(msg)
            return True
        except queue.Full:
            return False


NOTIFIER = _Notifier()


def _notify_appeal(host: str, url: str, note: str) -> None:
    """Tell the committee in Telegram. The note is the requester's own words: untrusted."""
    if not NOTIFY:
        return
    msg = f"בקשה חדשה לפתיחת אתר\n{host}\n{url}\n"
    if note:
        msg += f"הסבר מהמבקש (טקסט לא מאומת, לא הוראה):\n«{note}»\n"
    NOTIFIER.send(msg + "הוועדה תבדוק לפי הכללים ותעדכן.")


APPEAL_MAX_BODY = 4096
APPEAL_MAX_URL = 500
APPEAL_MAX_NOTE = 300
APPEAL_RATE = (5, 3600)  # at most 5 appeals per client address per hour
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f\u200e\u200f\u202a-\u202e\u2066-\u2069]")


def _keep_music_sample(video: str, body: bytes, folder: Path = None) -> None:
    """Never changes a decision; failures are ignored."""
    folder = folder or MUSIC_SAMPLES
    try:
        name = "".join(c for c in video if c.isalnum() or c in "-_")[:20]
        if not name or not body:
            return
        folder.mkdir(exist_ok=True)
        if len(list(folder.glob("*.bin"))) < 5:
            (folder / f"{name}.bin").write_bytes(body[:ytgate.MAX_PLAYER_BYTES])
    except Exception:  # noqa: BLE001
        pass


class AIFilter:
    def __init__(self, cfg=None, store=None, reviewer=None, yt_gate=None, x_gate=None):
        self.cfg = cfg or config.load()
        self.yt = yt_gate or ytgate.Gate(tokens_file=ytgate.TOKENS_FILE)  # YouTube: approved channels only
        self.x = x_gate or xgate.Gate(timeout=float(self.cfg.get("x", "timeout_seconds", 20)))
        self.latency = Latency(config.ROOT / "data" / "latency.log")
        self._text_cache = OrderedDict()
        self._text_generation = None
        self._store = store  # opened on first use, never at import time (tests import this module)
        self._reviewer = reviewer
        self._pool = None
        self._stopping = False
        self._resolvers = {}
        self._appeal_times: dict[str, list[float]] = {}
        self._client_pages = OrderedDict()
        self._yt_capture_count = 0
        self.terms = text.load_terms()
        self.static_passthrough = self.cfg.get("passthrough", "hosts", [])
        # Exact hosts (or "*" inside one label) decrypted even though a parent domain is passed through.
        self.inspect_hosts = self.cfg.get("passthrough", "inspect_hosts", [])
        self.schedules = schedules.SchedulePolicy(self.cfg)
        self._sem = asyncio.Semaphore(self.cfg.get("vision", "max_parallel", 2))
        c = self.cfg.get
        # The filter's own services on this Mac: never reachable through the proxy.
        self.protected_ports = {int(c("admin", "port", 8090)), int(c("pac", "port", 8119)),
                                int(c("dns", "port", 53)), int(c("proxy", "listen_port", 8118)),
                                int(c("telegram_media", "port", 8120)), int(c("mcp", "port", 8130)),
                                # The app API's Serve port: relayed through the proxy, Serve would see the Mac
                                # itself and stamp the Mac owner's Tailscale login on any household device.
                                int(c("appapi", "port", 8140))}

    @property
    def store(self) -> Store | ProxyStore:
        # mitmproxy inspects every attribute when loading the script, so the
        # property itself must not raise; any real use before running() does.
        return self._store if self._store is not None else _UNINITIALIZED_STORE

    def running(self):
        if self._store is None:
            self._store = ProxyStore(config.db_path(), latency=self.latency, recent_hosts=RECENT_HOSTS)

    def done(self):
        # On hot reload, the stateless resolver stays installed for pending dials;
        # a new addon reuses it. On loop shutdown it can be safely removed.
        self._stopping = True
        if hasattr(self.x, "close"):
            self.x.close()
        if self._pool is not None:
            self._pool.close()
        for resolver in self._resolvers.values():
            resolver.close()
        self._resolvers.clear()
        if isinstance(self._store, ProxyStore):
            self._store.close()

    def _review_sync(self, data: bytes):
        return self._reviewer.review(data)  # injected unit-test reviewer only

    def _capture_youtube(self, flow: http.HTTPFlow, phase: str, route: str = "http") -> None:
        try:
            until = float(self.cfg.get("youtube", "capture_until", 0) or 0)
            host = flow.request.pretty_host.lower().rstrip(".")
            if time.time() >= until or self._yt_capture_count >= YT_CAPTURE_MAX or not _youtube_capture_host(host):
                return
            key = f"aifilter_yt_capture_{phase}"
            if flow.metadata.get(key):
                return
            flow.metadata[key] = True
            self._yt_capture_count += 1
            self.store.log("yt-capture", host, _youtube_capture_detail(flow, phase, route))
        except Exception:  # noqa: BLE001 - optional diagnostics must never affect traffic
            pass

    # Destinations ------------------------------------------------------

    @timed
    async def http_connect(self, flow: http.HTTPFlow):
        if self._unready(flow):
            return
        # DNS is checked exactly once, immediately before the upstream connection.
        host = flow.request.host
        literal = selfguard._ip(host.strip("[]"))
        why = selfguard.refusal([str(literal)], flow.request.port, self.protected_ports) if literal else None
        if literal and not any(literal in net for net in PASS_IP_NETS):
            flow.response = http.Response.make(403, b"destination IP not approved", {})
            self.store.log("ip-refused", f"{host}:{flow.request.port}", "destination IP not approved")
        elif why:
            self.store.log("self-refused", flow.request.host, why)
            flow.response = http.Response.make(403, b"", {})

        elif _wa_media_host(host) and _wa_text_only():
            # WhatsApp text-only mode: chats and calls work, media never downloads.
            flow.response = http.Response.make(403, b"", {})

    @timed
    async def server_connect(self, data):
        if self._store is None:
            data.server.error = "ai-filter: policy not initialized"
            return
        # Every upstream connection (plain HTTP, CONNECT, passthrough tunnels) passes here.
        if not data.server.address:
            return
        host, port = data.server.address[0], data.server.address[1]
        # Safe search: dial the provider's safe endpoint, keep the original name and TLS identity.
        ips = await selfguard.resolve(safesearch.target(str(host)) or str(host), port)
        why = selfguard.refusal(ips, int(port), self.protected_ports)
        if why:
            self.store.log("self-refused", str(host), why)
            data.server.error = f"ai-filter: destination refused ({why})"
            return
        # Pin the full checked address list at the dialer, preserving connection
        # reuse, multi-address fallback, HTTP Host and TLS verification identity.
        data.server._aifilter_host = str(host)
        if not getattr(data.server, "sni", None) and selfguard._ip(str(host)) is None:
            data.server.sni = str(host)
        try:
            if selfguard._ip(str(host)) is None:
                loop = asyncio.get_running_loop()
                if loop not in self._resolvers:
                    self._resolvers[loop] = selfguard.PinnedResolver.install(loop)
                if loop.getaddrinfo is not self._resolvers[loop].wrapper:
                    raise RuntimeError("pinned resolver was replaced")
                data.server.address = (selfguard.PinnedHost(str(host), port, ips), port)
            else:
                data.server.address = (ips[0], port)
        except (OSError, ValueError, RuntimeError) as exc:
            data.server.error = f"ai-filter: cannot pin destination ({type(exc).__name__})"

    # TLS ---------------------------------------------------------------
    @timed
    def tls_clienthello(self, data: tls.ClientHelloData):
        if self._store is None:
            data.context.client.error = "ai-filter: policy not initialized"
            return
        sni = (data.context.client.sni or "").lower()
        server = getattr(data.context, "server", None)
        dest = str(getattr(server, "_aifilter_host", server.address[0])).lower() if server is not None and server.address else ""
        passthrough = bool(sni) and self._passthrough_name(sni)
        # The CONNECT target must be the same service: a harmless SNI must not tunnel to another host.
        ip = selfguard._ip(dest) if dest else None
        if passthrough and dest and dest != sni and (
                (ip is not None and not any(ip in n for n in PASS_IP_NETS)) or (ip is None and not self._passthrough_name(dest))):
            passthrough = False  # a raw IP outside PASS_IP_NETS, or a different host: inspect
        peer = getattr(data.context.client, "peername", None)
        if passthrough and self._passthrough_blocked({sni, dest} - {""}, peer[0] if peer else None):
            passthrough = False  # inspect, so the request hook shows the block page
            self.store.log("passthrough-denied", sni, dest)
        if passthrough:
            data.ignore_connection = True
            # Ignored TLS has no HTTPFlow, so record its opaque route separately.
            if time.time() < float(self.cfg.get("youtube", "capture_until", 0) or 0) and _youtube_capture_host(sni) \
                    and self._yt_capture_count < YT_CAPTURE_MAX:
                self._yt_capture_count += 1
                self.store.log("yt-capture", sni, json.dumps({"phase": "tunnel", "route": "passthrough",
                                                               "reviewed": False, "registered": False,
                                                               "blocked": False}, separators=(",", ":"), sort_keys=True))
        if isinstance(self.store, ProxyStore):
            self.store.note_host(sni, getattr(data.context.client, "peername", None), "pass" if passthrough else "inspect")

    def _passthrough_name(self, name: str) -> bool:
        if schedules.host_listed(name, self.inspect_hosts):
            return False  # an open media/web surface under a pinned parent (audit 2026-11-18)
        return _suffix_match(name, self.static_passthrough) or _suffix_match(name, self.store.passthrough_hosts())

    def _static_passthrough(self, name: str) -> bool:
        return _suffix_match(name, self.static_passthrough) and not schedules.host_listed(name, self.inspect_hosts)

    def tcp_start(self, flow):
        """Only curated passthrough destinations may carry an opaque protocol."""
        server = flow.server_conn
        host = str(getattr(server, "_aifilter_host", server.address[0] if server.address else "")).lower().rstrip(".")
        ip = selfguard._ip(host.strip("[]"))
        approved = self._store is not None and (any(ip in net for net in PASS_IP_NETS)
                                                if ip else self._passthrough_name(host))
        if self._store is not None and time.time() < float(self.cfg.get("youtube", "capture_until", 0) or 0) \
                and _youtube_capture_host(host) and self._yt_capture_count < YT_CAPTURE_MAX:
            self._yt_capture_count += 1
            self.store.log("yt-capture", host, json.dumps({"phase": "tunnel", "route": "tcp",
                                                            "reviewed": False, "registered": False,
                                                            "blocked": not approved}, separators=(",", ":"), sort_keys=True))
        conn = getattr(flow, "client_conn", None)
        peer = getattr(conn, "peername", None)
        if not approved or self._passthrough_blocked({host}, peer[0] if peer else None):
            if self._store is not None:  # visible in the events table, so a broken app can be diagnosed
                self._store.log("raw-killed", host, "opaque tunnel to a host that is not an approved passthrough")
            flow.kill()

    def _passthrough_blocked(self, names: set[str], client: str | None = None) -> bool:
        """A block decision beats a passthrough exception.

        Own decisions (admin, policy, AI) always win. A community-list hit wins over
        an admin-added exception, but not over the curated static list in config.toml
        (banking, Apple, the committee channel), so a broad list can never cut those off.
        """
        for name in names:
            if self.schedules.reason(name, client=client):
                return True
            if self.store.verdict(name, lists=False) == BLOCK:
                return True
            if self.store.verdict(name, lists=False) is None and self.store.listed(name) \
                    and not self._static_passthrough(name):
                return True
        return False

    @timed
    def server_connect_error(self, data):
        if self._store is None:
            return
        server = data.server
        address = getattr(server, "address", None)
        host = getattr(server, "_aifilter_host", None) or (address[0] if address else None)
        if not host:
            return
        peer = getattr(server, "peername", None)
        ip = (peer or address or (None,))[0]
        try:
            literal = ipaddress.ip_address(str(ip).split("%", 1)[0])
        except ValueError:
            literal = None
        detail = str(getattr(server, "error", None) or "connection failed")
        if detail.startswith("ai-filter:"):
            return  # our own refusal (blocked or protected destination), not a reachability problem
        if literal:
            detail = f"IPv{literal.version} {ip}: {detail}"
        self.store.record_connect_failure(str(host), detail)

    def websocket_message(self, flow: http.HTTPFlow):
        # mitmproxy keeps every message of a websocket for the flow's lifetime; a long chat or live feed
        # would grow the proxy's memory without end. Keep a short tail; the current message is already forwarded.
        messages = flow.websocket.messages if flow.websocket else None
        if messages is not None and len(messages) > WS_KEEP:
            del messages[:-WS_KEEP]

    @timed
    def tls_failed_client(self, data: tls.TlsData):
        # Usually an app that pins its certificate. Listed for the admin to decide.
        sni = data.context.client.sni
        if sni:
            self.store.record_tls_failure(sni)

    # Requests ------------------------------------------------------------
    @timed
    def request(self, flow: http.HTTPFlow):
        self._request(flow)
        self._capture_youtube(flow, "request")

    def _request(self, flow: http.HTTPFlow):
        if self._unready(flow):
            return
        # Snapshot before inference or a later navigation can change attribution.
        self._page_host(flow)
        host = flow.request.pretty_host.lower()
        path = urlsplit(flow.request.path).path
        # Telegram's public channel pages are unrestricted media feeds, distinct from chat (audit 2026-11-18 S1).
        if _telegram_public_feed(host, flow.request.path):
            self._block(flow, host, "ערוצי טלגרם ציבוריים חסומים.")
            return
        # iCloud web shares open anyone's albums and files; the device's own iCloud services are untouched.
        if _icloud_web_share(host, flow.request.path):
            self._block(flow, host, "שיתופי iCloud מהדפדפן חסומים.")
            return
        # The local appeal endpoint must remain reachable from a schedule block page.
        if host == pages.APPEAL_HOST or path == pages.APPEAL_PATH:
            self._handle_appeal(flow, path)
            return
        # SchedulePolicy still applies focus blocks and its opt-in work/night rules.
        # Media flows need the existing player approval. Setup and cover requests
        # have their own response checks before any bytes can reach the app.
        work_music = host == "youtubei.googleapis.com" and ytgate.is_music_app(flow.request.headers)
        init_control = None
        music_cover = False
        if (self.cfg.get("youtube", "music_without_approval", False)
                and flow.request.method == "GET" and flow.request.scheme == "https"
                and flow.request.port == 443 and _hosts(flow) == {host}):
            music_cover = ytgate.music_cover(host, path, flow.request.headers)
            ua = (flow.request.headers.get("user-agent") or "").lower()
            if (not flow.request.raw_content and "range" not in flow.request.headers
                    and (not ua or ua.startswith("com.google.ios.youtubemusic/"))):
                init_control = ytgate.music_init_control(host, flow.request.path)
        # The regular app's dummy warm-up gets no schedule exception: only an unblocked one is ended locally.
        warmup_misses = _warmup_misses(flow, host) if ytgate.app_warmup(host, flow.request.path) else None
        if ytgate.is_stream_host(host):
            authorization = self.yt.stream_authorization(host, flow.request.pretty_url)
            if authorization:
                flow.metadata["yt_stream_authorization"] = authorization
                work_music = authorization[0] in (ytgate.MUSIC, ytgate.MUSIC_AUDIO)
                if authorization[0] == ytgate.MUSIC_AUDIO:
                    # The audio-only stream check reads the UMP parts: never let the CDN compress them.
                    flow.request.headers.pop("accept-encoding", None)
        peer = getattr(getattr(flow, "client_conn", None), "peername", None)
        client = str(peer[0]) if peer else None
        schedule_reason = self.schedules.reason(host, allow_work_music=work_music or music_cover, client=client)
        if schedule_reason and init_control:
            schedule_reason = self.schedules.reason(host, allow_work_music=True, client=client)
            if not schedule_reason:
                flow.metadata["yt_init_control_only"] = True
        if schedule_reason:
            self._block(flow, host, schedule_reason)
            return
        x_enabled = bool(self.cfg.get("x", "enabled", False))
        if x_enabled and (xgate.is_picture_host(host) or xgate.is_video_host(host)):
            # Checked media must never be satisfied from a browser cache without bytes to review.
            for header in ("if-none-match", "if-modified-since", "if-range"):
                flow.request.headers.pop(header, None)
        if x_enabled and xgate.is_live_host(host):
            self.store.log("x-blocked", host, "live/broadcast host")
            flow.response = http.Response.make(403, b"X live broadcasts are blocked", {})
            return
        if (flow.request.method == "POST" and path == "/initplayback"
                and (host == "googlevideo.com" or host.endswith(".googlevideo.com"))):
            # Onesie: the iOS app fetches an encrypted player response through the stream
            # server, which the filter cannot attribute to a video. Refuse it so the app
            # falls back to /youtubei/v1/player, which is reviewed (2026-11-18, ledger #74).
            self.store.log("video-blocked", host, "onesie POST /initplayback")
            flow.response = http.Response.make(403, b"", {})
            return
        if any(self.store.verdict(h) == BLOCK for h in _hosts(flow)):
            self._block(flow, host, "האתר סומן כחסום.")
            return
        if warmup_misses is not None:
            if not warmup_misses and self._text_only(flow):
                warmup_misses = ["text-only"]
            if not warmup_misses:
                # Upstream this probe can only be refused, and the app retried it every ~25 s all day
                # (2026-11-19). An empty local 204 grants no media, follows no redirect and registers nothing.
                flow.metadata["yt_app_warmup"] = True
                flow.response = http.Response.make(204, b"", {"cache-control": "no-store"})
                return
            self._note_warmup_miss(flow, warmup_misses)
        if init_control and not self._text_only(flow):
            flow.metadata["yt_init_control"] = init_control
            if init_control == "warmup" and flow.metadata.get("yt_init_control_only"):
                # The reserved ID is a periodic probe. End it locally so it cannot
                # return media, follow a redirect, or register a stream.
                flow.response = http.Response.make(204, b"", {"cache-control": "no-store"})
        if music_cover:
            flow.metadata["yt_music_cover"] = True
            # Require a complete response so a range or stale cache cannot skip review.
            for header in ("range", "if-range", "if-none-match", "if-modified-since"):
                flow.request.headers.pop(header, None)

    def _note_warmup_miss(self, flow: http.HTTPFlow, misses: list[str]):
        """The exact dummy warm-up went upstream (and will be refused): record which check failed, at most once
        every WARMUP_MISS_EVERY seconds. Only the User-Agent prefix and the client header, never bodies or cookies."""
        try:
            now = time.monotonic()
            if now < self.__dict__.get("_warmup_miss_next", 0):
                return
            self._warmup_miss_next = now + WARMUP_MISS_EVERY
            headers = flow.request.headers
            hosts = ",".join(sorted(_hosts(flow)))[:120]
            self.store.log("yt-warmup-miss", flow.request.pretty_host.lower(), json.dumps({
                "failed": misses, "ua": (headers.get("user-agent") or "")[:WARMUP_UA_PREFIX],
                "client": (headers.get("x-youtube-client-name") or "")[:16],
                "hosts": hosts, "http": flow.request.http_version[:10]}, ensure_ascii=True, separators=(",", ":")))
        except Exception:  # noqa: BLE001 - diagnostics never change a decision
            pass

    def _text_only(self, flow: http.HTTPFlow) -> bool:
        page = self._page_host(flow)
        # Referer can only make this response stricter; it never attributes strikes.
        ref = urlsplit(flow.request.headers.get("referer", "")).hostname
        x_enabled = bool(self.cfg.get("x", "enabled", False))
        if x_enabled and (xgate.is_page_host(flow.request.pretty_host)
                          or xgate.is_picture_host(flow.request.pretty_host)
                          or xgate.is_video_host(flow.request.pretty_host)):
            return False
        return any(self.store.verdict(h) == TEXT_ONLY for h in (flow.request.pretty_host, page, ref) if h)

    def _record_page(self, flow: http.HTTPFlow):
        if flow.metadata.get("aifilter_page_recorded"):
            return
        ctype = flow.response.headers.get("content-type", "").lower()
        peer = flow.client_conn.peername if flow.client_conn else None
        if peer and 200 <= flow.response.status_code < 300 and ctype.startswith(("text/html", "application/xhtml+xml")):
            flow.metadata["aifilter_page_recorded"] = True
            self._client_pages[peer[0]] = (time.monotonic(), flow.request.pretty_host.lower())
            self._client_pages.move_to_end(peer[0])
            while len(self._client_pages) > 4096:
                self._client_pages.popitem(last=False)

    def _page_host(self, flow: http.HTTPFlow) -> str | None:
        """Last HTML host observed for this IP, never the client-supplied Referer.

        One IP can have several tabs; this is bounded best-effort attribution.
        Unknown/stale page context never produces a host strike.
        """
        key = "aifilter_page_host"
        if key not in flow.metadata:
            peer = flow.client_conn.peername if flow.client_conn else None
            entry = self._client_pages.get(peer[0]) if peer else None
            flow.metadata[key] = entry[1] if entry and time.monotonic() - entry[0] < 1800 else None
        return flow.metadata[key]

    def _trusted(self, flow: http.HTTPFlow) -> bool:
        names = {flow.request.pretty_host.lower()}
        if flow.client_conn and flow.client_conn.sni:
            names.add(flow.client_conn.sni.lower())
        return all(self.store.verdict(h) == TRUSTED for h in names)

    def _video_allowed(self, flow: http.HTTPFlow) -> bool:
        if self._text_only(flow) or any(self.store.verdict(h) == BLOCK for h in _hosts(flow)):
            return False
        if any(ytgate.is_stream_host(h) for h in _hosts(flow)):
            # YouTube media: the channel gate is the only way in (no older trust or path approval).
            host = flow.request.pretty_host.lower()
            if flow.request.scheme != "https" or _hosts(flow) != {host}:
                return False
            authorization = self.yt.stream_authorization(host, flow.request.pretty_url)
            if authorization:
                flow.metadata["yt_stream_authorization"] = authorization
            return authorization is not None
        # Preserve existing trusted-host approvals. New approvals need no image trust.
        if self._trusted(flow):
            return True
        host = flow.request.pretty_host.lower()
        return flow.request.scheme == "https" and _hosts(flow) == {host} \
            and self.store.video_allowed(host, urlsplit(flow.request.pretty_url).path)

    def _appeal_reply(self, flow: http.HTTPFlow, code: int, body: bytes = b""):
        flow.response = http.Response.make(code, body or pages.appeal_error(), {"content-type": "text/html; charset=utf-8"})

    def _rate_limited(self, client: str) -> bool:
        limit, window = APPEAL_RATE
        now = time.time()
        if len(self._appeal_times) > 1024:  # bounded memory under a flood of addresses
            self._appeal_times = {k: v for k, v in self._appeal_times.items() if v and v[-1] > now - window}
        times = [t for t in self._appeal_times.get(client, []) if t > now - window]
        limited = len(times) >= limit
        if not limited:
            times.append(now)
        self._appeal_times[client] = times
        return limited

    def _handle_appeal(self, flow: http.HTTPFlow, path: str):
        # Only an exact POST to the form's route; everything else is not an appeal.
        if path not in (pages.APPEAL_PATH, "/appeal") or flow.request.method != "POST":
            return self._appeal_reply(flow, 405 if path == pages.APPEAL_PATH else 404)
        peer = flow.client_conn.peername if flow.client_conn else None
        if self._rate_limited(str(peer[0]) if peer else "-"):
            return self._appeal_reply(flow, 429, pages.appeal_error(pages.APPEAL_TOO_MANY))
        if len(flow.request.raw_content or b"") > APPEAL_MAX_BODY:
            return self._appeal_reply(flow, 413)
        form = parse_qs(flow.request.get_text(strict=False) or "", max_num_fields=10)
        url = (form.get("url") or [""])[0].strip()
        parts = urlsplit(url) if len(url) <= APPEAL_MAX_URL else None
        target = (parts.hostname or "").rstrip(".") if parts and parts.scheme in ("http", "https") else ""
        if not _HOSTNAME.match(target):
            return self._appeal_reply(flow, 400)
        note = _CONTROL.sub(" ", (form.get("note") or [""])[0])[:APPEAL_MAX_NOTE].strip()
        fresh = not self.store.appeals_for(target)
        self.store.add_appeal(target, url, note)
        self.store.log("appeal", target, url)
        if fresh:
            _notify_appeal(target, url, note)
        flow.response = http.Response.make(200, pages.appeal_sent(), {"content-type": "text/html; charset=utf-8"})

    @staticmethod
    def _own_probe(flow) -> bool:
        """Only requests carrying the install's probe marker are health probes (watchdog, self-test).

        Real browsing to the same sites, from this Mac too, has no marker and stays in the report.
        """
        return probe.matches(flow.request.headers.get(probe.HEADER, ""))

    def _block(self, flow: http.HTTPFlow, host: str, reason: str):
        flow.metadata["aifilter_blocked"] = True
        accept = flow.request.headers.get("accept", "")
        if "text/html" in accept:
            # One event per blocked page view (sub-resources stay silent), for the report.
            self.store.log("probe-blocked" if self._own_probe(flow) else "page-blocked", host, reason[:120])
            body = pages.blocked(host, flow.request.pretty_url, reason)
            flow.response = http.Response.make(403, body, {"content-type": "text/html; charset=utf-8"})
        else:
            flow.response = http.Response.make(403, b"", {})

    def _unready(self, flow):
        # No policy/store calls here: startup failure must itself be safe.
        # Once initialized, keep the last good policy through transient DB errors.
        if self._store is not None:
            return False
        flow.response = http.Response.make(503, pages.blocked(
            flow.request.pretty_host, flow.request.pretty_url, "הסינון עדיין אינו מוכן. נסו שוב בקרוב."),
            {"content-type": "text/html; charset=utf-8"})
        return True

    # Responses -----------------------------------------------------------
    @timed
    def _x_apply(self, flow: http.HTTPFlow, ok: bool, reason: str, checked_body=None, media_id=None):
        # Keep compatibility with injected gates while production returns checked bytes.
        if media_id is None and checked_body is not None and not isinstance(checked_body, bytes):
            media_id, checked_body = checked_body, None
        self.store.log("x-approved" if ok else "x-blocked", media_id or flow.request.pretty_host, reason)
        if ok and checked_body is not None:
            # Deliver precisely the bytes whose digest was recorded by xgate.
            headers = dict(flow.response.headers) if flow.response else {}
            headers.pop("content-encoding", None)
            headers.pop("transfer-encoding", None)
            headers["content-length"] = str(len(checked_body))
            flow.response = http.Response.make(200, checked_body, headers)
        elif not ok:
            flow.response = http.Response.make(403, ("X video blocked: " + reason).encode(),
                                               {"content-type": "text/plain; charset=utf-8"})

    async def _x_finish(self, flow: http.HTTPFlow):
        try:
            self._x_apply(flow, *(await self.x.allowed(flow.request.pretty_url)))
        except Exception as exc:  # noqa: BLE001 - fail closed
            self._x_apply(flow, False, type(exc).__name__, None, None)
        finally:
            flow.resume()

    def responseheaders(self, flow: http.HTTPFlow):
        if self._unready(flow):
            return
        self._record_page(flow)
        host = flow.request.pretty_host.lower()
        if (flow.metadata.get("yt_init_control") and flow.response.status_code == 204
                and not flow.response.raw_content):
            # A real CDN setup acknowledgement can arrive before /player. A 204
            # carries no media; record no authorization and keep the upstream header.
            flow.response.stream = False
            return
        if flow.metadata.get("yt_music_cover"):
            ctype = flow.response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if flow.response.status_code == 200 and ctype in YT_COVER_TYPES:
                flow.response.stream = False
                return
            if flow.response.status_code >= 400 and flow.response.headers.get("content-length") == "0":
                flow.response.stream = False
                return  # retain the CDN error and attribute it in response()
            self._block(flow, host, "התגובה אינה תמונת עטיפה מלאה.")
            if flow.killable:
                flow.kill()
            return
        x_media = self.cfg.get("x", "enabled", False) and (
            xgate.is_picture_host(host) or xgate.is_video_host(host))
        if x_media and flow.response.status_code == 304:
            self._x_apply(flow, False, "unreviewable 304", None, xgate.video_id(flow.request.pretty_url))
            return
        if xgate.is_video_host(host) and self.cfg.get("x", "enabled", False):
            known = self.x.known(flow.request.pretty_url)
            if known is not None:
                self._x_apply(flow, *known)
                return
            # Bound retained mitmproxy flows as well as worker concurrency.
            if hasattr(self.x, "begin") and not self.x.begin(flow.request.pretty_url):
                self._x_apply(flow, False, "busy, retry", None, xgate.video_id(flow.request.pretty_url))
                return
            flow.intercept()
            asyncio.get_running_loop().create_task(self._x_finish(flow))
            return
        if _looks_like_video(flow) and (flow.metadata.get("yt_init_control_only") or self._text_only(flow) or (
                self.cfg.get("policy", "block_video_untrusted", True) and not self._video_allowed(flow))):
            # Keep the bounded URL for the routine report, but record every
            # parameter name separately: the long signed googlevideo query puts
            # diagnostically useful flags (sabr/itag/mime) beyond byte 200.
            # Values are intentionally omitted, including sensitive sig/n/ip.
            try:
                query_keys = sorted(set(parse_qs(urlsplit(flow.request.pretty_url).query,
                                                 keep_blank_values=True)))
            except (ValueError, UnicodeError):
                query_keys = []
            detail = flow.request.pretty_url[:200] + " query-keys=" + ",".join(query_keys)
            if flow.metadata.get("yt_init_control"):
                detail = f"init-control upstream={flow.response.status_code} " + detail
            self.store.log("video-blocked", flow.request.pretty_host, detail)
            flow.metadata["aifilter_blocked"] = True
            flow.response = http.Response.make(403, b"", {})
            # A response replaced here would still pull the whole original body before the 403 is sent
            # (a live stream never ends): cut the stream now so the player fails at once.
            if flow.killable:
                flow.kill()
            return
        authorization = flow.metadata.get("yt_stream_authorization")
        response_type = flow.response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        try:
            stream_parts = urlsplit(flow.request.pretty_url)
            is_sabr = stream_parts.path == "/videoplayback" \
                and parse_qs(stream_parts.query).get("sabr") == ["1"]
        except (ValueError, UnicodeError):
            is_sabr = False
        audio_ump = is_sabr and response_type == "application/vnd.yt-ump" \
            and bool(self.yt.audio_itags(flow.request.pretty_url))
        encoding = flow.response.headers.get("content-encoding", "").strip().lower()
        if authorization and authorization[0] == ytgate.MUSIC_AUDIO and ytgate.is_stream_host(host) \
                and 200 <= flow.response.status_code < 300 and (
                    not (response_type.startswith("audio/") or audio_ump)
                    or (audio_ump and encoding not in ("", "identity"))):
            # An audio-only grant shares ei/id with the answer's video formats: the body itself must be audio
            # (or an uncompressed SABR UMP stream, checked part by part below: encoded bytes would hide the parts).
            self.store.log("video-blocked", flow.request.pretty_host, "music-audio grant, non-audio response "
                           + flow.response.headers.get("content-type", "")[:40] + f" encoding={encoding[:20]}")
            flow.metadata["aifilter_blocked"] = True
            flow.response = http.Response.make(403, b"", {})
            if flow.killable:
                flow.kill()
            return
        if ytgate.is_reviewed_api(flow.request.pretty_host, flow.request.path) and flow.response.status_code == 200:
            # iOS Shorts put protobuf player responses inside reel/next answers. Keep only
            # explicitly bounded API answers; an absent, invalid or oversized length streams
            # as before and therefore cannot register anything.
            # A missing length (chunked HTTP/1.1, most HTTP/2 answers) is kept whole too: these are API
            # answers, not media, and response() registers nothing above MAX_PLAYER_BYTES.
            declared = flow.response.headers.get("content-length")
            try:
                api_length = int(declared) if declared is not None else 0
            except ValueError:
                api_length = -1
            if 0 <= api_length <= ytgate.MAX_PLAYER_BYTES:
                return
        if authorization and is_sabr and 200 <= flow.response.status_code < 300 \
                and flow.response.headers.get("content-type", "").lower().split(";", 1)[0] == "application/vnd.yt-ump":
            # UMP is an unbounded media stream. Pass every byte through immediately,
            # while retaining only a small prefix in which SABR redirect/reload
            # control parts occur. Only this already-authorised HTTPS response can
            # delegate more stream keys, and delegated keys inherit its expiry.
            marker, expiry = authorization
            prefix = bytearray()
            registered: set[str] = set()
            allowed = self.yt.audio_itags(flow.request.pretty_url) if marker == ytgate.MUSIC_AUDIO else None
            guard = ytgate.UmpAudioGuard(allowed) if allowed is not None else None
            stopped = [False]

            def inspect_ump(chunk):
                if stopped[0]:
                    return b""
                if guard is not None and not guard.feed(chunk):
                    # An audio-only grant met a video (or unlabelled) format. mitmproxy cannot cut a flow in
                    # transit (mitmproxy#4711), so this chunk and every later byte are dropped as well.
                    stopped[0] = True
                    flow.metadata["aifilter_blocked"] = True
                    self.store.log("video-blocked", flow.request.pretty_host,
                                   f"music-audio grant, UMP itags {guard.itags[-3:]} not audio")
                    if flow.killable:
                        flow.kill()
                    return b""
                if chunk and len(prefix) < ytgate.MAX_UMP_INSPECT_BYTES:
                    prefix.extend(chunk[:ytgate.MAX_UMP_INSPECT_BYTES - len(prefix)])
                keys = ytgate.ump_redirect_keys(bytes(prefix), final=not chunk) - registered
                if keys and self.yt.register_streams(keys, marker, expires_at=expiry, audio_itags=allowed):
                    registered.update(keys)
                return chunk

            flow.response.stream = inspect_ump
            self._capture_youtube(flow, "response")
            return
        # HTTP 304/HEAD have no reviewable body. Trusted images are already cleared
        # by committee policy; never trust a mutable image URL/ETag as its digest.
        ctype = flow.response.headers.get("content-type", "").lower()
        if flow.request.method == "HEAD" or flow.response.status_code == 304 or (
                _looks_like_image(flow) and self._trusted(flow) and not self._text_only(flow)):
            flow.response.stream = True
            self._capture_youtube(flow, "response")
            return
        if not (_looks_like_image(flow) or _is_text(flow)):
            flow.response.stream = True  # nothing to review; do not buffer
            self._capture_youtube(flow, "response")
            return
        # A declared giant non-HTML text body is a file download, not a page: buffering it
        # whole would exhaust memory and time the client out. HTML is always reviewed.
        try:
            declared = int(flow.response.headers.get("content-length", "0"))
        except ValueError:
            declared = 0
        if declared > GIANT_TEXT_BYTES and not _looks_like_image(flow) and "html" not in ctype:
            flow.response.stream = True

    @timed
    async def response(self, flow: http.HTTPFlow):
        try:
            await self._response(flow)
        finally:
            self._capture_youtube(flow, "response")

    async def _response(self, flow: http.HTTPFlow):
        if self._unready(flow):
            return
        code = flow.response.status_code
        if code == 204 and flow.metadata.get("yt_init_control"):
            flow.response.content = b""
            flow.response.trailers = None
            # Forward only harmless headers: an unapproved video's setup answer reveals nothing.
            for header in list(flow.response.headers.keys()):
                if header.lower() not in ("date", "cache-control"):
                    flow.response.headers.pop(header, None)
            return
        if code < 200 or code in (204, 205, 304) or flow.request.method == "HEAD" or flow.response.stream:
            return
        if code in (301, 302, 303, 307, 308) and flow.response.headers.get("location"):
            # A redirect shows nothing itself; its target is reviewed when the client follows it.
            # Replacing it with a placeholder would cut the real picture off for good.
            return
        if (code >= 400 and not flow.response.raw_content
                and flow.request.pretty_host.lower() in ytgate.YT_IMAGE_HOSTS
                and (flow.metadata.get("yt_music_cover") or _looks_like_image(flow))):
            source = "filter" if flow.metadata.get("aifilter_blocked") else "upstream"
            self.store.log("image-fetch-error", flow.request.pretty_host.lower(), f"code={code} source={source}")
            return
        self._record_page(flow)
        if ytgate.is_player_api(flow.request.pretty_host, flow.request.path):
            await self._review_youtube_player(flow)
            return
        if ytgate.is_youtube_api(flow.request.pretty_host, flow.request.path):
            reviewed = await self._review_youtube_embedded(flow)
            if not reviewed:
                self._note_youtube_api(flow)
            self._yt_prefetch_from(flow)
        if flow.metadata.get("yt_music_cover"):
            await self._review_image(flow, music_cover=True)
        elif _looks_like_image(flow):
            if code == 206 and (self._text_only(flow) or not self._trusted(flow)):
                self._hide_image(flow)  # a partial image cannot be reviewed
            else:
                await self._review_image(flow)
        elif _is_text(flow):
            await self._review_page(flow)
            if not flow.metadata.get("aifilter_blocked") and flow.response.headers.get("content-type", "").lower().startswith(
                    ("text/html", "application/xhtml+xml")):
                await self._review_inline(flow)

    async def _review_youtube_player(self, flow: http.HTTPFlow):
        flow.metadata["aifilter_reviewed"] = True
        if flow.response.status_code != 200:
            return
        host = flow.request.pretty_host.lower()
        ok, channel, note = False, None, ""
        video = ""
        try:
            video = (parse_qs(urlsplit(flow.request.path).query).get("id") or [""])[0][:20]
        except Exception:  # noqa: BLE001
            video = ""
        try:
            # Only a real HTTPS answer from YouTube itself may register streams: Host, SNI and upstream must agree.
            if flow.request.scheme == "https" and _hosts(flow) == {host}:
                music_app = ytgate.is_music_app(flow.request.headers)
                self.yt.music_enabled = bool(self.cfg.get("youtube", "music_without_approval", False))
                # The check runs only with a picture-reading model: the detector-only judge passed adult Shorts.
                self.yt.checked_enabled = bool(self.cfg.get("youtube", "ai_check", False)) \
                    and bool(self.cfg.get("youtube", "ai_model", ""))
                body = flow.response.get_content(strict=False) or b""
                # Songs (audio track, cover only) stay free; music and podcast videos get the AI check (committee
                # 2026-11-16). Until the protobuf type is decoded, only formats explicitly labelled audio are granted.
                kind = ytgate.music_video_type(body) if music_app else ""
                music = self.yt.music_enabled and music_app and kind in ("MUSIC_VIDEO_TYPE_ATV", "")
                audio_only = music and not kind
                music_video = music_app and self.yt.music_enabled and not music
                if music_app:
                    note = f"music-type={kind or '?'} ctype={flow.response.headers.get('content-type', '')[:30]}"
                    if not kind:
                        _keep_music_sample(video, body)
                ok, channel = self.yt.review_player(body, music=music, audio_only=audio_only)
                if ok and music and channel not in self.yt.channels():
                    channel = f"{channel or 'unknown'} (music app)"
                elif not ok and channel and self.yt.checked_enabled and ytgate.answer_names_video(body, video):
                    # Not on the list: the AI check looks at this one video (words, transcript, frames).
                    passed, note = await self._yt_ai_check(video, channel)
                    if passed:
                        ok, _ = self.yt.review_player(body, checked=True)
                        note = "ai-checked " + note if ok else "ai-ok but no streams"
                    else:
                        note = "ai: " + note
                if music_video:
                    note = "music-video " + note
        except Exception:  # noqa: BLE001 - any failure is a no
            ok = False
        if not ok:  # the player shows an error at once instead of spinning on blocked streams
            flow.metadata["aifilter_blocked"] = True
            flow.response = http.Response.make(403, b"", {})
        else:
            flow.metadata["aifilter_registered"] = True
        try:
            self.store.log("yt-approved" if ok else "yt-blocked", host, f"video={video} channel={channel or 'unknown'} client="
                           f"{flow.request.headers.get('x-youtube-client-name', '')}/{flow.request.headers.get('user-agent', '')[:40]}"
                           + (f" {note[:160]}" if note else ""))
        except Exception:  # noqa: BLE001 - logging never changes the decision
            pass

    async def _review_youtube_embedded(self, flow: http.HTTPFlow) -> bool:
        """Review independently attributable player responses inside reel/next answers."""
        host = flow.request.pretty_host.lower()
        body = flow.response.get_content(strict=False) or b""
        players = ytgate.embedded_players(body)
        if not players:
            return False
        flow.metadata["aifilter_reviewed"] = True
        # The source requirements are identical to the direct /player path.
        if flow.request.scheme != "https" or _hosts(flow) != {host}:
            return False
        self.yt.checked_enabled = bool(self.cfg.get("youtube", "ai_check", False)) \
            and bool(self.cfg.get("youtube", "ai_model", ""))
        path = urlsplit(flow.request.path).path[:80]
        async def decide(video, channel, keys):
            # Only keys from this player's own streamingData are registered; no music shortcut here.
            ok, note = False, ""
            if channel in self.yt.channels():
                ok = self.yt.register_streams(keys, channel)
            elif self.yt.checked_enabled:
                passed, note = await self._yt_ai_check(video, channel)
                ok = passed and self.yt.register_streams(keys, ytgate.CHECKED)
                note = ("ai-checked " if passed else "ai: ") + note
            if ok:
                flow.metadata["aifilter_registered"] = True
            try:
                self.store.log("yt-approved" if ok else "yt-blocked", host,
                               f"video={video} channel={channel} embedded={path}"
                               + (f" {note[:160]}" if note else ""))
            except Exception:  # noqa: BLE001 - logging never changes the decision
                pass

        # A Shorts feed embeds several players: check them together, not one after another, so the
        # answer is held for the slowest check only (the review pool still bounds concurrency).
        try:  # hold the answer at most this long; an unfinished check approves nothing
            await asyncio.wait_for(asyncio.gather(*(decide(*c) for c in players)), EMBEDDED_TIMEOUT)
        except asyncio.TimeoutError:
            self.store.log("yt-blocked", host, f"embedded={path} check timed out")
        return True

    def _note_youtube_api(self, flow: http.HTTPFlow):
        """Diagnostics for a YouTube API answer whose streams could not be attributed safely."""
        try:
            if b"googlevideo.com" in (flow.response.get_content(strict=False) or b"")[:ytgate.MAX_PLAYER_BYTES]:
                path = urlsplit(flow.request.path).path[:80]
                self.store.log("yt-unreviewed", flow.request.pretty_host.lower(), f"path={path} client="
                               f"{flow.request.headers.get('x-youtube-client-name', '')}")
        except Exception:  # noqa: BLE001 - diagnostics never change a decision
            pass

    def _yt_policy(self) -> tuple[dict, tuple]:
        """The check's options and the policy key its verdicts are kept under (a policy or term-list change
        checks again)."""
        opts = {"faces": bool(self.cfg.get("vision", "block_female_faces", False)),
                "text_block_score": int(self.cfg.get("policy", "text_block_score", 6)),
                "model": str(self.cfg.get("youtube", "ai_model", "")),
                "modesty_mode": str(self.cfg.get("youtube", "modesty_mode", "strict"))}
        try:
            terms_stamp = text.TERMS_FILE.stat().st_mtime
        except OSError:
            terms_stamp = None
        return opts, (json.dumps(opts, sort_keys=True), terms_stamp, ytcheck.POLICY_VERSION)

    def _yt_kept(self, video: str, channel: str, policy: tuple) -> tuple[bool, str] | None:
        hit = self.__dict__.setdefault("_yt_verdicts", OrderedDict()).get((video, channel, policy))
        if hit and hit[0] > time.time():
            return hit[1], hit[2] + (" (prefetched)" if hit[3:] == ("prefetch",) else " (kept)")
        return None

    def _yt_keep(self, video: str, channel: str, policy: tuple, ok: bool, reason: str, source: str):
        """Only a completed check (ok or bad) is ever kept."""
        cache = self.__dict__.setdefault("_yt_verdicts", OrderedDict())
        cache[(video, channel, policy)] = (time.time() + ytcheck.VERDICT_TTL, ok, reason, source)
        while len(cache) > 5000:
            cache.popitem(last=False)

    def _yt_known(self, video: str) -> bool:
        """A prefetch is not needed: a verdict for this video is kept (any channel), or a real check runs now."""
        if video in self.__dict__.get("_yt_real_running", {}):
            return True
        _, policy = self._yt_policy()
        now = time.time()
        return any(k[0] == video and k[2] == policy and v[0] > now
                   for k, v in self.__dict__.get("_yt_verdicts", {}).items())

    def _yt_pool_for(self, opts: dict):
        """The real checks' pool. A changed option set closes both pools; the next checks start fresh workers."""
        if self.__dict__.get("_yt_pool") is None or self.__dict__.get("_yt_pool_opts") not in (None, opts):
            from aifilter.workers import ReviewPool

            if self.__dict__.get("_yt_pool") is not None:
                self._yt_pool.close()
            if self.__dict__.get("_yt_prefetch_pool") is not None:
                self._yt_prefetch_pool.close()
                self._yt_prefetch_pool = None
            size = max(1, min(3, int(self.cfg.get("youtube", "ai_workers", 1) or 1)))
            self._yt_pool = ReviewPool(size, dict(opts), factory=ytcheck.VideoReviewer)
            self._yt_pool_opts = opts
        return self._yt_pool

    def _yt_prefetch_pool_for(self, opts: dict):
        """Prefetch has its own worker process: it never takes a worker a real check could use."""
        self._yt_pool_for(opts)
        if self.__dict__.get("_yt_prefetch_pool") is None:
            from aifilter.workers import ReviewPool

            self._yt_prefetch_pool = ReviewPool(1, dict(opts), factory=ytcheck.VideoReviewer)
        return self._yt_prefetch_pool

    def _yt_timing(self, video: str, meta: dict, source: str):
        if meta.get("t"):
            try:
                self.store.log("yt-check-time", "youtubei.googleapis.com", f"video={video} {source} {meta['t'][:120]}")
            except Exception:  # noqa: BLE001 - diagnostics never change a decision
                pass

    async def _yt_ai_check(self, video: str, channel: str) -> tuple[bool, str]:
        """(passed, short reason) for one video of an unlisted channel. Verdicts are kept a week; a busy,
        slow or failed check is a no for now and is not kept, so the next try checks again.

        A real request never waits for prefetch: its own check starts at once. When a prefetch of the same video
        is already running, whichever completes first with a verdict for this exact channel decides."""
        if not ytcheck.valid_video(video):
            return False, "no video id"
        opts, policy = self._yt_policy()
        kept = self._yt_kept(video, channel, policy)
        if kept:
            return kept
        prefetcher = self.__dict__.get("_yt_prefetcher")
        running = None
        if prefetcher is not None:
            prefetcher.drop(video)
            running = prefetcher.inflight(video)
        check = asyncio.ensure_future(self._yt_real_check(video, channel, opts, policy))
        try:
            if running is not None and not running.done():
                await asyncio.wait({check, running}, return_when=asyncio.FIRST_COMPLETED)
                kept = None if check.done() else self._yt_kept(video, channel, policy)
                if kept:
                    # The real check finishes in the background and keeps its own verdict too.
                    check.add_done_callback(lambda t: t.cancelled() or t.exception())
                    return kept
            return await check
        except asyncio.CancelledError:
            check.cancel()
            raise

    async def _yt_real_check(self, video: str, channel: str, opts: dict, policy: tuple) -> tuple[bool, str]:
        pool = self._yt_pool_for(opts)
        running = self.__dict__.setdefault("_yt_real_running", {})
        running[video] = running.get(video, 0) + 1
        timeout = float(self.cfg.get("youtube", "ai_timeout_seconds", 15))
        try:  # the wait for a free worker counts too: a queue of checks never holds a video forever
            status, labels = await asyncio.wait_for(pool.review(json.dumps(
                {"video": video, "channel": channel, "meta": True}).encode(), timeout), timeout + 3)
        except asyncio.TimeoutError:
            status, labels = "busy", ["queue"]
        finally:
            running[video] -= 1
            if running[video] <= 0:
                running.pop(video, None)
        meta, reasons = _split_meta(labels)
        self._yt_timing(video, meta, "check")
        reason = ", ".join(reasons)[:200]
        if status == "error" and ytprefetch.BILLING_LABEL in reasons and self.__dict__.get("_yt_prefetcher"):
            self._yt_prefetcher.pause("judge billing/credit error on a real check")
        if status not in ("ok", "bad"):
            return False, f"{status} {reason}".strip()
        self._yt_keep(video, channel, policy, status == "ok", reason, "check")
        return status == "ok", reason

    async def _yt_prefetch_run(self, video: str) -> tuple[str, list[str]]:
        """One background check in the prefetch worker. Keeps a completed verdict under the channel the check
        read from YouTube; a failure keeps nothing."""
        opts, policy = self._yt_policy()
        if not opts["model"]:
            return "skipped", []
        pool = self._yt_prefetch_pool_for(opts)
        timeout = float(self.cfg.get("youtube", "ai_timeout_seconds", 15))
        try:
            status, labels = await asyncio.wait_for(pool.review(json.dumps(
                {"video": video, "channel": "", "prefetch": True, "meta": True}).encode(), timeout), timeout + 3)
        except asyncio.TimeoutError:
            status, labels = "busy", ["queue"]
        meta, reasons = _split_meta(labels)
        owner = meta.get("channel", "")
        self._yt_timing(video, meta, "prefetch")
        kept = status in ("ok", "bad") and bool(ytcheck._CHANNEL_ID.fullmatch(owner))
        if kept:
            self._yt_keep(video, owner, policy, status == "ok", ", ".join(reasons)[:200], "prefetch")
        try:
            self.store.log("yt-prefetch-done", "youtubei.googleapis.com",
                           f"video={video} status={status} kept={'yes' if kept else 'no'} {', '.join(reasons)[:120]}")
        except Exception:  # noqa: BLE001
            pass
        return status, reasons

    def _yt_prefetch_from(self, flow: http.HTTPFlow):
        """Queue background checks of the videos a Shorts feed answer lists next. Never changes this answer."""
        try:
            path = urlsplit(flow.request.path).path.rstrip("/")
            if path not in (ytprefetch.SEQUENCE_PATH, ytprefetch.NEXT_PATH) or flow.response.status_code != 200:
                return
            if not (self.cfg.get("youtube", "prefetch", False) and self.cfg.get("youtube", "ai_check", False)
                    and self.cfg.get("youtube", "ai_model", "")):
                return
            host = flow.request.pretty_host.lower()
            if flow.request.scheme != "https" or _hosts(flow) != {host} or ytgate.is_music_app(flow.request.headers):
                return
            ids = ytprefetch.upcoming_videos(flow.response.get_content(strict=False) or b"", path)
            prefetcher = self.__dict__.get("_yt_prefetcher")
            if prefetcher is None:
                def log(kind, detail):
                    try:
                        self.store.log(kind, "youtubei.googleapis.com", detail)
                    except Exception:  # noqa: BLE001
                        pass
                prefetcher = self._yt_prefetcher = ytprefetch.Prefetcher(
                    self._yt_prefetch_run, self._yt_known, log,
                    daily_max=int(self.cfg.get("youtube", "prefetch_daily_max", 150)),
                    budget_file=ytprefetch.BUDGET_FILE)
            prefetcher.daily_max = int(self.cfg.get("youtube", "prefetch_daily_max", 150))
            queued = prefetcher.offer(ids)
            if queued or not ids:
                self.store.log("yt-prefetch", host, f"path={path[-30:]} found={len(ids)} queued={','.join(queued)}")
        except Exception:  # noqa: BLE001 - prefetch never affects the answer
            pass

    async def _review_image(self, flow: http.HTTPFlow, *, music_cover=False):
        # IP-only page context can belong to another tab or an iframe. Permanent
        # strikes require a same-host image and Referer matching the observed page.
        page = self._page_host(flow)
        try:
            ref = (urlsplit(flow.request.headers.get("referer", "")).hostname or "").lower().rstrip(".")
        except ValueError:
            ref = ""
        if not ref or ref != flow.request.pretty_host.lower().rstrip(".") or ref != page:
            page = None
        if self._text_only(flow):
            self._hide_image(flow)
            return
        if not music_cover and self._trusted(flow):
            return
        data, complete = await _content_work(
            bodies.prefix, flow.response.raw_content or b"",
            flow.response.headers.get("content-encoding", ""), IMAGE_DECODE_BYTES, IMAGE_DECODE_BYTES)
        if not complete:
            self.store.log("image-unreviewed", page, flow.request.pretty_url[:200])
            if music_cover or self.cfg.get("vision", "on_busy", "hide") == "hide":
                self._hide_image(flow)
            return
        if not music_cover and "svg" in flow.response.headers.get("content-type", ""):
            # Vector art is not a photo, unless it smuggles an embedded raster image.
            if b"data:image" in data or b"<image" in data:
                self._hide_image(flow)
            return
        bad = await self._image_bad(data, flow, page, fail_closed=music_cover)
        if bad:
            self._hide_image(flow)

    async def _image_bad(self, data, flow, page, *, url_cache=True, fail_closed=False):
        # Old first-frame approvals must not bypass the new decoder/animation policy.
        policy = ("sample3-640-v2", self.cfg.get("vision", "level", "modest"),
                  self.cfg.get("vision", "min_score", 0.45), self.cfg.get("vision", "block_female_faces", False))
        digest = await _content_work(_image_digest, policy, data)
        bad = self.store.image_verdict(digest)
        identity = image_url.image_url_key(flow.request.pretty_url) if url_cache else ""
        url_key = "url:" + _image_digest(policy, identity.encode()) if identity else ""
        url_bad = self.store.image_verdict(url_key) if url_key else None
        # The URL key only ever blocks: one size or thumbnail judged bad hides every size and thumbnail of that
        # picture or video, but a good verdict never lets an unreviewed picture through (review of PR #4).
        if bad is True or url_bad is True:
            return True
        if bad is None:
            status, labels = await self._run_review(data)
            url = flow.request.pretty_url[:200]
            if status in ("invalid", "timeout", "error"):
                # Not evidence about the image: hide it this time, never cache it, never a strike.
                # Enough to tell a truncated body, an error page or an unknown format apart
                # (sizes, declared type and the first bytes only; never the picture itself).
                head = flow.response.headers
                self.store.log("image-error", page, f"{url} {status} {labels} code={flow.response.status_code} "
                               f"type={head.get('content-type', '')[:40]} enc={head.get('content-encoding', '')[:12]} "
                               f"len={len(data)} declared={head.get('content-length', '')[:12]} magic={data[:16].hex()}")
                return True
            if status == "unreviewed":
                self.store.log("image-unreviewed", page, url)
                return fail_closed or self.cfg.get("vision", "on_busy", "hide") == "hide"
            bad = status == "bad"
            self.store.set_image_verdict(digest, bad, ",".join(labels))
            if url_key and bad:
                self.store.set_image_verdict(url_key, True, ",".join(labels))
            if bad:
                self.store.log("image-blocked", page, f"{url} {labels}")
                if page:
                    self._strike(page)
        return bad

    def _strike(self, page: str):
        """Repeated bad images block the page's exact host (never its parent domain).

        Strikes expire, and infrastructure hosts (search engines, CDNs the Mac depends
        on) are never blocked automatically: their bad images are still hidden one by one."""
        days = self.cfg.get("policy", "strike_days", 7)
        if self.store.add_strike(page, days) >= self.cfg.get("policy", "bad_images_to_block_host", 3) \
                and not protected(page.lower()) and not _page_only_host(page):
            self.store.ai_block(page, "תמונות לא צנועות חוזרות")

    @staticmethod
    def _hide_image(flow: http.HTTPFlow):
        flow.response.status_code = 200
        flow.response.headers.pop("content-encoding", None)
        flow.response.headers.pop("content-range", None)
        flow.response.content = pages.PLACEHOLDER_PNG
        flow.response.headers["content-type"] = "image/png"
        # The placeholder must never be cached in place of the real picture: a hide can be
        # transient (reviewer busy, unreadable download), and the origin's long cache lifetime
        # would otherwise keep the picture hidden for months.
        for name in ("etag", "last-modified", "expires", "age"):
            flow.response.headers.pop(name, None)
        flow.response.headers["cache-control"] = "no-store"

    async def _run_review(self, data: bytes) -> tuple[str, list[str]]:
        """(status, labels); status is bad | ok | invalid | timeout | error | unreviewed.

        Production timeouts reap the worker before returning its permit. Injected
        test threads retain their permit until they finish."""
        if self._stopping:
            return "error", ["addon stopped"]
        timeout = self.cfg.get("vision", "timeout_seconds", 4.0)
        try:
            await asyncio.wait_for(self._sem.acquire(), self.cfg.get("vision", "queue_wait_seconds", timeout))
        except asyncio.TimeoutError:
            return "unreviewed", ["busy"]
        if self._stopping:
            self._sem.release()
            return "error", ["addon stopped"]
        if self._reviewer is None:
            # Production uses killable processes. The injected reviewer below is
            # retained for deterministic unit tests, never for loading a real model.
            try:
                if self._pool is None:
                    from aifilter.workers import ReviewPool

                    self._pool = ReviewPool(self.cfg.get("vision", "max_parallel", 2), {
                        "level": self.cfg.get("vision", "level", "modest"),
                        "min_score": self.cfg.get("vision", "min_score", 0.45),
                        "block_female_faces": self.cfg.get("vision", "block_female_faces", False),
                    })
                return await self._pool.review(data, timeout)
            except Exception as exc:
                return "error", [type(exc).__name__]
            finally:
                self._sem.release()
        try:
            task = asyncio.ensure_future(_content_work(self._review_sync, data))
        except BaseException:
            self._sem.release()
            raise
        task.add_done_callback(lambda _t: self._sem.release())
        task.add_done_callback(lambda t: t.cancelled() or t.exception())  # never "exception never retrieved"
        try:
            bad, labels = await asyncio.wait_for(asyncio.shield(task), timeout)
        except ValueError:
            return "invalid", []  # unreadable image: hide without a cached verdict/strike
        except asyncio.TimeoutError:
            return "timeout", ["timeout"]
        except Exception as e:  # noqa: BLE001 - model failure: hide this image, keep serving
            return "error", [type(e).__name__]
        return ("bad" if bad else "ok"), list(labels)

    async def _body_prefix(self, flow):
        raw = flow.response.raw_content or b""
        encoding = flow.response.headers.get("content-encoding", "")
        if not encoding or encoding.lower() == "identity":
            return raw[:text.MAX_SCAN_BYTES], len(raw) <= text.MAX_SCAN_BYTES
        return await _content_work(bodies.prefix, raw, encoding, text.MAX_SCAN_BYTES)

    async def _body_samples(self, flow):
        raw = flow.response.raw_content or b""
        encoding = flow.response.headers.get("content-encoding", "")
        if encoding.lower() not in ("", "identity"):
            raw, _ = await _content_work(bodies.prefix, raw, encoding, text.MAX_DECODE_BYTES)
        return text.sample_windows(raw)

    async def _review_page(self, flow: http.HTTPFlow, prefix=None):
        host = flow.request.pretty_host
        verdict = self.store.verdict(host)
        x_checked_page = self.cfg.get("x", "enabled", False) and xgate.is_page_host(host) and verdict == TEXT_ONLY
        if verdict is not None and not x_checked_page:
            return  # committee/domain decisions always precede a URL cache
        generation = getattr(self.store, "generation", None)
        if generation != self._text_generation:
            self._text_cache.clear()
            self._text_generation = generation
        # Limit bytes before charset decoding and parsing; never parse the full page.
        samples = await self._body_samples(flow)
        data = samples[0]
        encoding = infer_content_encoding(flow.response.headers.get("content-type", ""), data)
        plain = flow.response.headers.get("content-type", "").lower().startswith("text/plain")
        key = (flow.request.pretty_url, encoding.lower(), plain,
               hashlib.sha256(b"\0".join(samples)).digest())
        now = time.monotonic()
        cached = self._text_cache.get(key)
        if cached and cached[0] > now:
            total, hits, contextual = cached[1]
            self._text_cache.move_to_end(key)
        else:
            def assess_samples():
                total, hits, contextual = 0, set(), False
                for sample in samples:
                    try:
                        body = sample.decode(encoding, errors="replace")
                    except LookupError:
                        body = sample.decode("utf-8", errors="replace")
                    score, found, context = text.assess(body, self.terms, plain=True) if plain else text.assess(body, self.terms)
                    total += score
                    hits.update(found)
                    contextual |= context
                return total, sorted(hits), contextual
            total, hits, contextual = await _content_work(assess_samples)
            self._text_cache[key] = (now + 30, (total, hits, contextual))
            self._text_cache.move_to_end(key)
            if len(self._text_cache) > 1024:
                self._text_cache.popitem(last=False)
        # A committee decision may arrive while scoring runs in the worker.
        verdict = self.store.verdict(host)
        x_checked_page = self.cfg.get("x", "enabled", False) and xgate.is_page_host(host) and verdict == TEXT_ONLY
        if verdict is not None and not x_checked_page:
            if verdict == BLOCK:
                self._block(flow, host, "האתר סומן כחסום.")
            return
        if total >= self.cfg.get("policy", "text_block_score", 6) and len(hits) >= 2:
            # Safety/education discussions may trip the term rule. Restrict only
            # this response; one such page must never poison the host's verdict.
            # Search engines and big portals echo arbitrary text (suggestions,
            # snippets); a hit there restricts only this page, never the host.
            if contextual or len(samples) > 1 or _page_only_host(host) or self.store.ai_block(host, f"תוכן טקסט לא מתאים ({', '.join(hits[:5])})"):
                self.store.log("page-blocked", host, f"score={total} {hits[:8]}")
                self._block(flow, host, "התוכן באתר לא מתאים.")
                return
        self._schedule_site_judge(flow, host, data, encoding)

    def _schedule_site_judge(self, flow: http.HTTPFlow, host: str, data: bytes, encoding: str):
        """First web page of a host with no decision: ask the AI about the whole site in the background
        (aifilter/sitejudge.py). The page itself was already checked as usual and is not held."""
        try:
            model = str(self.cfg.get("sites", "ai_model", ""))
            if not (self.cfg.get("sites", "ai_judge", False) and model):
                return
            host = host.lower().rstrip(".")
            if not flow.response.headers.get("content-type", "").lower().startswith("text/html") \
                    or flow.request.headers.get("sec-fetch-dest", "document") != "document" \
                    or _page_only_host(host) or self._trusted(flow) or flow.request.scheme != "https":
                return
            judged = self.__dict__.setdefault("_site_judged", None)
            if judged is None:
                judged = self._site_judged = _load_site_judged()
            now = time.time()
            busy = self.__dict__.setdefault("_site_busy", set())
            if (judged.get(host) or [0])[0] > now or host in busy or len(busy) >= 4:
                return
            try:
                html = data.decode(encoding or "utf-8", errors="replace")
            except LookupError:
                html = data.decode("utf-8", errors="replace")
            from aifilter import sitejudge

            title, images = sitejudge.page_parts(html, flow.request.pretty_url)
            job = json.dumps({"host": host, "url": flow.request.pretty_url[:300], "title": title, "images": images,
                              "text": text.visible_text(html)[:sitejudge.MAX_TEXT]}).encode()
            busy.add(host)
            task = asyncio.ensure_future(self._site_judge(host, job, model))
            self.__dict__.setdefault("_site_tasks", set()).add(task)
            task.add_done_callback(self._site_tasks.discard)
        except Exception:  # noqa: BLE001 - the background check never changes this page
            pass

    async def _site_judge(self, host: str, job: bytes, model: str):
        from aifilter import sitejudge

        try:
            if self.__dict__.get("_site_pool") is None:
                from aifilter.workers import ReviewPool

                self._site_pool = ReviewPool(1, {"model": model}, factory=sitejudge.SiteReviewer)
            status, reasons = await self._site_pool.review(job, 25)
            reason = ", ".join(str(r) for r in reasons)[:160]
            if status not in ("ok", "bad"):
                self.store.log("site-unjudged", host, f"{status} {reason}")
                return  # no verdict kept: the next visit asks again
            self._site_judged[host] = [time.time() + sitejudge.VERDICT_DAYS * 86400, status, reason]
            _save_site_judged(self._site_judged)
            if status == "bad" and self.store.ai_block(host, f"בדיקת AI של האתר: {reason}"):
                self.store.log("site-judged", host, f"block: {reason}")
            else:
                self.store.log("site-judged", host, f"{'allow' if status == 'ok' else 'block (decided by committee)'}: {reason}")
        except Exception as exc:  # noqa: BLE001
            self.store.log("site-unjudged", host, type(exc).__name__)
        finally:
            self._site_busy.discard(host)

    async def _review_inline(self, flow, body_prefix=None):
        """Review entity-encoded and whitespace-folded data images in bounded HTML.

        Preserve original markup/charset; replace only matching URL byte spans.
        Blob/script-built/escaped media require a separate compatibility design.
        """
        if self._trusted(flow) and not self._text_only(flow):
            return
        ctype = flow.response.headers.get("content-type", "").lower()
        raw = flow.response.raw_content or b""
        if re.search(r"utf-?(16|32)|ucs-?[24]", ctype) or raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            # Not ASCII-compatible: the byte scan cannot see inline images, so forbid them.
            flow.response.headers.add("content-security-policy", NO_INLINE_CSP)
            return
        compressed = flow.response.headers.get("content-encoding", "").lower() not in ("", "identity")
        if compressed:
            data, complete = await _content_work(
                bodies.prefix, raw, flow.response.headers.get("content-encoding", ""), INLINE_SCAN_BYTES)
        else:
            data, complete = raw, len(raw) <= INLINE_SCAN_BYTES
        if not complete:
            # Too large to scan and rewrite safely: the browser refuses data:/blob: images instead.
            flow.response.headers.add("content-security-policy", NO_INLINE_CSP)
            return
        candidates, hidden, seen = [], [], set()
        for start, end, encoded in _inline_urls(data):
            try:
                image = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error):
                continue
            if _tiny_inline(image) and not self._text_only(flow):
                continue
            if image not in seen and len(seen) >= INLINE_REVIEW_MAX:
                hidden.append((start, end))  # over budget: hide, never pass unreviewed
                continue
            seen.add(image)
            candidates.append(((start, end), image))
        if not candidates and not hidden:
            return
        tasks = []
        try:
            if not self._text_only(flow):
                unique = {}
                for _, image in candidates:
                    if image not in unique:
                        unique[image] = asyncio.create_task(self._image_bad(image, flow, flow.request.pretty_host.lower(), url_cache=False))
                    tasks.append(unique[image])
                _, pending = await asyncio.wait(tasks, timeout=self.cfg.get("vision", "inline_timeout_seconds", 4.0))
                for task in pending:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
            replacements = []
            for i, ((start, end), _) in enumerate(candidates):
                task = tasks[i] if tasks else None
                bad = task is None or task.cancelled() or task.exception() is not None or task.result()
                replacements.append((start, end, INLINE_PLACEHOLDER if bad else data[start:end]))
            replacements += [(start, end, INLINE_PLACEHOLDER) for start, end in hidden]
            replacements.sort(key=lambda r: r[0])
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        if any(replacement != data[start:end] for start, end, replacement in replacements):
            rewritten = await _content_work(bodies.replace_spans, data, replacements)
            flow.response.headers.pop("content-encoding", None)
            for name in ("etag", "content-md5", "digest"):
                flow.response.headers.pop(name, None)
            flow.response.content = rewritten


try:
    addons = [AIFilter()]
except FileNotFoundError:  # imported by tests without a config
    addons = []
