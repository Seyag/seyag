"""Tailnet-only, resource-bounded media verdict service for Telegram clients."""
import base64, binascii, concurrent.futures, hashlib, hmac, io, ipaddress, json
import secrets, socket, sqlite3, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib import metadata
from pathlib import Path
from PIL import Image
from aifilter import config
from aifilter.vision import Reviewer

KINDS = {"sticker", "animated_emoji", "gif", "photo"}
TAILNETS = (ipaddress.ip_network("100.64.0.0/10"), ipaddress.ip_network("fd7a:115c:a1e0::/48"))
MAX_BODY = 3 * 1024 * 1024
POLICY_SCHEMA_VERSION = "telegram-media-v2"
SCHEMA = """
CREATE TABLE IF NOT EXISTS telegram_media_tokens(device TEXT PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS telegram_media_verdicts_v2(frame_digest TEXT NOT NULL,rules_version TEXT NOT NULL,kind TEXT NOT NULL,verdict TEXT NOT NULL CHECK(verdict IN ('allow','block')),updated REAL NOT NULL,PRIMARY KEY(frame_digest,rules_version,kind));
CREATE TABLE IF NOT EXISTS telegram_media_hints_v2(client_sha256 TEXT NOT NULL,frame_digest TEXT NOT NULL,rules_version TEXT NOT NULL,kind TEXT NOT NULL,verdict TEXT NOT NULL CHECK(verdict IN ('allow','block')),updated REAL NOT NULL,PRIMARY KEY(client_sha256,frame_digest,rules_version,kind));
CREATE INDEX IF NOT EXISTS telegram_media_hints_lookup ON telegram_media_hints_v2(client_sha256,rules_version,kind,verdict);
"""

def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()

def frames_digest(frames):
    digest = hashlib.sha256()
    for frame in frames:
        digest.update(len(frame).to_bytes(8, "big")); digest.update(frame)
    return digest.hexdigest()

def policy_version(level, min_score, block_female_faces, model_version=None):
    if model_version is None:
        try:
            model_version = f"nudenet-{metadata.version('nudenet')}"
        except metadata.PackageNotFoundError:
            model_version = "nudenet-unknown"
    value = json.dumps([POLICY_SCHEMA_VERSION, model_version, level, float(min_score),
                        bool(block_female_faces)], separators=(",", ":"))
    return hashlib.sha256(value.encode()).hexdigest()

class MediaStore:
    """Thread-safe, expiring, bounded store; bearer tokens are only stored hashed."""
    def __init__(self, path, max_cache=10_000, cache_ttl=7 * 86400):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock(); self.max_cache = max(1, int(max_cache)); self.cache_ttl = max(.001, float(cache_ttl))
        with self._lock: self._db.executescript(SCHEMA)
    def issue(self, device):
        token = secrets.token_urlsafe(32)
        with self._lock: self._db.execute("INSERT OR REPLACE INTO telegram_media_tokens VALUES(?,?,?)", (device, token_hash(token), time.time()))
        return token
    def revoke(self, device):
        with self._lock: cursor = self._db.execute("DELETE FROM telegram_media_tokens WHERE device=?", (device,))
        return bool(cursor.rowcount)
    def authenticate_device(self, token):
        digest = token_hash(token)
        with self._lock: rows = self._db.execute("SELECT device,token_hash FROM telegram_media_tokens").fetchall()
        return next((device for device, saved in rows if hmac.compare_digest(digest, saved)), None)
    def authenticated(self, token): return self.authenticate_device(token) is not None
    def _expire(self, now):
        cutoff = now - self.cache_ttl
        self._db.execute("DELETE FROM telegram_media_verdicts_v2 WHERE updated < ?", (cutoff,))
        self._db.execute("DELETE FROM telegram_media_hints_v2 WHERE updated < ?", (cutoff,))
    def verdict(self, digest, rules_version="legacy", kind="photo"):
        with self._lock:
            self._expire(time.time())
            row = self._db.execute("SELECT verdict FROM telegram_media_verdicts_v2 WHERE frame_digest=? AND rules_version=? AND kind=?", (digest, rules_version, kind)).fetchone()
        return row[0] if row else None
    def hint_blocked(self, client_digest, rules_version, kind):
        with self._lock:
            self._expire(time.time())
            row = self._db.execute("SELECT 1 FROM telegram_media_hints_v2 WHERE client_sha256=? AND rules_version=? AND kind=? AND verdict='block' LIMIT 1", (client_digest, rules_version, kind)).fetchone()
        return row is not None
    def set_verdict(self, digest, verdict, rules_version="legacy", kind="photo", client_digest=None):
        now = time.time()
        with self._lock:
            self._expire(now)
            self._db.execute("INSERT INTO telegram_media_verdicts_v2 VALUES(?,?,?,?,?) ON CONFLICT(frame_digest,rules_version,kind) DO UPDATE SET verdict=CASE WHEN verdict='block' OR excluded.verdict='block' THEN 'block' ELSE 'allow' END,updated=excluded.updated", (digest, rules_version, kind, verdict, now))
            final = self._db.execute("SELECT verdict FROM telegram_media_verdicts_v2 WHERE frame_digest=? AND rules_version=? AND kind=?", (digest, rules_version, kind)).fetchone()[0]
            if client_digest:
                self._db.execute("INSERT INTO telegram_media_hints_v2 VALUES(?,?,?,?,?,?) ON CONFLICT(client_sha256,frame_digest,rules_version,kind) DO UPDATE SET verdict=CASE WHEN verdict='block' OR excluded.verdict='block' THEN 'block' ELSE 'allow' END,updated=excluded.updated", (client_digest, digest, rules_version, kind, final, now))
            for table in ("telegram_media_verdicts_v2", "telegram_media_hints_v2"):
                self._db.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} ORDER BY updated DESC LIMIT -1 OFFSET ?)", (self.max_cache,))

class DeviceRateLimiter:
    def __init__(self, limit=30, window=60):
        self.limit, self.window = max(1, int(limit)), max(1, float(window)); self._requests = {}; self._lock = threading.Lock()
    def allow(self, device):
        now = time.monotonic()
        with self._lock:
            recent = [stamp for stamp in self._requests.get(device, ()) if now - stamp < self.window]
            if len(recent) >= self.limit: self._requests[device] = recent; return False
            recent.append(now); self._requests[device] = recent; return True

class BoundedHTTPServer(HTTPServer):
    """A fixed worker pool, rather than one thread per possibly-stalled socket."""
    def __init__(self, address, handler, max_workers=8):
        super().__init__(address, handler)
        workers = max(1, int(max_workers)); self._slots = threading.BoundedSemaphore(workers)
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="telegram-media-http")
    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        self._executor.submit(self._run, request, client_address)
    def _run(self, request, client_address):
        try: self.finish_request(request, client_address)
        except Exception: self.handle_error(request, client_address)
        finally: self.shutdown_request(request); self._slots.release()
    def server_close(self):
        super().server_close(); self._executor.shutdown(wait=True, cancel_futures=True)

def tailnet_source(address):
    try: ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError: return False
    return any(ip in network for network in TAILNETS)

def _frames(value):
    if not isinstance(value, list) or len(value) > 3: raise ValueError("frames must be an array of at most 3 JPEGs")
    decoded = []
    for encoded in value:
        if not isinstance(encoded, str): raise ValueError("frame must be base64")
        try: data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc: raise ValueError("frame must be valid base64") from exc
        try:
            with Image.open(io.BytesIO(data)) as image:
                if image.format != "JPEG" or max(image.size) > 512 or min(image.size) < 1: raise ValueError("frame must be a JPEG no larger than 512px")
                image.verify()
        except (OSError, Image.DecompressionBombError) as exc: raise ValueError("frame must be a valid JPEG") from exc
        decoded.append(data)
    return decoded

def make_handler(enabled, store, reviewer, source_allowed=tailnet_source, *, rules_version="legacy", rate_limiter=None, inference_workers=2, inference_timeout=4.0, socket_timeout=5.0):
    limiter = rate_limiter or DeviceRateLimiter()
    inference = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, int(inference_workers)), thread_name_prefix="telegram-media-inference")
    slots = threading.BoundedSemaphore(max(1, int(inference_workers)))
    class Handler(BaseHTTPRequestHandler):
        def setup(self): self.request.settimeout(socket_timeout); super().setup()
        def log_message(self, *_args): pass
        def _json(self, code, value):
            body = json.dumps(value, separators=(",", ":")).encode(); self.send_response(code)
            self.send_header("content-type", "application/json"); self.send_header("content-length", str(len(body))); self.send_header("cache-control", "no-store"); self.end_headers(); self.wfile.write(body)
        def do_POST(self):
            if self.path != "/v1/media-verdict": return self._json(404, {"error": "not found"})
            if not source_allowed(self.client_address[0]): return self._json(403, {"error": "tailnet only"})
            if not enabled: return self._json(200, {"verdict": "unknown", "disabled": True})
            auth = self.headers.get("authorization", ""); device = store.authenticate_device(auth[7:]) if auth.startswith("Bearer ") else None
            if device is None: return self._json(401, {"error": "unauthorized"})
            if not limiter.allow(device): return self._json(429, {"error": "rate limit"})
            try:
                length = int(self.headers.get("content-length", ""))
                if length < 0 or length > MAX_BODY: raise ValueError("invalid body size")
                raw = self.rfile.read(length)
                if len(raw) != length: raise ValueError("incomplete body")
                body = json.loads(raw)
                if not isinstance(body, dict) or body.get("kind") not in KINDS: raise ValueError("invalid kind")
                kind = body["kind"]; client_digest = body.get("sha256", "").lower()
                if len(client_digest) != 64 or any(c not in "0123456789abcdef" for c in client_digest): raise ValueError("invalid sha256")
                frames = _frames(body.get("frames", []))
            except (ValueError, TypeError, json.JSONDecodeError, socket.timeout) as exc: return self._json(400, {"error": str(exc) or "body timeout"})
            if store.hint_blocked(client_digest, rules_version, kind): return self._json(200, {"verdict": "block", "cached": True})
            if not frames: return self._json(200, {"verdict": "unknown"})
            server_digest = frames_digest(frames); cached = store.verdict(server_digest, rules_version, kind)
            if cached is not None:
                store.set_verdict(server_digest, cached, rules_version, kind, client_digest)
                return self._json(200, {"verdict": cached, "cached": True})
            if not slots.acquire(timeout=inference_timeout): return self._json(200, {"verdict": "unknown"})
            try:
                future = inference.submit(lambda: any(reviewer.review(frame)[0] for frame in frames))
                future.add_done_callback(lambda _future: slots.release())
                bad = future.result(timeout=inference_timeout)
            except Exception: return self._json(200, {"verdict": "unknown"})
            verdict = "block" if bad else "allow"; store.set_verdict(server_digest, verdict, rules_version, kind, client_digest)
            return self._json(200, {"verdict": store.verdict(server_digest, rules_version, kind), "cached": False})
    return Handler

def main():
    cfg = config.load(); enabled = bool(cfg.get("telegram_media", "enabled", False)); bind = cfg.get("telegram_media", "bind", cfg.get("admin", "bind", "127.0.0.1")); port = int(cfg.get("telegram_media", "port", 8120))
    store = MediaStore(config.db_path(), cfg.get("telegram_media", "max_cache_entries", 10_000), cfg.get("telegram_media", "cache_ttl_seconds", 7 * 86400))
    level = cfg.get("vision", "level", "modest"); score = cfg.get("vision", "min_score", 0.45); faces = cfg.get("vision", "block_female_faces", False)
    reviewer = Reviewer(level=level, min_score=score, block_female_faces=faces) if enabled else None
    handler = make_handler(enabled, store, reviewer, rules_version=policy_version(level, score, faces), rate_limiter=DeviceRateLimiter(cfg.get("telegram_media", "requests_per_minute", 30)), inference_workers=cfg.get("telegram_media", "max_parallel", 2), inference_timeout=cfg.get("telegram_media", "inference_timeout_seconds", 4), socket_timeout=cfg.get("telegram_media", "socket_timeout_seconds", 5))
    print(f"telegram media verdict on http://{bind}:{port} (enabled={enabled})", flush=True)
    BoundedHTTPServer((bind, port), handler, cfg.get("telegram_media", "http_workers", 8)).serve_forever()
if __name__ == "__main__": main()
