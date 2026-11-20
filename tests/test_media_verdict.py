import base64
import hashlib
import http.client
import io
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer

from PIL import Image

from aifilter.media_verdict import (
    BoundedHTTPServer,
    DeviceRateLimiter,
    MediaStore,
    frames_digest,
    make_handler,
    policy_version,
    tailnet_source,
)


class FakeReviewer:
    def __init__(self, bad=False, error=False):
        self.bad = bad
        self.error = error
        self.calls = 0

    def review(self, _data):
        self.calls += 1
        if self.error:
            raise RuntimeError("model unavailable")
        return self.bad, ["FACE_FEMALE:0.9"] if self.bad else []


def jpeg(size=(32, 20)):
    output = io.BytesIO()
    Image.new("RGB", size, "white").save(output, "JPEG")
    return base64.b64encode(output.getvalue()).decode()


class Service:
    def __init__(self, handler):
        self.handler = handler

    def __enter__(self):
        self.worker = ThreadPoolExecutor(max_workers=1)
        return self

    def request(self, body, token=None, path="/v1/media-verdict"):
        # Exercise real HTTP framing over a connected pair without opening a listener.
        headers = {"content-type": "application/json"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        client, server = socket.socketpair()
        with client, server:
            client.settimeout(5)
            handled = self.worker.submit(self.handler, server, ("127.0.0.1", 0), None)
            conn = http.client.HTTPConnection("localhost")
            conn.sock = client
            try:
                conn.request("POST", path, json.dumps(body), headers)
                response = conn.getresponse()
                result = response.status, json.loads(response.read())
                handled.result(timeout=5)
            finally:
                conn.close()
        return result

    def __exit__(self, *_args):
        self.worker.shutdown()


def body(**changes):
    value = {"sha256": "a" * 64, "kind": "photo", "frames": [jpeg()]}
    value.update(changes)
    return value


def test_disabled_returns_contract_without_auth(tmp_path):
    store = MediaStore(tmp_path / "db")
    with Service(make_handler(False, store, None, source_allowed=lambda _ip: True)) as service:
        assert service.request({}) == (200, {"verdict": "unknown", "disabled": True})


def test_public_source_is_rejected_even_while_disabled(tmp_path):
    with Service(make_handler(False, MediaStore(tmp_path / "db"), None,
                              source_allowed=lambda _ip: False)) as service:
        assert service.request({})[0] == 403


def test_tokens_are_hashed_and_revoked(tmp_path):
    store = MediaStore(tmp_path / "db")
    token = store.issue("iphone")
    assert token not in (tmp_path / "db").read_bytes().decode("latin1")
    assert store.authenticated(token)
    assert store.revoke("iphone")
    assert not store.authenticated(token)
    assert not store.revoke("iphone")


def test_review_and_hash_only_cache(tmp_path):
    store = MediaStore(tmp_path / "db")
    token = store.issue("iphone")
    reviewer = FakeReviewer(bad=True)
    handler = make_handler(True, store, reviewer, source_allowed=lambda _ip: True)
    with Service(handler) as service:
        assert service.request(body(), token) == (200, {"verdict": "block", "cached": False})
        assert service.request(body(frames=[]), token) == (200, {"verdict": "block", "cached": True})
    assert reviewer.calls == 1


def test_clean_frames_cannot_poison_client_hash_allow(tmp_path):
    """An allow for unrelated samples must never make a client hash-only request safe."""
    store = MediaStore(tmp_path / "db")
    token = store.issue("iphone")
    reviewer = FakeReviewer()
    with Service(make_handler(True, store, reviewer, source_allowed=lambda _ip: True)) as service:
        assert service.request(body(), token)[1]["verdict"] == "allow"
        assert service.request(body(frames=[]), token) == (200, {"verdict": "unknown"})


def test_concurrent_allow_cannot_overwrite_block(tmp_path):
    store = MediaStore(tmp_path / "db")
    digest = "f" * 64
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda verdict: store.set_verdict(digest, verdict), ["block", "allow"]))
    assert store.verdict(digest) == "block"


def test_unknown_hash_and_model_error_are_not_cached(tmp_path):
    store = MediaStore(tmp_path / "db")
    token = store.issue("iphone")
    with Service(make_handler(True, store, FakeReviewer(error=True),
                              source_allowed=lambda _ip: True)) as service:
        assert service.request(body(frames=[]), token) == (200, {"verdict": "unknown"})
        assert service.request(body(), token) == (200, {"verdict": "unknown"})
    assert store.verdict("a" * 64) is None


def test_policy_and_media_kind_are_part_of_cache_key(tmp_path):
    store = MediaStore(tmp_path / "db")
    token = store.issue("iphone")
    first = FakeReviewer()
    strict = FakeReviewer(bad=True)
    with Service(make_handler(True, store, first, source_allowed=lambda _ip: True,
                              rules_version="old")) as service:
        assert service.request(body(), token)[1]["verdict"] == "allow"
    with Service(make_handler(True, store, strict, source_allowed=lambda _ip: True,
                              rules_version="strict")) as service:
        assert service.request(body(), token)[1] == {"verdict": "block", "cached": False}
    assert policy_version("basic", .45, False) != policy_version("modest", .45, False)
    assert store.verdict(frames_digest([base64.b64decode(jpeg())]), "strict", "gif") is None


def test_rate_inference_deadline_and_cache_maintenance_are_bounded(tmp_path):
    class SlowReviewer(FakeReviewer):
        def review(self, data):
            time.sleep(.15)
            return super().review(data)

    store = MediaStore(tmp_path / "db", max_cache=1, cache_ttl=.02)
    token = store.issue("iphone")
    handler = make_handler(True, store, SlowReviewer(), source_allowed=lambda _ip: True,
                           rate_limiter=DeviceRateLimiter(limit=2), inference_workers=1,
                           inference_timeout=.02)
    with Service(handler) as service:
        assert service.request(body(sha256="1" * 64), token)[1]["verdict"] == "unknown"
        assert service.request(body(sha256="2" * 64, frames=[]), token)[1]["verdict"] == "unknown"
        assert service.request(body(sha256="3" * 64), token)[0] == 429

    store.set_verdict("1" * 64, "block")
    store.set_verdict("2" * 64, "block")
    assert store.verdict("1" * 64) is None  # oldest row pruned
    time.sleep(.03)
    assert store.verdict("2" * 64) is None  # remaining row expired


def test_http_server_uses_fixed_worker_pool(tmp_path, monkeypatch):
    handler = make_handler(False, MediaStore(tmp_path / "db"), None,
                           source_allowed=lambda _ip: True)
    monkeypatch.setattr(HTTPServer, "server_bind", lambda self: None)
    monkeypatch.setattr(HTTPServer, "server_activate", lambda self: None)
    server = BoundedHTTPServer(("127.0.0.1", 0), handler, max_workers=2)
    try:
        assert server._executor._max_workers == 2
    finally:
        server.server_close()


def test_auth_and_request_limits(tmp_path):
    store = MediaStore(tmp_path / "db")
    token = store.issue("iphone")
    with Service(make_handler(True, store, FakeReviewer(), source_allowed=lambda _ip: True)) as service:
        assert service.request(body())[0] == 401
        assert service.request(body(kind="video"), token)[0] == 400
        assert service.request(body(sha256="not-a-hash"), token)[0] == 400
        assert service.request(body(frames=[jpeg()] * 4), token)[0] == 400
        assert service.request(body(frames=[jpeg((513, 10))]), token)[0] == 400
        assert service.request(body(frames=[base64.b64encode(b"not jpeg").decode()]), token)[0] == 400


def test_tailnet_source_ranges():
    tailnet = ipaddress.ip_network("100.64.0.0/10")
    assert tailnet_source(str(tailnet[0]))
    assert tailnet_source(str(tailnet[-1]))
    assert tailnet_source("fd7a:115c:a1e0::1")
    assert not tailnet_source(str(tailnet[-1] + 1))
    assert not tailnet_source("127.0.0.1")
