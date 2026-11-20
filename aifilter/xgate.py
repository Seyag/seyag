"""Fail-closed media gate for X/Twitter.

Media is approved only by exact canonical URL and content identity. HLS masters
are restricted to one fully checked lowest-bandwidth rendition, and checked
playlist/media bytes are served to the client rather than fetched again.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import math
import re
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

VIDEO_ID = re.compile(r"/(?:ext_tw_video|amplify_video|tweet_video)/(\d+)(?:/|$)")
LIVE_HOSTS = ("broadcast.twitter.com", "pscp.tv", "live-video.net")
MAX_DOWNLOAD, MAX_FRAMES, MAX_HLS_RESOURCES = 40 * 1024 * 1024, 120, 512
VERDICT_TTL, MAX_VERDICTS = 24 * 60 * 60, 2000
MAX_CACHE_BYTES = 256 * 1024 * 1024  # retained approved bodies, all entries together


def video_id(url):
    try:
        match = VIDEO_ID.search(urlsplit(url).path)
    except ValueError:
        return None
    return match.group(1) if match else None


def canonical_url(url):
    """Canonical exact asset key; X media queries remain representation-significant."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().rstrip(".")
    netloc = host
    if parts.port and not (parts.scheme.lower() == "https" and parts.port == 443):
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, ""))


def _host(host, suffix):
    host = (host or "").lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix)


def is_video_host(host):
    return _host(host, "video.twimg.com")


def is_picture_host(host):
    return _host(host, "pbs.twimg.com")


def is_page_host(host):
    host = (host or "").lower().rstrip(".")
    return host in ("x.com", "api.x.com", "twitter.com") or host.endswith(
        (".x.com", ".twitter.com")
    )


def is_live_host(host):
    return any(_host(host, suffix) for suffix in LIVE_HOSTS)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _validate_url(url):
    parts = urlsplit(url)
    if (
        parts.scheme != "https"
        or not is_video_host(parts.hostname or "")
        or parts.username
        or parts.password
    ):
        raise ValueError("media URL is not HTTPS on video.twimg.com")


def _read(url, limit=MAX_DOWNLOAD):
    _validate_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "ai-filter/1"})
    try:
        with urllib.request.build_opener(_NoRedirect()).open(
            request, timeout=10
        ) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as exc:
        if 300 <= exc.code < 400:
            raise ValueError("media redirect refused") from exc
        raise
    if not data or len(data) > limit:
        raise ValueError("empty or oversized media")
    return data


def _lowest_hls(manifest_url, body):
    lines, choices = body.decode("utf-8").splitlines(), []
    for index, line in enumerate(lines):
        if line.startswith("#EXT-X-STREAM-INF:"):
            attrs = dict(
                part.split("=", 1)
                for part in line.split(":", 1)[1].split(",")
                if "=" in part
            )
            target = next(
                (
                    v.strip()
                    for v in lines[index + 1 :]
                    if v.strip() and not v.startswith("#")
                ),
                "",
            )
            if target:
                choices.append(
                    (
                        int(attrs.get("BANDWIDTH", "999999999")),
                        urljoin(manifest_url, target),
                    )
                )
    return min(choices)[1] if choices else manifest_url


class VideoChecker:
    """Download a bounded local asset and uniformly review its entire duration."""

    def __init__(self, reviewer=None, fetch=_read):
        self.reviewer, self.fetch = reviewer, fetch
        self.cancel = threading.Event()
        self._processes = set()
        self._process_lock = threading.Lock()
        self._local = threading.local()  # per-check byte budget: each executor thread runs one check

    def close(self):
        """Cancel work and terminate/reap every child within two seconds."""
        self.cancel.set()
        with self._process_lock:
            processes = list(self._processes)
        for process in processes:
            if process.poll() is None:
                process.terminate()
        deadline = time.monotonic() + 2
        for process in processes:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def _run(self, command, **kwargs):
        timeout = kwargs.pop("timeout", 15)
        check = kwargs.pop("check", True)
        if kwargs.pop("capture_output", False):
            # Popen has no capture_output (only subprocess.run does); every X video check raised TypeError.
            # Only stdout is captured (ffprobe prints one number); stderr is discarded so a full pipe cannot stall the poll loop.
            kwargs["stdout"], kwargs["stderr"] = subprocess.PIPE, subprocess.DEVNULL
        process = subprocess.Popen(command, **kwargs)
        with self._process_lock:
            self._processes.add(process)
        try:
            deadline = time.monotonic() + timeout
            while process.poll() is None:
                if self.cancel.wait(.05):
                    process.terminate()
                    raise RuntimeError("cancelled")
                if time.monotonic() >= deadline:
                    process.kill()
                    raise subprocess.TimeoutExpired(command, timeout)
            stdout, _ = process.communicate()
            if check and process.returncode:
                raise subprocess.CalledProcessError(process.returncode, command)
            return type("Completed", (), {"stdout": stdout})()
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            with self._process_lock:
                self._processes.discard(process)

    def _fetch(self, url):
        _validate_url(url)
        if self.cancel.is_set():
            raise RuntimeError("cancelled")
        used = getattr(self._local, "used", 0)
        data = self.fetch(url, MAX_DOWNLOAD - used)
        self._local.used = used + len(data)
        if self._local.used > MAX_DOWNLOAD:
            raise ValueError("oversized media")
        return data

    def _local_hls(self, master_url, master, folder):
        chosen = _lowest_hls(master_url, master)
        if chosen == master_url:
            raise ValueError("master has no variant")
        body = self._fetch(chosen)
        assets = {canonical_url(chosen): body}
        while b"#EXT-X-STREAM-INF:" in body:
            chosen = _lowest_hls(chosen, body)
            body = self._fetch(chosen)
            assets[canonical_url(chosen)] = body
        lines, counter = [], 0
        for line in body.decode("utf-8").splitlines():
            rewritten = line
            refs = [] if not line or line.startswith("#") else [(line, line)]
            refs += [
                (m.group(1), m.group(0)) for m in re.finditer(r'URI="([^"]+)"', line)
            ]
            for ref, token in refs:
                if counter >= MAX_HLS_RESOURCES:
                    raise ValueError("too many HLS resources")
                target = urljoin(chosen, ref)
                _validate_url(target)
                local = (
                    folder
                    / f"resource-{counter:04d}{Path(urlsplit(target).path).suffix or '.bin'}"
                )
                counter += 1
                checked = self._fetch(target)
                assets[canonical_url(target)] = checked
                local.write_bytes(checked)
                replacement = (
                    f'URI="{local}"' if token.startswith("URI=") else str(local)
                )
                rewritten = rewritten.replace(token, replacement)
            lines.append(rewritten)
        playlist = folder / "playlist.m3u8"
        playlist.write_text("\n".join(lines) + "\n", encoding="utf-8")
        rewritten_master = ("#EXTM3U\n#EXT-X-STREAM-INF:BANDWIDTH=1\n" + chosen + "\n").encode()
        assets[canonical_url(master_url)] = rewritten_master
        return playlist, assets

    def check(self, url):
        if self.reviewer is None:
            from aifilter.vision import Reviewer
            reviewer = Reviewer()
        else:
            reviewer = self.reviewer

        self._local.used = 0
        data = self._fetch(url)
        hls = urlsplit(url).path.lower().endswith(".m3u8") or data.lstrip().startswith(
            b"#EXTM3U"
        )
        with tempfile.TemporaryDirectory(prefix="aifilter-x-") as name:
            folder = Path(name)
            if hls:
                source, assets = self._local_hls(url, data, folder)
            else:
                source = folder / (
                    "source" + (Path(urlsplit(url).path).suffix or ".mp4")
                )
                source.write_bytes(data)
                assets = {canonical_url(url): data}
            probe = self._run(
                [
                    "ffprobe",
                    "-v",
                    "error",
                    "-protocol_whitelist",
                    "file",
                    "-show_entries",
                    "format=duration",
                    "-of",
                    "default=nw=1:nk=1",
                    str(source),
                ],
                check=True,
                timeout=15,
                capture_output=True,
                text=True,
            )
            try:
                duration = float(probe.stdout.strip())
            except ValueError as exc:
                raise ValueError("unknown video duration") from exc
            if not math.isfinite(duration) or duration <= 0:
                raise ValueError("unknown video duration")
            count = min(MAX_FRAMES, max(1, math.ceil(duration / 2)))
            stamps = [duration * i / count for i in range(count)]
            reasons = []
            for index, stamp in enumerate(stamps):
                frame = folder / f"frame-{index:03d}.jpg"
                self._run(
                    [
                        "ffmpeg",
                        "-v",
                        "error",
                        "-protocol_whitelist",
                        "file",
                        "-ss",
                        str(stamp),
                        "-i",
                        str(source),
                        "-frames:v",
                        "1",
                        str(frame),
                    ],
                    check=True,
                    timeout=15,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if not frame.exists():
                    raise ValueError("missing sampled frame")
                bad, labels = reviewer.review(frame.read_bytes())
                if bad:
                    reasons.extend(labels)
            # Seeking from EOF and reversing the tail obtains the actual final
            # decodable frame. Missing output is a failed check.
            final = folder / "frame-final.jpg"
            self._run([
                "ffmpeg", "-v", "error", "-protocol_whitelist", "file",
                "-sseof", "-3", "-i", str(source), "-vf", "reverse",
                "-frames:v", "1", str(final),
            ], check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if not final.exists() or not final.stat().st_size:
                raise ValueError("missing final frame")
            bad, labels = reviewer.review(final.read_bytes())
            if bad:
                reasons.extend(labels)
            identities = {key: (hashlib.sha256(body).hexdigest(), body)
                          for key, body in assets.items()}
            return not reasons, reasons, identities if not reasons else {}


class Gate:
    """Two-worker gate whose allowlist and pending work use exact canonical URLs."""

    def __init__(self, checker=None, timeout=20):
        self._checker_object = VideoChecker() if checker is None else None
        self.checker = checker or self._checker_object.check
        self.timeout = timeout
        self.verdicts, self.pending, self._sync_pending = OrderedDict(), {}, {}
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="x-video")
        self._held = 0
        self._bytes = 0

    def close(self):
        if self._checker_object and hasattr(self._checker_object, "close"):
            self._checker_object.close()
        for future in list(self.pending.values()) + list(self._sync_pending.values()):
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def begin(self, url=None):
        key = canonical_url(url) if url else None
        if self._held >= 8 or (key not in self.pending and len(self.pending) >= 8):
            return False
        self._held += 1
        return True

    def _cached(self, url):
        key = canonical_url(url)
        item = self.verdicts.get(key)
        if not item or item[0] <= time.monotonic():
            self._drop(key)
            return None
        self.verdicts.move_to_end(key)
        return True, "checked", item[2]

    def known(self, url):
        media_id = video_id(url)
        if media_id is None:
            return False, "missing media id", None, None
        cached = self._cached(url)
        return (*cached, media_id) if cached else None

    @staticmethod
    def _entrypoint(url):
        suffix = Path(urlsplit(url).path).suffix.lower()
        return suffix in (".mp4", ".m3u8") or not suffix

    def _drop(self, key):
        item = self.verdicts.pop(key, None)
        if item:
            self._bytes -= len(item[2] or b"")

    def _save(self, value):
        approved, reasons, *rest = value
        assets = rest[0] if rest and isinstance(rest[0], dict) else {}
        if approved:
            expiry = time.monotonic() + VERDICT_TTL
            if sum(len(body or b"") for _digest, body in assets.values()) > MAX_CACHE_BYTES // 4:
                return False, "too large to keep checked bytes"  # fail closed, never serve unchecked bytes
            for key, (digest, body) in assets.items():
                self._drop(key)
                self.verdicts[key] = (expiry, digest, body)
                self._bytes += len(body or b"")
            while self.verdicts and (len(self.verdicts) > MAX_VERDICTS or self._bytes > MAX_CACHE_BYTES):
                self._drop(next(iter(self.verdicts)))
        return bool(approved), ",".join(reasons) if reasons else "checked"

    def allowed_sync(self, url):
        media_id, key = video_id(url), canonical_url(url)
        if media_id is None:
            return False, "missing media id", None, None
        cached = self._cached(url)
        if cached:
            return *cached, media_id
        if not self._entrypoint(url):
            return False, "URL was not checked", None, media_id
        future = self._sync_pending.get(key)
        if future is None:
            future = self._executor.submit(self.checker, url)
            self._sync_pending[key] = future
            future.add_done_callback(lambda f, k=key: self._sync_pending.pop(k, None))
        try:
            ok, reason = self._save(future.result(timeout=self.timeout))
            cached = self._cached(url)
            return ok, reason, cached[2] if cached else None, media_id
        except concurrent.futures.TimeoutError:
            return False, "check pending/timeout", None, media_id
        except Exception as exc:
            return False, type(exc).__name__, None, media_id

    async def allowed(self, url):
        media_id, key = video_id(url), canonical_url(url)
        try:
            if media_id is None:
                return False, "missing media id", None, None
            cached = self._cached(url)
            if cached:
                return *cached, media_id
            if not self._entrypoint(url):
                return False, "URL was not checked", None, media_id
            future = self.pending.get(key)
            if future is None:
                future = asyncio.get_running_loop().run_in_executor(self._executor, self.checker, url)
                self.pending[key] = future
                future.add_done_callback(lambda f, k=key: self.pending.pop(k, None))
                future.add_done_callback(lambda f: f.cancelled() or f.exception())
            try:
                ok, reason = self._save(await asyncio.wait_for(asyncio.shield(future), self.timeout))
                cached = self._cached(url)
                return ok, reason, cached[2] if cached else None, media_id
            except asyncio.TimeoutError:
                return False, "check pending/timeout", None, media_id
            except Exception as exc:
                return False, type(exc).__name__, None, media_id
        finally:
            self._held = max(0, self._held - 1)
