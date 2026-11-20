"""Background AI checks of the next Shorts (maintainer decision).

A Shorts feed answer (`/youtubei/v1/reel/reel_watch_sequence`, and a JSON `/next`) lists the videos the app will
show next. Their AI check (aifilter/ytcheck.py) takes about 4-6 s each. Checking the next few ahead of time, in
their own low-priority worker, lets the swipe find a finished verdict in the cache.

Nothing here decides anything: a prefetch runs exactly the same check as a real request and only a completed
check ("ok" or "bad") is kept, under the channel the check itself read from YouTube. A real request uses the
verdict only when that channel equals the one its own player answer names, exactly as for a normal kept verdict.
A failed, timed-out, cancelled or skipped prefetch keeps nothing.

Limits: at most MAX_PER_RESPONSE new videos per answer, MAX_PER_MINUTE per minute, MAX_PENDING waiting, and a daily
cap on prefetch checks (each makes at most one paid model call). A billing or credit error from the judge pauses
prefetch for PAUSE_SECONDS. Real checks never wait for prefetch and are never limited by it.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections import deque
from pathlib import Path

from aifilter import ytgate

MAX_PER_RESPONSE = 3
MAX_PER_MINUTE = 10
MAX_PENDING = 6
MAX_CANDIDATES = 12  # ids read from one answer, in order, before the known ones are skipped
MAX_DEPTH = 24
PAUSE_SECONDS = 3600
BILLING_LABEL = "BillingError"  # ytcheck.BillingError, as the worker pool reports it
BUDGET_FILE = Path(__file__).resolve().parent.parent / "data" / "yt-prefetch-budget.json"
_VIDEO_ID = re.compile(rb"[A-Za-z0-9_-]{11}")
SEQUENCE_PATH = "/youtubei/v1/reel/reel_watch_sequence"
NEXT_PATH = "/youtubei/v1/next"


def _json_ids(value, keys: tuple[str, ...]) -> list[str]:
    """videoId values of the named endpoint objects, in document order."""
    out: list[str] = []
    stack = [(value, 0)]
    while stack and len(out) < MAX_CANDIDATES * 4:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            continue
        if isinstance(node, dict):
            for key in keys:
                endpoint = node.get(key)
                vid = endpoint.get("videoId") if isinstance(endpoint, dict) else None
                if isinstance(vid, str) and _VIDEO_ID.fullmatch(vid.encode("ascii", "ignore")) and len(vid) == 11:
                    out.append(vid)
            stack.extend((child, depth + 1) for child in reversed(list(node.values())))
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in reversed(node))
    return out


def _proto_ids(body: bytes) -> list[str]:
    """11-character id-shaped string fields anywhere in a protobuf answer, in document order.

    The iOS field numbers of the sequence answer are not known, so this is a loose read: a wrong id only costs a
    capped background check of some other real (or non-existent) video and never changes a decision."""
    out: list[str] = []

    def walk(message: bytes, depth: int):
        if depth > MAX_DEPTH or len(out) >= MAX_CANDIDATES * 4:
            return
        for _, value in ytgate._protobuf_fields(message) or []:
            if len(value) == 11 and _VIDEO_ID.fullmatch(value):
                out.append(value.decode())
            elif len(value) > 11:
                walk(value, depth + 1)

    walk(body, 0)
    return out


def upcoming_videos(body: bytes, path: str) -> list[str]:
    """Distinct video ids an answer lists, first seen first, at most MAX_CANDIDATES. Junk gives []."""
    try:
        path = (path or "").split("?", 1)[0].rstrip("/")
        if not body or len(body) > ytgate.MAX_PLAYER_BYTES or path not in (SEQUENCE_PATH, NEXT_PATH):
            return []
        try:
            parsed = json.loads(body)
        except (ValueError, TypeError, UnicodeDecodeError, RecursionError):
            parsed = None
        if parsed is not None:
            keys = ("reelWatchEndpoint",) if path == SEQUENCE_PATH else ("reelWatchEndpoint", "watchEndpoint")
            ids = _json_ids(parsed, keys)
        elif path == SEQUENCE_PATH:
            ids = _proto_ids(body)
        else:
            return []  # a protobuf /next lists many unrelated ids (comments, playlists): not read
    except (RecursionError, ValueError, TypeError):
        return []
    out: list[str] = []
    for vid in ids:
        if vid not in out:
            out.append(vid)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def _today(now: float) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(now))


class Prefetcher:
    """A low-priority queue of background checks with its own limits; one check at a time.

    run(video) -> (status, reasons) performs one check in the prefetch worker and keeps a completed verdict.
    skip(video) -> True when the video needs no prefetch (already kept, or a real check is running).
    log(kind, detail) records an event; it must not raise."""

    def __init__(self, run, skip, log, *, daily_max: int = 150, clock=time.time, budget_file: Path | None = BUDGET_FILE,
                 per_response: int = MAX_PER_RESPONSE, per_minute: int = MAX_PER_MINUTE, max_pending: int = MAX_PENDING):
        self._run, self._skip, self._log, self._clock = run, skip, log, clock
        self.daily_max, self.per_response, self.per_minute, self.max_pending = daily_max, per_response, per_minute, max_pending
        self._budget_file = Path(budget_file) if budget_file else None
        self._pending: deque[str] = deque()
        self._accepted: deque[float] = deque()  # acceptance times within the last minute
        self._inflight: dict[str, asyncio.Future] = {}
        self._task: asyncio.Task | None = None
        self._loaded = self._budget_file is None
        self.day, self.used, self.paused_until = _today(clock()), 0, 0.0
        self._capped_day = ""
        self._broken = ""  # budget state unreadable or unwritable: prefetch stays off (fail closed on spend)

    # State -------------------------------------------------------------------------------------------------
    def _load(self):
        try:
            text = self._budget_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return  # first run: nothing spent yet
        except OSError as exc:
            self._fail(f"budget state unreadable ({type(exc).__name__})")
            return
        try:
            raw = json.loads(text)
            day, used, paused = str(raw["day"]), int(raw["used"]), float(raw.get("paused_until", 0))
            if len(day) != 10 or used < 0:
                raise ValueError("bad budget state")
        except (ValueError, TypeError, KeyError, AttributeError):
            self._fail("budget state corrupt")  # never read as zero spent
            return
        if day > self.day:  # the clock went back: keep the later day and its count (forward-only)
            self.day, self.used = day, max(self.used, used)
        elif day == self.day:
            self.used = max(self.used, used)
        self.paused_until = max(self.paused_until, paused)

    def _fail(self, reason: str):
        if not self._broken:
            self._log("yt-prefetch-paused", f"{reason}; prefetch off until the filter restarts with good state")
        self._broken = reason
        self._pending.clear()

    def _save(self) -> bool:
        if self._budget_file is None:
            return True
        try:
            tmp = self._budget_file.with_suffix(".tmp")
            tmp.write_text(json.dumps({"day": self.day, "used": self.used, "paused_until": self.paused_until}),
                           encoding="utf-8")
            with open(tmp, "rb+") as fh:
                os.fsync(fh.fileno())
            tmp.replace(self._budget_file)
            fd = os.open(self._budget_file.parent, os.O_RDONLY)  # the rename itself must survive a power loss
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return True
        except OSError:
            return False

    def _roll(self, now: float):
        day = _today(now)
        if day > self.day:  # forward only: a clock moved back never refills the allowance
            self.day, self.used = day, 0

    def stopped(self, now: float | None = None) -> str:
        """Why prefetch is off right now ("" when it may run)."""
        now = self._clock() if now is None else now
        self._roll(now)
        if self._broken:
            return "budget state"
        if now < self.paused_until:
            return "paused"
        if self.used >= max(0, int(self.daily_max)):
            return "daily cap"
        return ""

    def pause(self, reason: str, seconds: float = PAUSE_SECONDS):
        now = self._clock()
        if now >= self.paused_until:  # one event per pause, not one per failed check
            self._log("yt-prefetch-paused", f"{reason}; prefetch off for {int(seconds)} s, real checks unchanged")
        self.paused_until = max(self.paused_until, now + seconds)
        self._pending.clear()
        self._persist()

    def _persist(self):
        if self._budget_file is None:
            return
        try:
            asyncio.get_running_loop().run_in_executor(None, self._save_or_fail)
        except RuntimeError:
            self._save_or_fail()  # no loop (tests, shutdown)

    def _save_or_fail(self) -> bool:
        if self._save():
            return True
        self._fail("budget state unwritable")
        return False

    # Queue -------------------------------------------------------------------------------------------------
    def inflight(self, video: str) -> asyncio.Future | None:
        return self._inflight.get(video)

    def drop(self, video: str) -> bool:
        """A real request arrived first: its waiting prefetch is not needed."""
        try:
            self._pending.remove(video)
            return True
        except ValueError:
            return False

    def offer(self, videos: list[str]) -> list[str]:
        """Queue up to per_response new videos within the per-minute and pending limits. Returns those queued."""
        now = self._clock()
        if self.stopped(now):
            if self.stopped(now) == "daily cap" and self._capped_day != self.day:
                self._capped_day = self.day
                self._log("yt-prefetch-capped", f"{self.used} prefetch checks today (max {self.daily_max})")
            return []
        while self._accepted and now - self._accepted[0] >= 60:
            self._accepted.popleft()
        queued: list[str] = []
        for video in videos:
            if len(queued) >= self.per_response or len(self._accepted) >= self.per_minute \
                    or len(self._pending) >= self.max_pending:
                break
            if video in self._pending or video in self._inflight or self._skip(video):
                continue
            self._pending.append(video)
            self._accepted.append(now)
            queued.append(video)
        if queued and (self._task is None or self._task.done()):
            self._task = asyncio.get_running_loop().create_task(self._drain())
        return queued

    async def _drain(self):
        loop = asyncio.get_running_loop()
        if not self._loaded:
            self._loaded = True
            await loop.run_in_executor(None, self._load)
        while self._pending:
            if self.stopped():
                self._pending.clear()
                break
            video = self._pending.popleft()
            if self._skip(video):
                continue
            self.used += 1  # counted before the call: a check that dies still may have spent
            if self._budget_file is not None and not await loop.run_in_executor(None, self._save_or_fail):
                break  # the spend could not be recorded durably: no paid check
            done = loop.create_future()
            self._inflight[video] = done
            status, reasons = "error", []
            try:
                status, reasons = await self._run(video)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a prefetch failure is never a verdict
                status, reasons = "error", [type(exc).__name__]
            finally:
                self._inflight.pop(video, None)
                if not done.done():
                    done.set_result(None)
            if status == "error" and BILLING_LABEL in reasons:
                self.pause("judge billing/credit error")
