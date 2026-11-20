"""Time-based proxy restrictions and bridge-confirmed focus blocks.

These controls only add denials.  In particular, an active focus block is copied
into a private state file so editing the bridge file cannot end it early.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

from aifilter import config

JERUSALEM = ZoneInfo("Asia/Jerusalem")
_HOST = re.compile(r"(?=.{1,253}\Z)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")
MAX_FILE_BYTES = 64 * 1024
DEFAULT_FOCUS_FILE = config.db_path().with_name("focus-blocks.json")


def host_matches(host: str, suffixes) -> bool:
    host = host.lower().rstrip(".")
    return any(host == suffix or host.endswith("." + suffix) for suffix in suffixes)


@functools.lru_cache(maxsize=256)
def _exact_pattern(pattern: str) -> re.Pattern:
    """An exact host; "*" stands for letters, digits or "-" inside one label (never a dot)."""
    return re.compile("".join("[a-z0-9-]*" if part == "*" else re.escape(part)
                              for part in re.split(r"(\*)", pattern.lower().rstrip("."))) + r"\Z")


def host_listed(host: str, patterns) -> bool:
    """Exact-host match for carve-outs: a parent suffix never matches its subdomains here."""
    host = host.lower().rstrip(".")
    return any(_exact_pattern(p).match(host) for p in patterns if isinstance(p, str) and p)


def _hostname(value) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.lower().rstrip(".")
    return value if _HOST.fullmatch(value) else None


def _instant(value) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None


def _clock(value: str) -> time:
    try:
        return time.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError(f"invalid schedule time: {value!r}") from None


def in_window(now: datetime, start: str, end: str, weekdays: set[int] | None = None) -> bool:
    """Whether local ``now`` is in [start,end); wraparound belongs to its start day."""
    current, first, last = now.timetz().replace(tzinfo=None), _clock(start), _clock(end)
    if first < last:
        return (weekdays is None or now.weekday() in weekdays) and first <= current < last
    if first > last:
        start_day = now.weekday() if current >= first else (now.weekday() - 1) % 7
        return (weekdays is None or start_day in weekdays) and (current >= first or current < last)
    return False


@dataclass(frozen=True)
class FocusBlock:
    id: str
    start: datetime
    end: datetime
    topic: str
    allow: tuple[str, ...]
    confirmed_at: datetime

    def active(self, now: datetime) -> bool:
        return self.start <= now < self.end

    def json(self) -> dict:
        return {"id": self.id, "start": self.start.isoformat(), "end": self.end.isoformat(),
                "topic": self.topic, "allow": list(self.allow), "confirmed_at": self.confirmed_at.isoformat()}


def _parse_block(raw) -> FocusBlock | None:
    if not isinstance(raw, dict) or set(raw) != {"id", "start", "end", "topic", "allow", "confirmed_at"}:
        return None
    if not isinstance(raw["id"], str) or not raw["id"] or len(raw["id"]) > 128:
        return None
    if not isinstance(raw["topic"], str) or not raw["topic"] or len(raw["topic"]) > 200:
        return None
    start, end, confirmed = _instant(raw["start"]), _instant(raw["end"]), _instant(raw["confirmed_at"])
    if not start or not end or not confirmed or end <= start:
        return None
    allow = raw["allow"]
    if not isinstance(allow, list) or len(allow) > 50:
        return None
    hosts = tuple(_hostname(item) or "" for item in allow)
    if any(not item for item in hosts) or len(set(hosts)) != len(hosts):
        return None
    return FocusBlock(raw["id"], start, end, raw["topic"], hosts, confirmed)


def read_focus_file(path: Path, *, owner: int | None = None) -> list[FocusBlock] | None:
    """Strictly read the untrusted bridge file; None means reject the whole file."""
    owner = os.getuid() if owner is None else owner
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != owner \
                or info.st_size > MAX_FILE_BYTES:
            return None
        # O_NOFOLLOW closes the replacement-with-symlink race after lstat.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino) or opened.st_uid != owner \
                    or stat.S_IMODE(opened.st_mode) != 0o600:
                return None
            data = stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            return None
        raw = json.loads(data)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict) or set(raw) != {"blocks"} or not isinstance(raw["blocks"], list) \
            or len(raw["blocks"]) > 100:
        return None
    blocks = [_parse_block(item) for item in raw["blocks"]]
    if any(item is None for item in blocks):
        return None
    ids = [item.id for item in blocks]
    return None if len(ids) != len(set(ids)) else blocks


class SchedulePolicy:
    def __init__(self, cfg, *, focus_file: Path | None = None, state_file: Path | None = None):
        self.cfg = cfg
        data_dir = config.db_path().parent
        self.focus_file = Path(focus_file or DEFAULT_FOCUS_FILE or data_dir / "focus-blocks.json")
        self.state_file = Path(state_file or data_dir / "focus-blocks-active.json")

    def _section(self, name: str) -> dict:
        section = self.cfg.raw.get(name, {})
        return section if isinstance(section, dict) else {}

    def _retained(self) -> list[FocusBlock]:
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return []
        if not isinstance(raw, dict) or set(raw) != {"blocks"} or not isinstance(raw["blocks"], list):
            return []
        parsed = [_parse_block(item) for item in raw["blocks"]]
        return [] if any(item is None for item in parsed) else parsed

    def _save(self, blocks: list[FocusBlock]) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_file.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump({"blocks": [block.json() for block in blocks]}, stream, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.state_file)
        except OSError:
            pass  # failure cannot loosen the current evaluation; the bridge file remains authoritative

    def active_focus(self, now: datetime) -> list[FocusBlock]:
        retained = {block.id: block for block in self._retained() if block.active(now)}
        current = read_focus_file(self.focus_file)
        if current is not None:
            for block in current:
                if not block.active(now):
                    continue
                old = retained.get(block.id)
                # Intersection/max are the strictest parts of both versions.
                if old:
                    allowed = tuple(item for item in old.allow if item in block.allow)
                    retained[block.id] = FocusBlock(block.id, min(old.start, block.start), max(old.end, block.end),
                                                    old.topic, allowed, old.confirmed_at)
                else:
                    retained[block.id] = block
        active = sorted(retained.values(), key=lambda item: (item.end, item.id))
        self._save(active)
        return active

    @staticmethod
    def _work_device_exempt(work: dict, client: str | None) -> bool:
        """Whether this source IP is on the committee-approved work-rule exemption list.

        Only an exact, well-formed match exempts. Any ambiguity (no client, a bad entry,
        an unparsable address) keeps the work rule on, so a device that changes IP or a
        new device is never exempt by accident.
        """
        devices = work.get("exempt_devices", [])
        if not devices or not isinstance(devices, list) or not isinstance(client, str):
            return False
        if "%" in client:
            return False  # a scoped IPv6 address is ambiguous across links: never exempt
        try:
            source = ipaddress.ip_address(client)
        except ValueError:
            return False
        configured = set()
        for device in devices:
            if not isinstance(device, str) or "%" in device:
                return False  # a bad or scoped entry voids the whole list
            try:
                configured.add(ipaddress.ip_address(device))
            except ValueError:
                return False
        if isinstance(source, ipaddress.IPv6Address) and source.ipv4_mapped:
            source = source.ipv4_mapped
        return source in configured

    def reason(self, host: str, now: datetime | None = None, *, allow_work_music: bool = False,
               client: str | None = None) -> str | None:
        """Return the active restriction, optionally exempting music from work only.

        ``allow_work_music`` is deliberately considered after focus and night so
        callers cannot use the narrow work-hours exception to loosen either one.
        """
        now = (now or datetime.now(JERUSALEM)).astimezone(JERUSALEM)
        host = host.lower().rstrip(".")
        focus = self._section("focus")
        if focus.get("enabled", True):
            always = focus.get("always_allow", [])
            topics = focus.get("topics", {})
            for block in self.active_focus(now):
                mapped = topics.get(block.topic, []) if isinstance(topics, dict) else []
                allowed = [*always, *block.allow, *mapped]
                if not host_matches(host, allowed):
                    return f"זמן מיקוד: {block.topic} עד {block.end.astimezone(JERUSALEM):%H:%M}"
        schedule = self._section("schedule")
        night = schedule.get("night", {})
        if night.get("enabled", True) and in_window(now, night.get("start", "23:00"), night.get("end", "06:00")):
            # night_except carves open web/media hosts out of a broader night_allow parent (e.g. icloud.com).
            allowed = host_matches(host, schedule.get("night_allow", [])) \
                and not host_listed(host, schedule.get("night_except", []))
            if not allowed and not (
                    allow_work_music and night.get("allow_music", False)):
                return f"מצב לילה עד {_clock(night.get('end', '06:00')):%H:%M}"
        work = schedule.get("work", {})
        if work.get("enabled", True) and not self._work_device_exempt(work, client) \
                and in_window(now, work.get("start", "09:00"), work.get("end", "17:00"), {6, 0, 1, 2, 3}):
            if host_matches(host, schedule.get("work_block", [])) and not (
                    allow_work_music and work.get("allow_music", False)):
                return f"שעות עבודה עד {_clock(work.get('end', '17:00')):%H:%M}"
        return None
