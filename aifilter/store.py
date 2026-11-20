"""SQLite store for the filter's decisions: the "committee's" memory."""

import json
import math
import sqlite3
import threading
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import unquote
from pathlib import Path

from aifilter.suffixes import ancestors, normalize, registrable

# Domain verdicts.
ALLOW = "allow"      # open, images still reviewed
TRUSTED = "trusted"  # open, nothing reviewed
BLOCK = "block"
TEXT_ONLY = "textonly"  # open, but every image and video hidden

def _loosen_clock() -> float:
    """Time source of the night rule when a caller passes no explicit `now` (tests replace it)."""
    return time.time()


_STRICT = {BLOCK: 3, TEXT_ONLY: 2, ALLOW: 1, TRUSTED: 0}  # how restrictive a verdict is
MAX_OVERRIDE_DAYS = 30  # no approval is permanent
CONFIRM_AFTER = 24 * 3600  # rule 7: a confirmation counts only a full day after the request

# COMMITTEE.md rule 4: never opened, by any caller (social feeds, unrestricted video, VPN and proxy services).
# Covers every subdomain. policy.py's feed lists must stay inside it (tests/test_appapi.py guards that).
NEVER_LOOSEN = (
    "x.com", "twitter.com", "twimg.com", "t.co", "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
    "instagram.com", "cdninstagram.com", "tiktok.com", "tiktokcdn.com", "tiktokv.com", "facebook.com", "fb.com",
    "fb.watch", "fbcdn.net", "threads.net", "threads.com", "snapchat.com", "pinterest.com", "tumblr.com",
    "bsky.app", "twitch.tv", "kick.com", "9gag.com", "imgur.com", "discord.com", "discord.gg",
    "youtube.com", "youtu.be", "googlevideo.com", "vimeo.com", "dailymotion.com", "rumble.com", "bilibili.com",
    "nordvpn.com", "expressvpn.com", "protonvpn.com", "surfshark.com", "privateinternetaccess.com",
    "windscribe.com", "hide.me", "hidemyass.com", "hola.org", "psiphon.ca", "torproject.org", "ultrasurf.us",
    "proxysite.com", "croxyproxy.com", "hidester.com", "kproxy.com",
)


def _lock_owner(reason: str) -> str:
    """One policy-lock owner token: never empty and never containing the ' | ' separator."""
    token = " ".join(str(reason or "").replace("|", "/").split())
    return token or "unknown"


def never_loosen(host: str) -> bool:
    host = str(host).lower().strip().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in NEVER_LOOSEN)

SCHEMA = """
CREATE TABLE IF NOT EXISTS domains (
  host TEXT PRIMARY KEY,
  verdict TEXT NOT NULL,
  source TEXT NOT NULL,          -- ai | admin
  reason TEXT,
  updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS overrides (  -- temporary committee decisions, layered over the standing ones
  host TEXT PRIMARY KEY,
  verdict TEXT NOT NULL,
  source TEXT NOT NULL,
  reason TEXT,
  created REAL NOT NULL,
  expires REAL NOT NULL,
  include_subdomains INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS domain_denials (
  host TEXT NOT NULL, denied REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS domain_denials_host ON domain_denials(host, denied);
CREATE TABLE IF NOT EXISTS images (
  digest TEXT PRIMARY KEY,
  bad INTEGER NOT NULL,
  labels TEXT,
  updated REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS video_permissions (
  host TEXT NOT NULL,
  path_prefix TEXT NOT NULL,
  expires REAL NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY (host, path_prefix)
);
CREATE TABLE IF NOT EXISTS bad_image_hits (
  host TEXT PRIMARY KEY,
  count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS bad_image_strikes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,             -- exact page host, never a parent domain
  ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS bad_image_strikes_host ON bad_image_strikes(host, ts);
CREATE TABLE IF NOT EXISTS appeals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT NOT NULL,
  url TEXT,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | denied
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS tls_failures (
  host TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  last REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS connect_failures (
  host TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  last REAL NOT NULL,
  detail TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS passthrough (
  host TEXT PRIMARY KEY,
  added REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS blocklist (
  host TEXT PRIMARY KEY,          -- blocks the host and every subdomain
  list TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS committee_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL, target TEXT NOT NULL, payload TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'pending', created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS owner_confirmations (
  request_id INTEGER PRIMARY KEY, confirmed REAL NOT NULL, channel TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policy_locks (  -- policy rows a stricter committee decision took over: still a lock
  host TEXT PRIMARY KEY, verdict TEXT NOT NULL, updated REAL NOT NULL, reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS mcp_tokens (
  token_hash TEXT PRIMARY KEY, client TEXT NOT NULL, scope TEXT NOT NULL,
  created REAL NOT NULL, revoked REAL
);
CREATE TABLE IF NOT EXISTS committee_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, agent TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL, outcome TEXT NOT NULL, detail TEXT
);
CREATE TABLE IF NOT EXISTS entity_verdicts (
  kind TEXT NOT NULL, target TEXT NOT NULL, verdict TEXT NOT NULL, reason TEXT,
  updated REAL NOT NULL, PRIMARY KEY(kind,target)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  kind TEXT NOT NULL,
  host TEXT,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS relay_actions (
  id TEXT PRIMARY KEY, payload_hash TEXT NOT NULL, status TEXT NOT NULL,
  created REAL NOT NULL, updated REAL NOT NULL
);
"""

class Store:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            # Acquire the write lock before inspecting columns. Launcher processes
            # may open the same older database concurrently.
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if "expires" not in {r[1] for r in self._db.execute("PRAGMA table_info(domains)")}:
                    self._db.execute("ALTER TABLE domains ADD COLUMN expires REAL")
                # Older lock rows are foreign to every writer and must never be pruned.
                if "reason" not in {r[1] for r in self._db.execute("PRAGMA table_info(policy_locks)")}:
                    self._db.execute("ALTER TABLE policy_locks ADD COLUMN reason TEXT NOT NULL DEFAULT 'legacy'")
                if "include_subdomains" not in {r[1] for r in self._db.execute("PRAGMA table_info(overrides)")}:
                    self._db.execute("ALTER TABLE overrides ADD COLUMN include_subdomains INTEGER NOT NULL DEFAULT 0")
                # Expiry brings back the standing decision after moving temporary approvals.
                self._db.execute("INSERT OR REPLACE INTO overrides(host,verdict,source,reason,created,expires,include_subdomains) "
                                 "SELECT host,verdict,source,reason,updated,expires,0 FROM domains "
                                 "WHERE expires IS NOT NULL")
                self._db.execute("DELETE FROM domains WHERE expires IS NOT NULL")
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _q(self, sql, args=()):
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # Domains -------------------------------------------------------------
    def _override(self, host: str) -> str | None:
        """Unexpired temporary decision, most specific ancestor first."""
        for h in ancestors(host):
            row = self._q("SELECT verdict,include_subdomains FROM overrides WHERE host=? AND expires > ?", (h, time.time()))
            if row and h != normalize(host) and not row[0][1]:
                continue
            if row:
                return row[0][0]
        return None

    def _standing(self, host: str):
        for h in ancestors(host):
            row = self._q("SELECT verdict, source FROM domains WHERE host=? AND expires IS NULL", (h,))
            if row and (row[0][1] != "ai" or h == normalize(host)):
                return row[0]
        return None

    def _policy_row(self, host: str):
        """Standing policy row (verdict, source) on this host or any ancestor, however an
        admin or AI row on a more specific name looks."""
        names = ancestors(host)
        marks = ",".join("?" * len(names))
        rows = self._q(f"SELECT verdict,source FROM domains WHERE host IN ({marks}) "
                       "AND source='policy' AND expires IS NULL", names)
        rows += [(v, "policy") for (v,) in self._q(f"SELECT verdict FROM policy_locks WHERE host IN ({marks})", names)]
        return max(rows, key=lambda r: _STRICT.get(r[0], 0)) if rows else None

    def _lock_policy(self, host: str, verdict: str, reason: str = ""):
        """Keep a policy row's lock (loosen, weaker decisions) after another row took its place."""
        self._q("INSERT INTO policy_locks(host,verdict,updated,reason) VALUES(?,?,?,?) ON CONFLICT(host) DO UPDATE SET "
                "verdict=CASE WHEN excluded.verdict='block' THEN 'block' ELSE policy_locks.verdict END, "
                "updated=excluded.updated, "
                # a lock keeps every writer's reason (an empty or legacy one counts as another writer), so
                # policy.py --prune, which matches its own reason exactly, never drops anyone else's lock
                # (membership is by whole ' | '-separated token, never by substring)
                "reason=CASE WHEN instr(' | ' || policy_locks.reason || ' | ', ' | ' || excluded.reason || ' | ') > 0 "
                "THEN policy_locks.reason ELSE policy_locks.reason || ' | ' || excluded.reason END",
                (normalize(host), verdict, time.time(), _lock_owner(reason)))

    def policy_records(self):
        """(kind 'row'|'lock', host, verdict, reason) of every policy row and policy lock."""
        rows = self._q("SELECT 'row',host,verdict,COALESCE(reason,'') FROM domains WHERE source='policy' AND expires IS NULL")
        return rows + self._q("SELECT 'lock',host,verdict,reason FROM policy_locks")

    def remove_policy_record(self, kind: str, host: str):
        if kind == "row":
            self._q("DELETE FROM domains WHERE host=? AND source='policy' AND expires IS NULL", (host,))
        else:
            self._q("DELETE FROM policy_locks WHERE host=?", (host,))
        self.log("policy-pruned", host, kind)

    def _decided(self, host: str, lists: bool = True):
        """(temporary verdict, standing row) of the most specific name that has either.

        At one name the temporary approval is returned first; a broad temporary
        approval never masks a more specific standing decision, and an approval
        inherited from a parent never beats a blocklist entry at a more specific name."""
        host = normalize(host)
        now = time.time()
        names = ancestors(host)
        for i, h in enumerate(names):
            temp = self._q("SELECT verdict,include_subdomains FROM overrides WHERE host=? AND expires > ?", (h, now))
            if temp and h != host and not temp[0][1]:
                temp = []
            standing = self._q("SELECT verdict,source FROM domains WHERE host=? AND expires IS NULL", (h,))
            row = standing[0] if standing and (standing[0][1] != "ai" or h == host) else None
            if temp and i and lists and not row:
                marks = ",".join("?" * i)
                if self._q(f"SELECT 1 FROM blocklist WHERE host IN ({marks}) LIMIT 1", names[:i]):
                    return BLOCK, None
            if temp or row:
                return (temp[0][0] if temp else None), row
        return None, None

    def verdict(self, host: str, lists: bool = True) -> str | None:
        """Resolve each name before its parent, across temporary and standing rows.

        Specificity decides first: a broad temporary approval never masks a more
        specific standing block. For one and the same name an unexpired approval
        replaces the standing row (appeal of an AI block, re-approval after the
        7-day denial window) and the standing row returns on expiry. AI rows
        remain exact-only and PSL tenant boundaries are never crossed.
        """
        temp, row = self._decided(host, lists)
        if temp is not None:
            return temp
        if row:
            return row[0]
        return BLOCK if lists and self.listed(host) else None

    def loosen(self, host: str, verdict: str, source: str, reason: str, *, days: float | None = None,
               now: float | None = None, domain: bool = False, request_id: int | str | None = None,
               passthrough: bool = False, require_request: bool = False):
        """The single gate for an operation that makes domain filtering less strict.

        Callers must explicitly opt into parent-domain scope. Passthrough is a
        configuration-level exception and additionally needs a confirmed request.
        `require_request` (channels the filtered device can reach, e.g. the owner's app API)
        also needs a confirmed committee request for exactly this domain.
        """
        if verdict not in (ALLOW, TRUSTED, TEXT_ONLY):
            raise ValueError("loosen only accepts allow, trusted or text-only")
        host = normalize(host)
        now = _loosen_clock() if now is None else float(now)
        hour = datetime.fromtimestamp(now, ZoneInfo("Asia/Jerusalem")).hour
        if hour >= 23 or hour < 6:
            raise ValueError("rule 6: no loosening at night (23:00-06:00 Israel)")
        if never_loosen(host):
            raise ValueError("rule 4: this is never approved")
        if self.listed(host) or self._policy_row(host):
            raise ValueError("rule 4: list and policy hosts cannot be loosened")
        cutoff = now - 7 * 86400
        names = ancestors(host)
        marks = ",".join("?" * len(names))
        if self._q(f"SELECT 1 FROM domain_denials WHERE host IN ({marks}) AND denied>=? LIMIT 1", (*names, cutoff)):
            raise ValueError("rule 5: this domain or a parent was denied within the last 7 days")
        if domain and not reason.strip():
            raise ValueError("parent-domain scope requires a reason")
        if passthrough:
            try:
                rid = int(request_id)
            except (TypeError, ValueError):
                raise ValueError("passthrough needs a confirmed request id") from None
            confirmed = self._q("SELECT 1 FROM owner_confirmations WHERE request_id=?", (rid,))
            if not confirmed:
                raise ValueError("passthrough needs a confirmed request id")
            self.add_passthrough(host, reason)
            return
        if days is None:
            raise ValueError("domain loosening must be temporary")
        if require_request:
            self._consume_request(request_id, host, verdict, days, domain)
        self.set_override(host, verdict, source, reason, days, domain=domain)

    def _consume_request(self, request_id, host: str, verdict: str, days, domain: bool):
        """A committee-approved request for exactly this loosening, confirmed by the owner calmly 24 hours
        later (rules 6-7); used once. Raises before anything changes."""
        refused = "needs a confirmed committee request for this domain"
        if isinstance(days, bool) or not isinstance(days, (int, float)) or not math.isfinite(days) \
                or not 0 < days <= MAX_OVERRIDE_DAYS:
            raise ValueError(f"days must be in (0, {MAX_OVERRIDE_DAYS}], got {days!r}")
        try:
            rid = int(request_id)
        except (TypeError, ValueError):
            raise ValueError(refused) from None
        row = self.committee_request(rid)
        if not row or row[1] != "domain" or normalize(row[2]) != host:
            raise ValueError(refused)
        if row[4] != "approved":
            raise ValueError("the committee has not approved this request")
        confirmed = row[6]
        if confirmed is None or confirmed - row[5] < CONFIRM_AFTER:
            raise ValueError("rule 7: confirmation counts only 24 hours after the request")
        hour = datetime.fromtimestamp(confirmed, ZoneInfo("Asia/Jerusalem")).hour
        if hour >= 23 or hour < 6:
            raise ValueError("rule 6: the confirmation was given at night")
        try:
            payload = json.loads(row[3])
        except (TypeError, ValueError):
            payload = {}
        if not isinstance(payload, dict) or payload.get("verdict") != verdict or payload.get("days") != days \
                or bool(payload.get("domain", False)) != bool(domain):
            raise ValueError("the request does not match this verdict, duration and scope")
        with self._lock:  # single use: only one caller can move it from approved to used
            if self._db.execute("UPDATE committee_requests SET status='used' WHERE id=? AND status='approved'",
                                (rid,)).rowcount != 1:
                raise ValueError("this request was already used")

    def strictest_permanent(self, host: str) -> str | None:
        """Strictest standing rule on this host and its parents (lists count as block, AI rows only on
        the exact host); temporary approvals are ignored. None when nothing was ever decided."""
        host = normalize(host)
        if self.listed(host):
            return BLOCK
        names = ancestors(host)
        marks = ",".join("?" * len(names))
        rows = [v for h, v, src in self._q(f"SELECT host,verdict,source FROM domains WHERE host IN ({marks}) "
                                         "AND expires IS NULL", names) if src != "ai" or h == host]
        return max(rows, key=lambda v: _STRICT.get(v, 3)) if rows else None

    def text_only_tightens(self, host: str) -> bool:
        """Text-only is a tightening only over a standing open rule; over nothing (no review yet), a block,
        a list or a policy it would skip page review, so it is a loosening."""
        return self.strictest_permanent(host) in (ALLOW, TRUSTED)

    def network_blocked(self, host: str) -> bool:
        """Block for the whole house: admin blocks and community lists only.

        Automatic AI decisions stay on filtered devices; a mistaken AI verdict must
        never cut the whole network off from a site.
        """
        host = host.lower().rstrip(".")
        temp, row = self._decided(host)
        if temp is not None:
            return temp == BLOCK
        if row:
            return row[0] == BLOCK and row[1] == "admin"  # "policy" blocks stay on filtered devices
        return bool(self.listed(host))

    def policy_blocked(self, host: str) -> bool:
        """Standing social-feed policy (block or text-only) covering this host."""
        host = host.lower().rstrip(".")
        temp, row = self._decided(host)
        if temp is not None:
            return False  # a temporary committee approval lifts the policy until it expires
        return bool(row) and row[1] == "policy" and row[0] in (BLOCK, TEXT_ONLY)

    def listed(self, host: str) -> str | None:
        """Name of the blocklist that covers this host or any parent domain."""
        names = ancestors(host)
        if not names:
            return None
        marks = ",".join("?" * len(names))
        rows = dict(self._q(f"SELECT host,list FROM blocklist WHERE host IN ({marks})", names))
        return next((rows[name] for name in names if name in rows), None)

    def replace_blocklists(self, entries) -> int:
        """Swap the whole blocklist table in one transaction. entries: iterable of (host, list)."""
        with self._lock:
            self._db.execute("BEGIN")
            try:
                self._db.execute("DELETE FROM blocklist")
                self._db.executemany("INSERT OR IGNORE INTO blocklist(host,list) VALUES(?,?)",
                                     ((normalize(host), name) for host, name in entries))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            return self._db.execute("SELECT count(*) FROM blocklist").fetchone()[0]

    def set_verdict(self, host: str, verdict: str, source: str, reason: str = "", days: float | None = None):
        """A standing decision (days=None), or a temporary one for 0 < days <= 30.

        A temporary decision never replaces the standing row: when it expires, the
        standing decision (policy, list, AI or admin) applies again."""
        host = normalize(host)
        if days is not None:
            return self.set_override(host, verdict, source, reason, days)
        policy = self._policy_row(host) if source != "policy" else None
        if policy and _STRICT.get(verdict, 0) < _STRICT.get(policy[0], 0) and source != "ai":
            raise ValueError("rule 4: a decision cannot be weaker than the standing policy")
        own = self.standing(host)
        if own and source == "policy" and (_STRICT.get(own[0], 3) > _STRICT.get(verdict, 0) or (
                own[1] == "admin" and _STRICT.get(own[0], 3) >= _STRICT.get(verdict, 0))):
            # A policy write never weakens a stricter standing row, and never turns an equally strict committee
            # (house-wide) decision into a device-only one: the row stays, the policy only adds its lock.
            self._lock_policy(host, verdict, reason)
            if verdict in (BLOCK, TEXT_ONLY):  # the tightening still ends a same-name temporary approval at once
                self._q("DELETE FROM overrides WHERE host=?", (host.lower(),))
            return
        if own and own[1] == "policy" and source != "policy":
            if source == "ai":
                return  # the AI never replaces a policy row
            # A committee decision at least as strict (weaker raised above) takes the row, so it applies
            # house-wide and records its denial; the policy keeps its lock.
            self._lock_policy(host, own[0], self._q("SELECT COALESCE(reason,'') FROM domains WHERE host=?",
                                                    (host,))[0][0])
        self._q(
            "INSERT INTO domains(host,verdict,source,reason,updated,expires) VALUES(?,?,?,?,?,NULL) "
            "ON CONFLICT(host) DO UPDATE SET verdict=excluded.verdict, source=excluded.source, "
            "reason=excluded.reason, updated=excluded.updated, expires=NULL",
            (host.lower(), verdict, source, reason, time.time()),
        )
        if source == "admin" or (source == "policy" and verdict in (BLOCK, TEXT_ONLY)):
            # a later committee decision, or a policy tightening, replaces a same-name approval at once
            self._q("DELETE FROM overrides WHERE host=?", (host.lower(),))
        self.log("verdict", host, f"{verdict} by {source}: {reason}")
        if verdict == BLOCK and source in ("admin", "policy"):
            self._q("INSERT INTO domain_denials(host,denied) VALUES(?,?)", (host, time.time()))

    def set_override(self, host: str, verdict: str, source: str, reason: str, days: float, *, domain: bool = False):
        host = normalize(host)
        if isinstance(days, bool) or not isinstance(days, (int, float)) or not math.isfinite(days) \
                or not 0 < days <= MAX_OVERRIDE_DAYS:
            raise ValueError(f"days must be in (0, {MAX_OVERRIDE_DAYS}], got {days!r}")
        now = time.time()
        self._q("INSERT OR REPLACE INTO overrides(host,verdict,source,reason,created,expires,include_subdomains) "
                "VALUES(?,?,?,?,?,?,?)",
                (host.lower(), verdict, source, reason, now, now + days * 86400, int(domain)))
        self.log("verdict", host, f"{verdict} by {source}: {reason} ({days}d)")

    def overrides(self):
        return self._q("SELECT host,verdict,reason,expires FROM overrides WHERE expires > ? ORDER BY expires",
                       (time.time(),))

    def standing(self, host: str):
        """(verdict, source) of the standing row for exactly this host, or None."""
        row = self._q("SELECT verdict, source FROM domains WHERE host=? AND expires IS NULL", (host.lower(),))
        return row[0] if row else None

    def source(self, host: str) -> str | None:
        row = self._q("SELECT source FROM domains WHERE host=?", (host.lower(),))
        return row[0][0] if row else None

    def admin_locked(self, host: str) -> bool:
        """An admin decision is never overridden by the AI."""
        names = ancestors(host)
        marks = ",".join("?" * len(names))
        rows = self._q(f"SELECT source FROM domains WHERE host IN ({marks}) AND expires IS NULL", names)
        return any(r[0] in ("admin", "policy") for r in rows) or self._override(host.lower()) is not None

    def ai_block(self, host: str, reason: str) -> bool:
        """Block one exact host on the AI's judgement unless the admin already decided.

        Never the parent domain: one bad page on a big platform (e.g. a google.com
        subdomain) must not take the whole platform down."""
        host = host.lower().rstrip(".")
        if self.admin_locked(host):
            return False
        self.set_verdict(host, BLOCK, "ai", reason)
        return True

    def domains(self, limit=200):
        return self._q("SELECT host,verdict,source,reason,updated FROM domains ORDER BY updated DESC LIMIT ?", (limit,))

    # Video approvals are exact media host + path scope, independent of image trust.
    @staticmethod
    def _video_path(path: str) -> str:
        path = unquote(path)
        if not path.startswith("/") or any(c in path for c in ("\\", "?", "#", "%")) \
                or any(ord(c) < 32 for c in path) or any(p in (".", "..") for p in path.split("/")):
            raise ValueError("video scope must be an absolute path without traversal or query")
        return path.rstrip("/") or "/"

    def grant_video(self, host: str, path_prefix: str, days: float, reason: str):
        if isinstance(days, bool) or not isinstance(days, (float, int)) or not math.isfinite(days) \
                or not 0 < days <= MAX_OVERRIDE_DAYS:
            raise ValueError("video permission needs a finite duration of at most 30 days")
        host, path_prefix = normalize(host), self._video_path(path_prefix)
        self._q("INSERT OR REPLACE INTO video_permissions VALUES(?,?,?,?)",
                (host, path_prefix, time.time() + days * 86400, reason))
        self.log("video-permission", host, f"{path_prefix} for {days} days: {reason}")

    def revoke_video(self, host: str, path_prefix: str):
        self._q("DELETE FROM video_permissions WHERE host=? AND path_prefix=?",
                (normalize(host), self._video_path(path_prefix)))
        self.log("video-revoked", host, path_prefix)

    def video_allowed(self, host: str, path: str) -> bool:
        try:
            path = self._video_path(path)
        except ValueError:
            return False
        rows = self._q("SELECT path_prefix FROM video_permissions WHERE host=? AND expires>?",
                       (normalize(host), time.time()))
        return any(prefix == "/" or path == prefix or path.startswith(prefix + "/") for (prefix,) in rows)

    # Images --------------------------------------------------------------
    def image_verdict(self, digest: str):
        row = self._q("SELECT bad FROM images WHERE digest=?", (digest,))
        return None if not row else bool(row[0][0])

    def set_image_verdict(self, digest: str, bad: bool, labels: str):
        self._q("INSERT OR REPLACE INTO images(digest,bad,labels,updated) VALUES(?,?,?,?)",
                (digest, int(bad), labels, time.time()))

    def add_strike(self, host: str, days: float = 7) -> int:
        """Record a bad image shown on this exact host; returns its strikes within `days`."""
        host, now = host.lower().rstrip("."), time.time()
        self._q("DELETE FROM bad_image_strikes WHERE ts < ?", (now - days * 86400,))
        self._q("INSERT INTO bad_image_strikes(host,ts) VALUES(?,?)", (host, now))
        return self._q("SELECT count(*) FROM bad_image_strikes WHERE host=? AND ts >= ?",
                       (host, now - days * 86400))[0][0]

    # Appeals -------------------------------------------------------------
    def add_appeal(self, host: str, url: str, note: str = "") -> int:
        host = normalize(host)
        existing = self._q("SELECT id FROM appeals WHERE host=? AND status='pending'", (host,))
        if existing:
            return existing[0][0]
        with self._lock:
            cur = self._db.execute("INSERT INTO appeals(host,url,note,created) VALUES(?,?,?,?)",
                                   (host, url[:500], note[:300], time.time()))
            return cur.lastrowid

    def appeals_for(self, host: str):
        return self._q("SELECT id FROM appeals WHERE host=? AND status='pending'", (normalize(host),))

    def appeals(self, status="pending"):
        return self._q("SELECT id,host,url,note,created FROM appeals WHERE status=? ORDER BY created DESC", (status,))

    def resolve_appeal(self, appeal_id: int, approve: bool, days: float | None = None):
        """Approving needs a finite duration; denying is a standing block."""
        if approve and days is None:
            raise ValueError("an approval needs days")
        row = self._q("SELECT host FROM appeals WHERE id=?", (appeal_id,))
        if not row:
            return
        if approve:
            self.loosen(row[0][0], ALLOW, "admin", "appeal", days=days)  # the exact appealed host only
        else:
            self.set_verdict(row[0][0], BLOCK, "admin", "appeal")
        self._q("UPDATE appeals SET status=? WHERE id=?", ("approved" if approve else "denied", appeal_id))

    # TLS / passthrough ---------------------------------------------------
    def record_tls_failure(self, host: str):
        self._q("INSERT INTO tls_failures(host,count,last) VALUES(?,1,?) "
                "ON CONFLICT(host) DO UPDATE SET count=count+1, last=excluded.last", (host, time.time()))

    def tls_failures(self):
        return self._q("SELECT host,count,last FROM tls_failures WHERE host NOT IN (SELECT host FROM passthrough) "
                       "ORDER BY last DESC LIMIT 100")

    def record_connect_failure(self, host: str, detail: str):
        self._q("INSERT INTO connect_failures(host,count,last,detail) VALUES(?,1,?,?) "
                "ON CONFLICT(host) DO UPDATE SET count=count+1, last=excluded.last, detail=excluded.detail",
                (host, time.time(), detail))

    def connect_failures(self):
        return self._q("SELECT host,count,last,detail FROM connect_failures")

    def add_passthrough(self, host: str, reason: str = "added by admin"):
        self._q("INSERT OR IGNORE INTO passthrough(host,added) VALUES(?,?)", (host.lower(), time.time()))
        self.log("passthrough", host, reason)

    def passthrough_hosts(self) -> set[str]:
        return {r[0] for r in self._q("SELECT host FROM passthrough")}

    # Vendor-neutral committee state ---------------------------------------
    def create_committee_request(self, kind: str, target: str, payload: str = "{}", created=None) -> int:
        with self._lock:
            cur = self._db.execute("INSERT INTO committee_requests(kind,target,payload,created) VALUES(?,?,?,?)",
                                   (kind, target, payload, time.time() if created is None else created))
            return cur.lastrowid

    def create_committee_proposal(self, kind: str, target: str, payload: str, agent: str) -> int:
        """Persist an MCP proposal and its audit entry in one SQLite transaction."""
        now = time.time()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                cur = self._db.execute(
                    "INSERT INTO committee_requests(kind,target,payload,created) VALUES(?,?,?,?)",
                    (kind, target, payload, now))
                rid = cur.lastrowid
                self._db.execute(
                    "INSERT INTO committee_audit(ts,agent,action,target,outcome,detail) VALUES(?,?,?,?,?,?)",
                    (now, agent, "record-proposal", f"{kind}:{target}", "proposed", f"request {rid}"))
                self._db.execute("COMMIT")
                return rid
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def committee_requests(self, status="pending"):
        return self._q("SELECT id,kind,target,payload,status,created FROM committee_requests WHERE status=? ORDER BY created", (status,))

    def committee_request(self, request_id: int):
        rows = self._q("SELECT r.id,r.kind,r.target,r.payload,r.status,r.created,c.confirmed "
                       "FROM committee_requests r LEFT JOIN owner_confirmations c ON c.request_id=r.id WHERE r.id=?",
                       (request_id,))
        return rows[0] if rows else None

    def finish_committee_request(self, request_id: int, status: str):
        self._q("UPDATE committee_requests SET status=? WHERE id=?", (status, request_id))

    def decide_committee_request(self, request_id: int, status: str, note: str,
                                 earliest_at: str | None = None) -> bool:
        """Record a relay-visible committee decision without discarding proposal data."""
        if status not in {"approved", "declined", "waiting"}:
            raise ValueError("invalid committee decision status")
        with self._lock:
            row = self._db.execute(
                "SELECT payload,status FROM committee_requests WHERE id=?", (request_id,)).fetchone()
            if not row:
                return False
            if row[1] == "used":
                raise ValueError("this request was already used; it cannot be decided again")
            try:
                payload = json.loads(row[0])
            except (TypeError, ValueError):
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            payload["decision_note"] = note
            payload["earliest_at"] = earliest_at
            payload["decided_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._db.execute(
                "UPDATE committee_requests SET status=?, payload=? WHERE id=?",
                (status, json.dumps(payload, ensure_ascii=False, separators=(",", ":")), request_id))
            return True

    def set_entity_verdict(self, kind: str, target: str, verdict: str, reason=""):
        self._q("INSERT OR REPLACE INTO entity_verdicts VALUES(?,?,?,?,?)",
                (kind, target, verdict, reason, time.time()))

    def entity_verdict(self, kind: str, target: str):
        rows = self._q("SELECT verdict,reason,updated FROM entity_verdicts WHERE kind=? AND target=?", (kind,target))
        return rows[0] if rows else None

    def entity_verdicts(self, kind: str | None = None):
        return self._q("SELECT kind,target,verdict,reason,updated FROM entity_verdicts " +
                       ("WHERE kind=? " if kind else "") + "ORDER BY updated DESC", (kind,) if kind else ())

    def audit(self, agent: str, action: str, target: str, outcome: str, detail=""):
        self._q("INSERT INTO committee_audit(ts,agent,action,target,outcome,detail) VALUES(?,?,?,?,?,?)",
                (time.time(), agent, action, target, outcome, detail[:500]))

    def audit_history(self, limit=100):
        return self._q("SELECT ts,agent,action,target,outcome,detail FROM committee_audit ORDER BY id DESC LIMIT ?", (limit,))

    # Events --------------------------------------------------------------
    def log(self, kind: str, host: str = "", detail: str = ""):
        # Capture records can contain a long (value-free) query-key inventory. Other event details stay terse.
        limit = 4000 if kind == "yt-capture" else 500
        self._q("INSERT INTO events(ts,kind,host,detail) VALUES(?,?,?,?)", (time.time(), kind, host, detail[:limit]))

    def prune_events(self, keep_days: float):
        self._q("DELETE FROM events WHERE ts < ?", (time.time() - keep_days * 86400,))

    def events(self, limit=100):
        return self._q("SELECT ts,kind,host,detail FROM events ORDER BY id DESC LIMIT ?", (limit,))
