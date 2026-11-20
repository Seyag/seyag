"""Proxy-only memory policy and bounded write-behind; SQLite stays off hooks.

The worker polls SQLite data_version every 250 ms for committee/list changes.
Expiry is checked at lookup time, so a cached approval never outlives its grant.
The ordinary Store remains the synchronous admin/DNS interface.
"""
import json
import math
import queue
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path

from aifilter import suffixes
from aifilter.store import Store, BLOCK
from aifilter.suffixes import ancestors, normalize, registrable


class Latency:
    def __init__(self, path, interval=300, clock=time.monotonic):
        self.path, self.interval, self.clock = Path(path), interval, clock
        self.last = clock()
        self.samples = {}
        self.lock = threading.Lock()

    def add(self, hook, seconds):
        with self.lock:
            self.samples.setdefault(hook, deque(maxlen=4096)).append(seconds * 1000)

    def flush(self, **counters):
        """Called only by the I/O worker, even on otherwise idle connections."""
        now = self.clock()
        if now - self.last < self.interval:
            return
        with self.lock:
            samples, self.samples = self.samples, {}
        rows = {}
        for hook, values in samples.items():
            values = sorted(values)
            rows[hook] = {"samples": len(values), "p50_ms": values[math.ceil(len(values) * .5) - 1],
                          "p95_ms": values[math.ceil(len(values) * .95) - 1]}
        record = {"ts": time.time(), "window_seconds": now - self.last, "hooks": rows, **counters}
        self.last = now
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.stat().st_size > 2_000_000:
            self.path.replace(self.path.with_suffix('.log.1'))
        with self.path.open('a') as out:
            out.write(json.dumps(record) + '\n')


class ProxyStore:
    """One producer/event loop, one I/O thread, atomically replaced policy snapshots.

    Hooks never open SQLite, wait for a transaction or touch the filesystem.
    On saturation telemetry may drop; policy/strike overlays remain enforced in
    memory. Counters expose saturation/errors rather than stalling browsing.
    """
    def __init__(self, path, *, latency=None, recent_hosts=None, max_queue=8192, poll=.25):
        self.path, self.latency = path, latency
        self.recent_hosts = Path(recent_hosts) if recent_hosts else None
        self.poll = poll
        self.queue = queue.Queue(max_queue)
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._lock = threading.RLock()
        self._policy = ({}, {}, {}, set(), {})
        self._images = OrderedDict()
        self._ai = {}
        self._strikes = {}
        self._appeals = set()
        self._pending_appeals = {}
        self._cache = OrderedDict()
        self.generation = 0
        self.dropped = self.errors = 0
        self._startup_error = None
        self._shutdown_deadline = float("inf")
        self._thread = threading.Thread(target=self._work, name='proxy-store', daemon=True)
        self._thread.start()
        # Startup only, before any request hooks are dispatched.
        if not self._ready.wait(15):
            self._stop.set()
            raise RuntimeError('proxy policy startup timed out')
        if self._startup_error:
            raise RuntimeError('proxy policy startup failed') from self._startup_error

    def _refresh(self, store):
        with store._lock:
            db = store._db
            db.execute('BEGIN')
            try:
                domains = {h: (v, s) for h, v, s in db.execute('SELECT host,verdict,source FROM domains WHERE expires IS NULL')}
                overrides = {h: (v, e, d) for h, v, e, d in db.execute(
                    'SELECT host,verdict,expires,include_subdomains FROM overrides')}
                lists = dict(db.execute('SELECT host,list FROM blocklist'))
                passthrough = {r[0] for r in db.execute('SELECT host FROM passthrough')}
                videos = {}
                for h, p, e in db.execute('SELECT host,path_prefix,expires FROM video_permissions'):
                    videos.setdefault(h, []).append((p, e))
                pending = {r[0] for r in db.execute("SELECT host FROM appeals WHERE status='pending'")}
                db.execute('COMMIT')
            except BaseException:
                db.execute('ROLLBACK')
                raise
        with self._lock:
            self._policy = domains, overrides, lists, passthrough, videos
            self._appeals = pending
            self._cache.clear()
            self.generation += 1

    def _work(self):
        store = None
        try:
            suffixes._rules()  # load/normalize the vendored PSL off the event loop
            store = Store(self.path)
            store._q('PRAGMA busy_timeout=250')
            version = store._q('PRAGMA data_version')[0][0]
            self._refresh(store)
            # Strikes/images are loaded once. Subsequent proxy writes update memory first.
            self._images.update((d, bool(b)) for d, b in store._q(
                'SELECT digest,bad FROM images ORDER BY updated DESC LIMIT 4096')[::-1])
            for h, ts in store._q('SELECT host,ts FROM bad_image_strikes'):
                self._strikes.setdefault(h, []).append(ts)
        except Exception as exc:
            self._startup_error = exc
            if store:
                store._db.close()
            self._ready.set()
            return
        self._ready.set()
        next_poll = time.monotonic() + self.poll
        try:
            while (not self._stop.is_set() or not self.queue.empty()) and time.monotonic() < self._shutdown_deadline:
                try:
                    operation, args = self.queue.get(timeout=max(0, min(self.poll, next_poll - time.monotonic())))
                except queue.Empty:
                    operation = None
                if operation:
                    batch = [(operation, args)]
                    for _ in range(127):
                        try:
                            batch.append(self.queue.get_nowait())
                        except queue.Empty:
                            break
                    changed = []
                    appeals = []
                    committed = False
                    try:
                        store._q('BEGIN')
                        for operation, args in batch:
                            try:
                                if operation == 'note_host':
                                    self._write_host(*args)
                                else:
                                    getattr(store, operation)(*args)
                                    if operation == 'ai_block':
                                        changed.append(args)
                                    elif operation == 'add_appeal':
                                        appeals.append(normalize(args[0]))
                            except Exception:
                                self.errors += 1
                                if operation == 'add_appeal':
                                    with self._lock:
                                        self._finish_appeal(normalize(args[0]))
                        store._q('COMMIT')
                        committed = True
                        with self._lock:
                            for host in appeals:
                                self._appeals.add(host)  # now persisted, before removing queued overlay
                                self._finish_appeal(host)
                        if changed or appeals:
                            self._refresh(store)
                            with self._lock:
                                for host, reason in changed:
                                    if self._ai.get(host) == reason:
                                        self._ai.pop(host, None)
                                self._cache.clear()
                    except Exception:
                        self.errors += 1
                        if not committed:
                            with self._lock:
                                for host in appeals:
                                    self._finish_appeal(host)
                        try:
                            store._q('ROLLBACK')
                        except Exception:
                            pass
                    finally:
                        for _ in batch:
                            self.queue.task_done()
                if time.monotonic() >= next_poll:
                    try:
                        # A site block that was dropped (full queue) or failed to save is
                        # retried here until it is durable; memory keeps enforcing it meanwhile.
                        with self._lock:
                            unsaved = list(self._ai.items())
                        for host, reason in unsaved:
                            store.ai_block(host, reason)
                        if unsaved:
                            self._refresh(store)
                            with self._lock:
                                for host, reason in unsaved:
                                    if self._ai.get(host) == reason:
                                        self._ai.pop(host, None)
                                self._cache.clear()
                        current = store._q('PRAGMA data_version')[0][0]
                        if current != version:
                            self._refresh(store)
                            version = current
                        if self.latency:
                            self.latency.flush(io_errors=self.errors, writes_dropped=self.dropped)
                    except Exception:
                        self.errors += 1
                    next_poll = time.monotonic() + self.poll
        finally:
            store._db.close()

    def _enqueue(self, operation, *args):
        try:
            self.queue.put_nowait((operation, args))
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def close(self):
        self._shutdown_deadline = time.monotonic() + 1.5
        self._stop.set()
        self._thread.join(timeout=2)  # never hang mitmproxy shutdown on a locked DB

    def flush(self, timeout=5):
        """Tests/benchmarks only; never called from proxy hooks."""
        deadline = time.monotonic() + timeout
        while self.queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(.005)
        return not self.queue.unfinished_tasks

    def _decision(self, host, lists):
        names, now = ancestors(host), time.time()
        domains, overrides, blocklists, _, _ = self._policy
        # Earliest expiry also bounds cached negative/standing/list results.
        expires = min((overrides[h][1] for h in names if h in overrides and overrides[h][1] > now), default=now + 60)
        for i, h in enumerate(names):
            override = overrides.get(h)
            if override and h != host and not override[2]:
                override = None
            row = domains.get(h)
            standing = row[0] if row and (row[1] != 'ai' or h == host) else None
            temporary = override[0] if override and override[1] > now else None
            if temporary is not None and i and lists and standing is None and any(n in blocklists for n in names[:i]):
                return BLOCK, expires  # an inherited approval never beats a more specific list entry
            if temporary is not None:
                return temporary, expires
            if standing is not None:
                return standing, expires
        if host in self._ai:
            return BLOCK, expires
        return (BLOCK if lists and any(h in blocklists for h in names) else None), expires

    def verdict(self, host, lists=True):
        host = normalize(host)
        key = host, lists
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached[1] > time.time():
                self._cache.move_to_end(key)
                return cached[0]
            result = self._decision(host, lists)
            self._cache[key] = result
            self._cache.move_to_end(key)
            if len(self._cache) > 8192:
                self._cache.popitem(last=False)
            return result[0]

    def listed(self, host):
        lists = self._policy[2]
        return next((lists[h] for h in ancestors(host) if h in lists), None)

    def passthrough_hosts(self):
        return self._policy[3]  # immutable after publication

    def video_allowed(self, host, path):
        try:
            path = Store._video_path(path)
        except ValueError:
            return False
        return any(e > time.time() and (p == '/' or path == p or path.startswith(p + '/'))
                   for p, e in self._policy[4].get(normalize(host), ()))

    def ai_block(self, host, reason):
        host = normalize(host)
        with self._lock:
            domains, overrides, _, _, _ = self._policy
            if any((h in domains and domains[h][1] in ('admin', 'policy')) or
                   (h in overrides and overrides[h][1] > time.time()) for h in ancestors(host)):
                return False
            self._ai[host] = reason
            self._cache.clear()
            self._enqueue('ai_block', host, reason)
            return True

    def image_verdict(self, digest):
        with self._lock:
            if digest in self._images:
                self._images.move_to_end(digest)
            return self._images.get(digest)

    def set_image_verdict(self, digest, bad, labels):
        with self._lock:
            self._images[digest] = bad
            self._images.move_to_end(digest)
            if len(self._images) > 4096:
                self._images.popitem(last=False)
        self._enqueue('set_image_verdict', digest, bad, labels)

    def add_strike(self, host, days=7):
        host, now = normalize(host), time.time()
        with self._lock:
            hits = [ts for ts in self._strikes.get(host, ()) if ts >= now - days * 86400]
            hits.append(now)
            self._strikes[host] = hits[-50:]
            if len(self._strikes) > 4096:  # bounded: forget the hosts struck longest ago
                for old in sorted(self._strikes, key=lambda h: self._strikes[h][-1])[:1024]:
                    del self._strikes[old]
        self._enqueue('add_strike', host, days)
        return len(hits)

    def appeals_for(self, host):
        name = normalize(host)
        with self._lock:
            return [True] if name in self._appeals or name in self._pending_appeals else []

    def _finish_appeal(self, name):
        count = self._pending_appeals.get(name, 0) - 1
        if count > 0:
            self._pending_appeals[name] = count
        else:
            self._pending_appeals.pop(name, None)

    def add_appeal(self, host, url, note=''):
        with self._lock:
            name = normalize(host)
            self._pending_appeals[name] = self._pending_appeals.get(name, 0) + 1
        if not self._enqueue('add_appeal', host, url, note):
            with self._lock:
                self._finish_appeal(name)

    def record_tls_failure(self, host):
        self._enqueue('record_tls_failure', host)

    def record_connect_failure(self, host, detail):
        self._enqueue('record_connect_failure', host, detail)

    def log(self, kind, host='', detail=''):
        self._enqueue('log', kind, host, detail[:500])

    def note_host(self, host, peer, mode):
        if host:
            self._enqueue('note_host', host, peer, mode)

    def _write_host(self, host, peer, mode):
        if not self.recent_hosts:
            return
        self.recent_hosts.parent.mkdir(parents=True, exist_ok=True)
        if self.recent_hosts.exists() and self.recent_hosts.stat().st_size > 2_000_000:
            self.recent_hosts.replace(self.recent_hosts.with_suffix('.log.1'))
        with self.recent_hosts.open('a') as out:
            out.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {peer[0] if peer else '-'} {mode} {host}\n")
