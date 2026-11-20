"""Regression guards for the offline round2 roadmap work."""
import asyncio

from mitmproxy import connection
from mitmproxy.test import tflow

from aifilter import selfguard
from test_filter import FakeReviewer, flow_for, make_filter, png, store  # noqa: F401


def test_dns_checked_once_and_socket_pinned_with_tls_identity(store, monkeypatch):
    calls = []

    async def changing_dns(host, port):
        calls.append(host)
        return ['203.0.113.8'] if len(calls) == 1 else ['127.0.0.1']

    monkeypatch.setattr(selfguard, 'resolve', changing_dns)
    flt = make_filter(store)
    f = tflow.tflow()
    f.request.method, f.request.host, f.request.port = 'CONNECT', 'news.example', 443
    server = connection.Server(address=('news.example', 443))
    data = type('Data', (), {'server': server})()
    async def connect():
        await flt.http_connect(f)
        await flt.server_connect(data)
        # Follow the real asyncio dialer resolution path: no second DNS lookup.
        loop = asyncio.get_running_loop()
        infos = await loop._ensure_resolved(server.address, loop=loop)
        assert [info[4][0] for info in infos] == ['203.0.113.8']
    try:
        asyncio.run(connect())
    finally:
        flt.done()
    assert calls == ['news.example']
    assert server.address == ('news.example', 443)
    assert server.sni == 'news.example' and not server.error
    assert f.request.host == 'news.example'


def test_lookup_failure_refuses_upstream(store, monkeypatch):
    async def failed(host, port):
        return []

    monkeypatch.setattr(selfguard, 'resolve', failed)
    server = connection.Server(address=('missing.example', 443))
    asyncio.run(make_filter(store).server_connect(type('Data', (), {'server': server})()))
    assert 'DNS lookup failed' in server.error
    assert server.address == ('missing.example', 443)


def test_strikes_use_observed_page_per_ip_and_ignore_referer(store):
    flt = make_filter(store, FakeReviewer(bad=True))
    page = flow_for('https://observed.example/', 'text/html')
    page.client_conn.peername = ('192.0.2.1', 1111)
    flt.responseheaders(page)
    other = flow_for('https://other.example/', 'text/html')
    other.client_conn.peername = ('192.0.2.2', 2222)
    flt.responseheaders(other)
    for i in range(3):
        image = flow_for('https://cdn.example/a.png', 'image/png', png() + bytes([i]),
                         referer='https://victim.example/')
        image.client_conn.peername = ('192.0.2.1', 3333)
        flt.request(image)
        asyncio.run(flt.response(image))
    assert store.verdict('observed.example') is None
    assert store.verdict('victim.example') is None
    assert store.verdict('other.example') is None
    assert store.verdict('cdn.example') is None


def test_page_context_snapshot_survives_navigation_and_unknown_has_no_strike(store):
    flt = make_filter(store, FakeReviewer(bad=True))
    flt.responseheaders(flow_for('https://first.example/', 'text/html'))
    image = flow_for('https://first.example/a.png', 'image/png', png(), referer='https://first.example/')
    flt.request(image)
    flt.responseheaders(flow_for('https://second.example/', 'text/html'))
    asyncio.run(flt.response(image))
    assert store._q('SELECT host FROM bad_image_strikes') == [('first.example',)]
    unknown = flow_for('https://cdn.example/b.png', 'image/png', png())
    unknown.client_conn.peername = ('192.0.2.99', 1234)
    asyncio.run(flt.response(unknown))
    assert store._q('SELECT host FROM bad_image_strikes') == [('first.example',)]


# A spawned stub must not import this whole test module to unpickle its factory.
from worker_fixtures import ProcessReviewer


def test_worker_pool_reuses_replaces_and_reaps_processes():
    from aifilter.workers import ReviewPool
    pool = ReviewPool(size=1, factory=ProcessReviewer)
    async def run():
        first = await pool.review(b'ok', 10)
        assert first[0] == 'ok'
        assert await pool.review(b'ok', 2) == first  # model process stays warm
        assert await pool.review(b'invalid', 2) == ('invalid', [])
        old = pool.workers[0].process
        assert (await pool.review(b'hang', 0.1))[0] == 'timeout'
        assert pool.workers[0].process is None  # reaped before releasing the slot
        assert old._closed
        second = await pool.review(b'ok', 10)
        assert second[0] == 'ok' and second != first
        assert (await pool.review(b'crash', 2))[0] == 'error'
        assert (await pool.review(b'ok', 10))[0] == 'ok'
    try:
        asyncio.run(run())
    finally:
        pool.close()
    assert all(w.process is None for w in pool.workers)


def test_addon_uses_process_pool_and_releases_permit_on_timeout(store):
    import addon
    from aifilter import config
    from aifilter.workers import ReviewPool
    flt = addon.AIFilter(config.load(), store)
    flt._pool = ReviewPool(size=1, factory=ProcessReviewer)
    flt.cfg.raw['vision']['timeout_seconds'] = 0.1
    try:
        assert asyncio.run(flt._run_review(b'hang'))[0] == 'timeout'
        assert flt._sem._value == 2
        flt.cfg.raw['vision']['timeout_seconds'] = 10
        assert asyncio.run(flt._run_review(b'ok'))[0] == 'ok'
    finally:
        flt.done()


def _detector_reviewer():
    from aifilter.vision import Reviewer
    reviewer = Reviewer.__new__(Reviewer)
    reviewer.min_score, reviewer.labels = 0.45, {'FEMALE_BREAST_EXPOSED'}
    class Detector:
        def __init__(self):
            self.sizes = []
        def detect(self, mat):
            self.sizes.append(mat.shape[:2])
            # Red content is the fixture's unsafe frame (BGR input).
            if mat[0, 0, 2] > 200:
                return [{'class': 'FEMALE_BREAST_EXPOSED', 'score': 0.9}]
            return []
    reviewer._detector = Detector()
    return reviewer


import pytest
from PIL import Image
import io


@pytest.mark.parametrize('fmt', ['GIF', 'WEBP', 'PNG'])
def test_animated_images_sample_later_frames_and_resize(fmt):
    reviewer = _detector_reviewer()
    frames = [Image.new('RGB', (1280, 720), c) for c in ('black', 'red', 'black', 'black', 'black')]
    # Unsafe middle frame, first and last harmless.
    frames[1], frames[2] = frames[2], frames[1]
    out = io.BytesIO()
    frames[0].save(out, fmt, save_all=True, append_images=frames[1:], duration=100, loop=0,
                   lossless=True, optimize=False)
    bad, labels = reviewer.review(out.getvalue())
    assert bad and labels
    assert 1 < len(reviewer._detector.sizes) <= 3
    assert all(max(size) <= 640 for size in reviewer._detector.sizes)


def test_invalid_and_small_undecodable_images_hidden_without_cache_or_strike(store):
    reviewer = _detector_reviewer()
    flt = make_filter(store, reviewer)
    for data in (b'', b'not an image', b'\x89PNG\r\n\x1a\n' + b'x' * 3000):
        image = flow_for('https://cdn.example/a.png', 'image/png', data)
        asyncio.run(flt.response(image))
        from aifilter.pages import PLACEHOLDER_PNG
        assert image.response.content == PLACEHOLDER_PNG
    assert not store._q('SELECT * FROM images')
    assert not store._q('SELECT * FROM bad_image_strikes')


def test_static_resize_preserves_aspect_and_never_upscales():
    from aifilter.vision import decode
    out = io.BytesIO()
    Image.new('RGB', (1280, 320)).save(out, 'PNG')
    assert decode(out.getvalue()).shape[:2] == (160, 640)
    out = io.BytesIO()
    Image.new('RGB', (12, 16)).save(out, 'PNG')
    assert decode(out.getvalue()).shape[:2] == (16, 12)


@pytest.mark.parametrize('context', ['prevention', 'addiction', 'help', 'education', 'מניעה', 'התמכרות', 'עזרה'])
def test_safety_text_blocks_only_page_never_host(store, context):
    flt = make_filter(store)
    page = flow_for('https://education.example/article', 'text/html; charset=utf-8',
                    f'<p>{context}: porn xxx nude porn</p>'.encode())
    asyncio.run(flt.response(page))
    assert page.response.status_code == 403
    assert store.verdict('education.example') is None
    normal = flow_for('https://education.example/home', 'text/html', b'<p>Welcome to school</p>')
    flt.request(normal)
    asyncio.run(flt.response(normal))
    assert normal.response.status_code == 200


def test_hidden_safety_words_do_not_immunize_host(store):
    flt = make_filter(store)
    page = flow_for('https://adult.example/', 'text/html',
                    b'<script>prevention help</script><p>porn xxx nude porn</p>')
    asyncio.run(flt.response(page))
    assert store.verdict('adult.example') == 'block'


@pytest.mark.parametrize('host,expected', [
    ('a.alice.github.io', 'alice.github.io'), ('a.bob.blogspot.com', 'bob.blogspot.com'),
    ('www.ynet.co.il', 'ynet.co.il'), ('a.b.k12.ak.us', 'b.k12.ak.us'),
    ('a.b.ck', 'a.b.ck'), ('a.www.ck', 'www.ck'),
    ('x.city.kawasaki.jp', 'city.kawasaki.jp'), ('x.foo.kawasaki.jp', 'x.foo.kawasaki.jp'),
    ('WWW.Example.COM.', 'example.com'), ('127.0.0.1', '127.0.0.1'), ('::1', '::1'),
    ('www.食狮.com.cn', 'xn--85x722f.com.cn'),
])
def test_offline_psl_tenants_wildcards_exceptions_and_ips(host, expected):
    from aifilter.store import registrable
    assert registrable(host) == expected


def test_domain_precedence_stops_at_private_tenant_and_ai_exact_host(store):
    from aifilter.store import ALLOW, BLOCK
    store.set_verdict('github.io', BLOCK, 'admin')
    store.set_verdict('alice.github.io', ALLOW, 'admin')
    assert store.verdict('x.alice.github.io') == ALLOW
    assert store.verdict('bob.github.io') is None
    store.set_verdict('section.alice.github.io', BLOCK, 'admin')
    assert store.verdict('x.section.alice.github.io') == BLOCK
    assert not store.ai_block('x.section.alice.github.io', 'test')
    store.set_override('x.section.alice.github.io', ALLOW, 'admin', 'test', 1)
    assert store.verdict('x.section.alice.github.io') == ALLOW
    assert store.ai_block('bad.bob.github.io', 'test')
    assert store.verdict('child.bad.bob.github.io') is None
    assert store.verdict('bob.github.io') is None
    store.replace_blocklists([('blogspot.com', 'too broad'), ('bad.blogspot.com', 'tenant')])
    assert store.verdict('good.blogspot.com') is None
    assert store.verdict('x.bad.blogspot.com') == BLOCK


def test_scoped_video_approval_does_not_trust_images_and_expires(store, monkeypatch):
    import time
    from aifilter.pages import PLACEHOLDER_PNG
    flt = make_filter(store, FakeReviewer(bad=True))
    now = time.time()
    monkeypatch.setattr(time, 'time', lambda: now)
    store.grant_video('cdn.school.example', '/lessons', 1, 'reviewed lesson collection')
    for path, status in [('/lessons/a.mp4?token=x', 200), ('/lessons-other/a.mp4', 403), ('/other/a.mp4', 403)]:
        f = flow_for('https://cdn.school.example' + path, 'video/mp4')
        flt.responseheaders(f)
        assert f.response.status_code == status
    for host in ['other.school.example', 'sub.cdn.school.example']:
        f = flow_for('https://' + host + '/lessons/a.mp4', 'video/mp4')
        flt.responseheaders(f)
        assert f.response.status_code == 403
    image = flow_for('https://cdn.school.example/lessons/a.png', 'image/png', png())
    asyncio.run(flt.response(image))
    assert image.response.content == PLACEHOLDER_PNG
    assert store.verdict('cdn.school.example') is None
    monkeypatch.setattr(time, 'time', lambda: now + 86401)
    assert not store.video_allowed('cdn.school.example', '/lessons/a.mp4')


def test_video_grants_never_override_blocks_textonly_or_identity(store):
    from aifilter.store import BLOCK, TEXT_ONLY
    flt = make_filter(store)
    store.grant_video('school.example', '/lessons', 1, 'test')
    f = flow_for('https://school.example/lessons/a.mp4', 'video/mp4')
    f.client_conn.sni = 'other.example'
    flt.responseheaders(f)
    assert f.response.status_code == 403
    for verdict in [BLOCK, TEXT_ONLY]:
        store.set_verdict('school.example', verdict, 'admin')
        f = flow_for('https://school.example/lessons/a.mp4', 'video/mp4')
        flt.responseheaders(f)
        assert f.response.status_code == 403
    store.revoke_video('school.example', '/lessons')
    assert not store.video_allowed('school.example', '/lessons/a.mp4')


def test_video_scope_rejects_traversal_and_unbounded_duration(store):
    for days in [0, -1, 31, float('inf'), float('nan'), True]:
        with pytest.raises(ValueError):
            store.grant_video('school.example', '/lessons', days, 'test')
    for path in ['/lessons/../other', '/lessons/%2e%2e/other', '/lessons/%252e%252e/other', 'relative', '/lessons?x=1']:
        with pytest.raises(ValueError):
            store.grant_video('school.example', path, 1, 'test')
    store.grant_video('school.example', '/lessons', 1, 'test')
    assert not store.video_allowed('school.example', '/lessons/%2e%2e/other.mp4')


def test_ca_failure_keeps_pac_alive_and_never_starts_proxy(tmp_path):
    import os
    import signal
    import subprocess
    import time
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    script = tmp_path / 'run.sh'
    script.write_text((root / 'run.sh').read_text())
    bindir = tmp_path / '.venv' / 'bin'
    bindir.mkdir(parents=True)
    python = bindir / 'python'
    python.write_text('''#!/bin/bash
if [ "$1" = "-c" ]; then echo 18000; exit 0; fi
if [ "$2" = "aifilter.cacheck" ]; then echo CA_FAIL >> events; exit 1; fi
if [ "$2" = "http.server" ]; then
  echo PAC_START >> events
  trap 'echo PAC_STOP >> events; exit 0' TERM INT
  while true; do sleep 1; done
fi
exit 0
''')
    python.chmod(0o755)
    mitm = bindir / 'mitmdump'
    mitm.write_text('#!/bin/bash\necho FORBIDDEN_PROXY_START >> events\n')
    mitm.chmod(0o755)
    proc = subprocess.Popen(['bash', str(script)], cwd=tmp_path, start_new_session=True,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 5
        events = tmp_path / 'events'
        while time.monotonic() < deadline:
            content = events.read_text() if events.exists() else ''
            if 'PAC_START' in content and 'CA_FAIL' in content:
                break
            time.sleep(0.02)
        assert 'PAC_START' in content and 'CA_FAIL' in content
        time.sleep(0.15)
        assert proc.poll() is None
        assert 'PAC_STOP' not in events.read_text()
        assert 'FORBIDDEN_PROXY_START' not in events.read_text()
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=5)


def test_legacy_first_frame_cache_cannot_bypass_new_review(store):
    import hashlib
    from aifilter.pages import PLACEHOLDER_PNG
    data = png()
    store.set_image_verdict(hashlib.sha1(data).hexdigest(), False, 'old first-frame decision')
    rev = FakeReviewer(bad=True)
    flt = make_filter(store, rev)
    image = flow_for('https://cdn.example/a.png', 'image/png', data)
    asyncio.run(flt.response(image))
    assert rev.calls == 1 and image.response.content == PLACEHOLDER_PNG


def test_apng_poster_does_not_displace_animation_samples():
    reviewer = _detector_reviewer()
    out = io.BytesIO()
    poster = Image.new('RGB', (200, 200), 'black')
    frames = [Image.new('RGB', (200, 200), c) for c in ('black', 'red', 'black')]
    poster.save(out, 'PNG', save_all=True, append_images=frames, default_image=True, duration=100)
    assert reviewer.review(out.getvalue())[0]
    assert len(reviewer._detector.sizes) == 3


def test_late_html_completion_does_not_replace_newer_page_context(store):
    flt = make_filter(store)
    older = flow_for('https://older.example/', 'text/html', b'hello')
    flt.responseheaders(older)
    flt.responseheaders(flow_for('https://newer.example/', 'text/html', b'hello'))
    asyncio.run(flt.response(older))
    image = flow_for('https://cdn.example/a.png', 'image/png', png())
    assert flt._page_host(image) == 'newer.example'


def test_idna_decisions_and_lists_use_same_psl_normalization(store):
    store.set_verdict('食狮.com.cn', 'allow', 'admin')
    assert store.verdict('www.xn--85x722f.com.cn') == 'allow'
    store.replace_blocklists([('example.cn', 'base'), ('bad.example.cn', 'specific')])
    assert store.listed('x.bad.example.cn') == 'specific'


def test_cancelled_review_reaps_worker_and_returns_slot():
    from aifilter.workers import ReviewPool
    pool = ReviewPool(size=1, factory=ProcessReviewer)
    async def run():
        assert (await pool.review(b'ok', 10))[0] == 'ok'
        old = pool.workers[0].process
        task = asyncio.create_task(pool.review(b'hang', 20))
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert old._closed and pool.free.qsize() == 1
        assert (await pool.review(b'ok', 10))[0] == 'ok'
    try:
        asyncio.run(run())
    finally:
        pool.close()


def test_pinned_dial_preserves_connection_reuse_and_checked_address_fallback(store, monkeypatch):
    import socket
    from mitmproxy.proxy.layers.http import GetHttpConnection
    from mitmproxy import connection
    calls, attempts = [], []
    async def resolve(host, port):
        calls.append(host)
        # IPv4 is dialed first; when it fails, asyncio must still try the checked IPv6.
        return ['2001:db8::1', '203.0.113.9']
    monkeypatch.setattr(selfguard, 'resolve', resolve)
    flt = make_filter(store)
    server = connection.Server(address=('news.example', 443), tls=True)
    async def run():
        loop = asyncio.get_running_loop()
        await flt.server_connect(type('Data', (), {'server': server})())
        assert not server.error
        assert GetHttpConnection(('news.example', 443), True, None).connection_spec_matches(server)
        assert hash(server.address) == hash(('news.example', 443))
        async def no_dns(*args, **kwargs):
            raise AssertionError('second DNS lookup')
        flt._resolvers[loop].original = no_dns
        async def connect_sock(exceptions, addr_info, local_addr_infos=None):
            attempts.append(addr_info[4][0])
            if addr_info[0] == socket.AF_INET:
                raise OSError('IPv4 route unavailable')
            return 'connected-socket'
        async def transport(sock, protocol_factory, ssl, *args, **kwargs):
            assert sock == 'connected-socket'
            return 'transport', 'protocol'
        monkeypatch.setattr(loop, '_connect_sock', connect_sock)
        monkeypatch.setattr(loop, '_create_connection_transport', transport)
        assert await loop.create_connection(lambda: None, *server.address) == ('transport', 'protocol')
        # Pinned passthrough dials opt in to asyncio's staggered multi-address
        # attempts, so a black-holed Apple edge cannot consume the whole timeout.
        assert flt._resolvers[loop].connect_wrapper == loop.create_connection
    try:
        asyncio.run(run())
    finally:
        flt.done()
    assert calls == ['news.example']
    assert attempts == ['203.0.113.9', '2001:db8::1']


def test_pinned_dial_enables_happy_eyeballs_for_passthrough_addresses(monkeypatch):
    import socket
    calls = []

    async def run():
        loop = asyncio.get_running_loop()
        original = loop.create_connection

        async def dial(*args, **kwargs):
            calls.append(kwargs)
            return 'transport', 'protocol'

        monkeypatch.setattr(loop, 'create_connection', dial)
        resolver = selfguard.PinnedResolver.install(loop)
        host = selfguard.PinnedHost('amp-account.itunes.apple.com', 443,
                                    ['17.157.96.170', '17.32.214.33'])
        try:
            assert await loop.create_connection(lambda: None, host, 443) == ('transport', 'protocol')
        finally:
            # Let close restore both loop methods after asyncio.run stops it.
            resolver.original_create_connection = original

    asyncio.run(run())
    assert calls == [{'happy_eyeballs_delay': 0.25, 'interleave': 1}]


def test_pinned_resolver_scopes_ports_and_delegate_lifetime(monkeypatch):
    import socket
    async def run():
        loop = asyncio.get_running_loop()
        calls = []
        async def ordinary(host, port, **kwargs):
            calls.append((host, port))
            return ['ordinary']
        monkeypatch.setattr(loop, 'getaddrinfo', ordinary)
        resolver = selfguard.PinnedResolver(loop)
        try:
            assert await loop.getaddrinfo('ordinary.example', 443) == ['ordinary']
            assert calls == [('ordinary.example', 443)]
            pinned = selfguard.PinnedHost('pinned.example', 443, ['203.0.113.9'])
            with pytest.raises(OSError):
                await loop.getaddrinfo(pinned, 8090)
            with pytest.raises(OSError):
                await loop.getaddrinfo(pinned, 443, type=socket.SOCK_DGRAM)
            infos = await loop.getaddrinfo(pinned, 443)
            assert infos[0][4] == ('203.0.113.9', 443) and len(calls) == 1
            # Never clobber a later resolver installed by another addon.
            loop.getaddrinfo = ordinary
        finally:
            resolver.close()
        assert loop.getaddrinfo is ordinary
    asyncio.run(run())


def test_scoped_ipv6_keeps_scope_for_local_guard_and_dialer(monkeypatch):
    import socket
    async def run():
        loop = asyncio.get_running_loop()
        infos = [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('fe80::1', 8090, 7, 3))]
        async def getaddrinfo(*args, **kwargs):
            return infos
        monkeypatch.setattr(loop, 'getaddrinfo', getaddrinfo)
        ips = await selfguard.resolve('local.example', 8090)
        assert ips == ['fe80::1%3']
        seen = []
        def local(ip):
            seen.append(ip)
            return True
        assert selfguard.refusal(ips, 8090, {8090}, is_local=local)
        assert seen == ['fe80::1%3']
        assert selfguard.PinnedHost('local.example', 8090, ips).addrinfos == tuple(infos)
    asyncio.run(run())


def test_reload_keeps_pending_dials_pinned_and_reuses_resolver(store):
    from mitmproxy import connection
    flt = make_filter(store)
    async def run():
        loop = asyncio.get_running_loop()
        resolver = selfguard.PinnedResolver.install(loop)
        flt._resolvers[loop] = resolver
        pinned = selfguard.PinnedHost('pending.example', 443, ['203.0.113.9'])
        async def forbidden_dns(*args, **kwargs):
            raise AssertionError('pending dial lost its pin')
        resolver.original = forbidden_dns
        flt.done()  # script reload while the loop is still active
        assert loop.getaddrinfo is resolver.wrapper
        assert selfguard.PinnedResolver.install(loop) is resolver
        infos = await loop._ensure_resolved((pinned, 443), loop=loop)
        assert infos[0][4] == ('203.0.113.9', 443)
        # An unrelated resolver replacement must never silently unpin new dials.
        loop.getaddrinfo = forbidden_dns
        server = connection.Server(address=('8.8.8.8', 443))
        with pytest.raises(RuntimeError):
            selfguard.PinnedResolver.install(loop)
    asyncio.run(run())


def test_loopback_detection_never_requires_permission_to_bind(monkeypatch):
    import socket
    def forbidden(*args):
        raise PermissionError('sandbox disallows bind probes')
    monkeypatch.setattr(socket, 'socket', forbidden)
    assert selfguard.is_local_address('127.0.0.1')
    assert selfguard.is_local_address('::1')
    assert selfguard.is_local_address('::ffff:127.0.0.1')


def test_reload_cannot_create_worker_after_waiting_for_permit(store):
    import addon
    from aifilter import config
    flt = addon.AIFilter(config.load(), store)
    flt._sem = asyncio.Semaphore(0)
    async def run():
        waiting = asyncio.create_task(flt._run_review(b'not started'))
        await asyncio.sleep(0)
        flt.done()
        flt._sem.release()
        assert await waiting == ('error', ['addon stopped'])
        assert flt._sem._value == 1 and flt._pool is None
    asyncio.run(run())


def test_real_model_runs_inside_production_pool_and_shutdown_reaps_it(store):
    import addon
    from aifilter import config
    cfg = config.load()
    cfg.raw['vision'].update(max_parallel=1, timeout_seconds=10)
    flt = addon.AIFilter(cfg, store)
    out = io.BytesIO()
    Image.new('RGB', (1280, 720), 'white').save(out, 'PNG')
    image = flow_for('https://school.example/plain.png', 'image/png', out.getvalue())
    try:
        asyncio.run(flt.response(image))
        assert image.response.content == out.getvalue()
        assert flt._pool is not None
        assert flt._pool.workers[0].process.is_alive()
    finally:
        flt.done()
    assert flt._pool.workers[0].process is None
