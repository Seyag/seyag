"""Local-only guards for round3: no live files or paid/network services."""
import asyncio
import base64
import json
import threading
import time
from pathlib import Path

import pytest

import addon
from aifilter import config, text
from aifilter.hotstore import Latency, ProxyStore
from aifilter.store import Store, ALLOW, BLOCK, TEXT_ONLY, TRUSTED
from test_filter import FakeReviewer, flow_for, make_filter, png, store  # noqa: F401


def eventually(predicate, timeout=3):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(.01)
    assert predicate()


@pytest.fixture
def hot(tmp_path):
    memory = ProxyStore(tmp_path / 'test.sqlite', recent_hosts=tmp_path / 'hosts.log', poll=.01)
    yield memory
    assert memory.flush()
    memory.close()
    assert not memory._thread.is_alive()


def test_sqlite_never_runs_on_hook_thread(hot, monkeypatch):
    main = threading.get_ident()
    original = Store._q
    calls = []

    def checked(self, *args, **kwargs):
        assert threading.get_ident() != main, 'SQLite on event loop'
        calls.append(threading.get_ident())
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Store, '_q', checked)
    flt = make_filter(hot, FakeReviewer(bad=True))
    page = flow_for('https://page.example/', 'text/html', b'<p>hello</p>')
    flt.request(page)
    flt.responseheaders(page)
    asyncio.run(flt.response(page))
    image = flow_for('https://page.example/image.png', 'image/png', png(), referer='https://page.example/')
    flt.request(image)
    asyncio.run(flt.response(image))
    hot.note_host('apple.com', ('192.0.2.1', 123), 'pass')
    assert hot.flush()
    assert calls
    connection = Store(hot.path)
    raw = original(connection, 'SELECT host FROM bad_image_strikes')
    connection._db.close()
    assert raw == [('page.example',)]
    assert hot.recent_hosts.read_text().endswith('pass apple.com\n')


def test_external_committee_changes_invalidate_warm_decisions(hot):
    admin = Store(hot.path)
    assert hot.verdict('a.example') is None
    admin.set_verdict('a.example', BLOCK, 'admin')
    eventually(lambda: hot.verdict('a.example') == BLOCK)
    admin.set_override('a.example', ALLOW, 'admin', 'brief approval', 1)
    eventually(lambda: hot.verdict('a.example') == ALLOW)
    admin._q('UPDATE overrides SET expires=?', (time.time() - 1,))
    eventually(lambda: hot.verdict('a.example') == BLOCK)
    admin._db.close()


def test_approval_expiry_checked_without_database_or_poll(hot, monkeypatch):
    now = time.time()
    clock = [now]
    monkeypatch.setattr(time, 'time', lambda: clock[0])
    with hot._lock:  # override rows are (verdict, expires, include_subdomains)
        hot._policy = ({'example.com': (BLOCK, 'policy')},
                       {'example.com': (ALLOW, now + 100, 1)}, {}, set(), {})
        hot._cache.clear()
    assert hot.verdict('www.example.com') == ALLOW
    clock[0] = now + 101
    assert hot.verdict('www.example.com') == BLOCK
    with hot._lock:  # without explicit parent scope the approval never reaches a subdomain
        hot._policy = ({'example.com': (BLOCK, 'policy')},
                       {'example.com': (ALLOW, clock[0] + 100, 0)}, {}, set(), {})
        hot._cache.clear()
    assert hot.verdict('example.com') == ALLOW and hot.verdict('www.example.com') == BLOCK


def test_memory_policy_parity_and_list_reload(hot):
    admin = Store(hot.path)
    admin.replace_blocklists([('example.com', 'list'), ('tenant.github.io', 'list')])
    admin.set_verdict('safe.example.com', TRUSTED, 'admin')
    admin.set_verdict('ai.example.net', BLOCK, 'ai')
    admin.set_override('example.com', TEXT_ONLY, 'admin', 'temporary', .1)
    admin.add_passthrough('pinned.example')
    admin.grant_video('video.example', '/lessons', 1, 'class')
    eventually(lambda: hot.video_allowed('video.example', '/lessons/1'))
    for host in ('example.com', 'safe.example.com', 'x.safe.example.com', 'ai.example.net',
                 'child.ai.example.net', 'tenant.github.io', 'other.github.io'):
        assert hot.verdict(host) == admin.verdict(host)
        assert hot.verdict(host, lists=False) == admin.verdict(host, lists=False)
        assert hot.listed(host) == admin.listed(host)
    assert hot.passthrough_hosts() == admin.passthrough_hosts()
    assert not hot.video_allowed('video.example', '/lessons-other')
    admin.revoke_video('video.example', '/lessons')
    eventually(lambda: not hot.video_allowed('video.example', '/lessons/1'))
    admin._db.close()


def test_write_behind_ai_cannot_override_committee(hot):
    admin = Store(hot.path)
    admin.set_verdict('safe.example', ALLOW, 'admin')
    eventually(lambda: hot.verdict('safe.example') == ALLOW)
    assert not hot.ai_block('safe.example', 'AI')
    assert hot.ai_block('bad.example', 'AI')
    assert hot.verdict('bad.example') == BLOCK
    assert hot.verdict('child.bad.example') is None
    hot.set_image_verdict('digest', True, 'bad')
    assert hot.image_verdict('digest') is True
    assert hot.add_strike('bad.example') == 1
    assert hot.add_strike('bad.example') == 2
    hot.log('test', 'bad.example')
    assert hot.flush()
    assert admin.verdict('bad.example') == BLOCK
    assert admin.image_verdict('digest') is True
    assert admin._q('SELECT count(*) FROM bad_image_strikes')[0][0] == 2
    admin._db.close()


def test_worker_error_does_not_stop_serving(hot, monkeypatch):
    def failed(*args):
        raise OSError('disk unavailable')
    monkeypatch.setattr(hot, '_write_host', failed)
    hot.note_host('x.example', None, 'inspect')
    assert hot.flush()
    assert hot.errors == 1
    assert hot.verdict('unknown.example') is None
    hot.log('still-writing')
    assert hot.flush()


def test_queue_saturation_never_waits_or_loses_memory_block(hot, monkeypatch):
    import queue
    def full(*args, **kwargs):
        raise queue.Full
    monkeypatch.setattr(hot.queue, 'put_nowait', full)
    hot.log('dropped')
    assert hot.ai_block('blocked.example', 'queued full')
    assert hot.verdict('blocked.example') == BLOCK
    assert hot.add_strike('blocked.example') == 1
    assert hot.dropped == 3


def test_image_and_decision_caches_bounded(hot):
    for i in range(8500):
        hot.verdict(f'h{i}.example')
    assert len(hot._cache) <= 8192
    for i in range(4100):
        hot.set_image_verdict(str(i), False, '')
    assert len(hot._images) == 4096


def test_latency_5minute_flush_and_bounded_samples(tmp_path):
    now = [0]
    metrics = Latency(tmp_path / 'latency.log', clock=lambda: now[0])
    for i in range(5000):
        metrics.add('request', .001)
    metrics.flush()
    assert not metrics.path.exists()
    now[0] = 300
    metrics.flush()
    entry = json.loads(metrics.path.read_text())
    assert entry['window_seconds'] == 300
    assert entry['hooks']['request'] == {'samples': 4096, 'p50_ms': 1, 'p95_ms': 1}
    assert metrics.samples == {}
    metrics.flush()
    assert len(metrics.path.read_text().splitlines()) == 1


def test_idle_worker_writes_metrics(tmp_path):
    metrics = Latency(tmp_path / 'latency.log', interval=.02)
    memory = ProxyStore(tmp_path / 'idle.sqlite', latency=metrics, poll=.01)
    try:
        metrics.add('response', .002)
        eventually(lambda: metrics.path.exists() and 'p95_ms' in metrics.path.read_text())
    finally:
        memory.close()


@pytest.mark.parametrize('ctype', ['text/css', 'application/javascript', 'font/woff2', 'application/pdf', 'application/octet-stream'])
def test_static_and_large_nonhtml_stream_without_review(store, ctype, monkeypatch):
    flt = make_filter(store)
    flow = flow_for('https://unknown.example/file', ctype, b'x' * 100)
    async def forbidden(*args):
        pytest.fail('streamed body inspected')
    monkeypatch.setattr(flt, '_review_page', forbidden)
    monkeypatch.setattr(flt, '_review_image', forbidden)
    flt.responseheaders(flow)
    assert flow.response.stream
    asyncio.run(flt.response(flow))


def test_large_plain_html_and_untrusted_images_always_buffer_for_review(store):
    flt = make_filter(store)
    plain = flow_for('https://example.com/file', 'text/plain')
    plain.response.headers['content-length'] = str(text.MAX_SCAN_BYTES + 1)
    flt.responseheaders(plain)
    assert not plain.response.stream  # above the scan cap the prefix is still reviewed
    plain = flow_for('https://example.com/file', 'text/plain')
    plain.response.headers['content-length'] = str(addon.LARGE_PLAIN_BYTES + 1)
    flt.responseheaders(plain)
    assert not plain.response.stream
    disguised = flow_for('https://unknown.example/photo.png', 'text/plain')
    disguised.response.headers['content-length'] = str(addon.LARGE_PLAIN_BYTES + 1)
    flt.responseheaders(disguised)
    assert not disguised.response.stream  # declared size never clears an image
    for ctype in ('text/html', 'image/png'):
        flow = flow_for('https://unknown.example/file', ctype)
        flt.responseheaders(flow)
        assert not flow.response.stream


def test_trusted_images_skip_buffering_but_text_only_stays_enforced(store):
    store.set_verdict('trusted.example', TRUSTED, 'admin')
    flt = make_filter(store)
    image = flow_for('https://trusted.example/p.png', 'image/png')
    flt.responseheaders(image)
    assert image.response.stream
    store.set_verdict('text.example', TEXT_ONLY, 'admin')
    image = flow_for('https://trusted.example/p.png', 'image/png', referer='https://text.example/')
    flt.responseheaders(image)
    assert not image.response.stream
    asyncio.run(flt.response(image))
    assert image.response.content == addon.pages.PLACEHOLDER_PNG


def test_text_patterns_compile_once_and_cap_input(store, monkeypatch):
    text._patterns.cache_clear()
    terms = {'xxx': 3, 'porn': 4}
    assert text.score('<p>xxx porn</p>', terms) == (7, ['xxx', 'porn'])
    def forbidden(*args, **kwargs):
        pytest.fail('pattern compiled again')
    monkeypatch.setattr(text.re, 'compile', forbidden)
    assert text.score('<p>xxx porn</p>', terms) == (7, ['xxx', 'porn'])
    assert text.score('x ' * text.MAX_SCAN_BYTES + ' xxx porn', terms) == (0, [])


def test_url_cache_ttl_body_change_and_byte_cap(store, monkeypatch):
    flt = make_filter(store)
    calls = []
    def assess(body, terms):
        calls.append(body)
        return 0, [], False
    monkeypatch.setattr(text, 'assess', assess)
    flow = flow_for('https://unknown.example/a', 'text/html', b'x' * (text.MAX_SCAN_BYTES + 100))
    asyncio.run(flt._review_page(flow))
    asyncio.run(flt._review_page(flow))
    assert len(calls) == 2 and len(calls[0].encode()) == text.MAX_SCAN_BYTES
    assert len(calls[1].encode()) == 100
    flow.response.content = b'different'
    asyncio.run(flt._review_page(flow))
    assert len(calls) == 3
    for key, (_, verdict) in list(flt._text_cache.items()):
        flt._text_cache[key] = (0, verdict)
    asyncio.run(flt._review_page(flow))
    assert len(calls) == 4


def test_url_cache_committee_generation_and_new_block(hot, monkeypatch):
    flt = make_filter(hot)
    calls = []
    monkeypatch.setattr(text, 'assess', lambda *a: (calls.append(1) or (0, [], False)))
    flow = flow_for('https://unknown.example/', 'text/html', b'hello')
    asyncio.run(flt._review_page(flow))
    asyncio.run(flt._review_page(flow))
    hot.generation += 1
    asyncio.run(flt._review_page(flow))
    assert len(calls) == 2
    admin = Store(hot.path)
    admin.set_verdict('unknown.example', BLOCK, 'admin')
    eventually(lambda: hot.verdict('unknown.example') == BLOCK)
    flow.response = None
    flt.request(flow)
    assert flow.response.status_code == 403
    admin._db.close()


def inline(data):
    return b'data:image/png;base64,' + base64.b64encode(data)


@pytest.mark.parametrize('bad', [False, True])
def test_inline_images_use_existing_reviewer_and_placeholder(store, bad):
    reviewer = FakeReviewer(bad=bad)
    flt = make_filter(store, reviewer)
    image = inline(png(40, 40))
    body = b'<html><img src="' + image + b'"></html>'
    flow = flow_for('https://unknown.example/', 'text/html', body)
    flt.request(flow)
    flt.responseheaders(flow)
    asyncio.run(flt.response(flow))
    assert reviewer.calls == 1
    assert flow.response.content == (body.replace(image, addon.INLINE_PLACEHOLDER) if bad else body)
    assert len(store._q('SELECT host FROM bad_image_strikes')) == int(bad)


def test_inline_bounded_count_small_images_and_cache(store):
    reviewer = FakeReviewer(bad=True)
    flt = make_filter(store, reviewer)
    image = inline(png(40, 40))
    body = b'<img src="' + inline(png(1, 1)) + b'">' + (b'<img src="' + image + b'">') * 6
    flow = flow_for('https://unknown.example/', 'text/html', body)
    asyncio.run(flt._review_inline(flow))
    # Every copy of a bad image is hidden; none passes for being "over the count".
    assert flow.response.content.count(addon.INLINE_PLACEHOLDER) == 6
    assert flow.response.content.count(image) == 0
    # Concurrent same-page repeats can coalesce only after a result is cached;
    # subsequent pages must reuse the content digest without another model call.
    assert reviewer.calls == 1
    before = reviewer.calls
    flow.response.content = b'<img src="' + image + b'">'
    asyncio.run(flt._review_inline(flow))
    assert reviewer.calls == before


def test_inline_prefix_boundary_not_decoded_and_textonly_skips_model(store):
    reviewer = FakeReviewer(bad=True)
    flt = make_filter(store, reviewer)
    image = inline(png(40, 40))
    body = b' ' * (text.MAX_SCAN_BYTES - 100) + b'<img src="' + image + b'">'
    flow = flow_for('https://unknown.example/', 'text/html', body)
    asyncio.run(flt._review_inline(flow))
    # An image past the text-scan prefix is still found and hidden.
    assert reviewer.calls == 1 and addon.INLINE_PLACEHOLDER in flow.response.content
    reviewer.calls = 0
    store.set_verdict('unknown.example', TEXT_ONLY, 'admin')
    flow.response.content = b'<img src="' + image + b'">'
    asyncio.run(flt._review_inline(flow))
    assert reviewer.calls == 0 and addon.INLINE_PLACEHOLDER in flow.response.content


def test_inline_timeout_has_one_page_budget_and_no_strike(store, monkeypatch):
    cfg = config.Config({'vision': {'inline_timeout_seconds': .02, 'max_parallel': 2}})
    flt = addon.AIFilter(cfg, store, FakeReviewer(delay=.1))
    flow = flow_for('https://unknown.example/', 'text/html', (b'<img src="' + inline(png(40, 40)) + b'">') * 4)
    budgets = []
    original_wait = asyncio.wait
    async def checked_wait(tasks, *, timeout):
        budgets.append(timeout)
        return await original_wait(tasks, timeout=timeout)
    monkeypatch.setattr(asyncio, 'wait', checked_wait)
    asyncio.run(flt._review_inline(flow))
    assert budgets == [.02]
    assert flow.response.content.count(addon.INLINE_PLACEHOLDER) == 4
    assert store._q('SELECT host FROM bad_image_strikes') == []
    assert store._q('SELECT digest FROM images') == []


def test_http2_and_logical_host_connection_reuse_options():
    from mitmproxy.options import Options
    options = Options()
    assert options.http2 and options.upstream_cert
    source = (Path(__file__).resolve().parents[1] / 'run.sh').read_text()
    assert '--set http2=true' in source
    assert '--set connection_strategy=lazy' in source
    # Round2 dialer tests prove real mitmproxy connection identity/reuse/fallback.


def test_inline_strikes_current_html_host_not_previous_page(store):
    flt = make_filter(store, FakeReviewer(bad=True))
    flt.responseheaders(flow_for('https://previous.example/', 'text/html'))
    flow = flow_for('https://current.example/', 'text/html', b'<img src="' + inline(png(40, 40)) + b'">',
                    referer='https://victim.example/')
    flt.request(flow)
    flt.responseheaders(flow)
    asyncio.run(flt.response(flow))
    assert store._q('SELECT host FROM bad_image_strikes') == [('current.example',)]


def test_production_startup_uses_background_store(tmp_path, monkeypatch):
    path = tmp_path / 'startup.sqlite'
    monkeypatch.setattr(config, 'db_path', lambda: path)
    flt = addon.AIFilter(config.load(), reviewer=FakeReviewer())
    assert not flt.store  # mitmproxy getattr()s it at load; only real use raises
    with pytest.raises(RuntimeError):
        flt.store.verdict('x')
    try:
        flt.running()
        assert isinstance(flt.store, ProxyStore)
        assert path.exists()
        flt.request(flow_for('https://unknown.example/'))
    finally:
        flt.done()
    assert not flt.store._thread.is_alive()


def test_committee_block_during_text_scoring_wins(store, monkeypatch):
    flt = make_filter(store)
    def changed(*args):
        store.set_verdict('unknown.example', BLOCK, 'admin')
        return 0, [], False
    monkeypatch.setattr(text, 'assess', changed)
    flow = flow_for('https://unknown.example/', 'text/html', b'hello')
    asyncio.run(flt._review_page(flow))
    assert flow.response.status_code == 403


def test_resolved_appeals_invalidate_memory_and_can_notify_again(hot):
    hot.add_appeal('www.example.com', 'https://www.example.com/', 'first')
    assert hot.appeals_for('www.example.com')
    assert hot.flush()
    admin = Store(hot.path)
    appeal = admin.appeals()[0][0]
    admin.resolve_appeal(appeal, False)
    eventually(lambda: not hot.appeals_for('www.example.com'))
    hot.add_appeal('www.example.com', 'https://www.example.com/', 'again')
    assert hot.appeals_for('www.example.com')
    assert hot.flush()
    assert len(admin.appeals()) == 1
    admin._db.close()


def test_cold_psl_load_is_on_worker_before_hooks(tmp_path, monkeypatch):
    from aifilter import suffixes
    suffixes._rules.cache_clear()
    suffixes.registrable.cache_clear()
    main = threading.get_ident()
    read_text = Path.read_text
    calls = []
    def checked(path, *a, **kw):
        if path.name == 'public_suffix_list.dat':
            calls.append(threading.get_ident())
            assert threading.get_ident() != main
        return read_text(path, *a, **kw)
    monkeypatch.setattr(Path, 'read_text', checked)
    memory = ProxyStore(tmp_path / 'cold.sqlite')
    try:
        assert memory.verdict('cold-host.example') is None
        assert len(calls) == 1
    finally:
        memory.close()


def test_url_cache_includes_decoding_charset(store):
    flt = make_filter(store)
    flt.terms = {'porn': 4, 'xxx': 3}
    flow = flow_for('https://unknown.example/', 'text/html; charset=utf-16-le', b'porn xxx ')
    asyncio.run(flt._review_page(flow))
    assert flow.response.status_code == 200
    flow.response.headers['content-type'] = 'text/html; charset=utf-8'
    asyncio.run(flt._review_page(flow))
    assert flow.response.status_code == 403


def test_appeal_enqueue_and_writer_failure_do_not_leave_phantom_pending(hot, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(hot, '_enqueue', lambda *a: False)
        hot.add_appeal('example.com', 'https://example.com/')
        assert not hot.appeals_for('example.com')
    def failed(*args):
        raise OSError('write failed')
    monkeypatch.setattr(Store, 'add_appeal', failed)
    hot.add_appeal('example.com', 'https://example.com/')
    assert hot.flush()
    assert not hot.appeals_for('example.com')


def test_meta_charset_preserves_hebrew_text_filtering(store):
    flt = make_filter(store)
    flt.terms = {'פורנו': 4, 'סרטי סקס': 3}
    body = '<meta charset="windows-1255"><p>פורנו סרטי סקס</p>'.encode('cp1255')
    flow = flow_for('https://unknown.example/', 'text/html', body)
    asyncio.run(flt._review_page(flow))
    assert flow.response.status_code == 403


@pytest.mark.parametrize('encoding', ['gzip', 'deflate', 'raw-deflate', 'br', 'zstd'])
def test_compressed_html_prefix_bound_and_no_whole_body_decode(store, monkeypatch, encoding):
    import gzip
    import zlib
    import brotli
    from mitmproxy.net.encoding import zstd
    from mitmproxy import http
    body = b'<p>hello world</p>' * 100_000
    compressed = {'gzip': gzip.compress, 'deflate': zlib.compress,
                  'raw-deflate': lambda b: zlib.compress(b)[2:-4],
                  'br': brotli.compress, 'zstd': zstd.compress}[encoding](body)
    flow = flow_for('https://unknown.example/', 'text/html')
    flow.response.raw_content = compressed
    flow.response.headers['content-encoding'] = 'deflate' if encoding == 'raw-deflate' else encoding
    def forbidden(*a, **kw):
        pytest.fail('whole body decoded on a bounded path')
    monkeypatch.setattr(http.Response, 'get_content', forbidden)
    flt = make_filter(store)
    prefix, complete = asyncio.run(flt._body_prefix(flow))
    assert prefix == body[:text.MAX_SCAN_BYTES]
    assert not complete
    asyncio.run(flt._review_page(flow))
    asyncio.run(flt._review_inline(flow))
    assert flow.response.raw_content == compressed


def test_small_compressed_inline_rewrites_only_blocked_spans(store):
    import gzip
    image = inline(png(40, 40))
    body = b'<html><img src="' + image + b'"></html>'
    flow = flow_for('https://unknown.example/', 'text/html')
    flow.response.raw_content = gzip.compress(body)
    flow.response.headers['content-encoding'] = 'gzip'
    flow.response.headers['etag'] = 'old-content'
    flt = make_filter(store, FakeReviewer(bad=True))
    asyncio.run(flt._review_inline(flow))
    assert 'content-encoding' not in flow.response.headers
    assert 'etag' not in flow.response.headers
    assert flow.response.content == body.replace(image, addon.INLINE_PLACEHOLDER)


def test_concatenated_gzip_members_are_scanned():
    import gzip
    from aifilter import bodies
    data, complete = bodies.prefix(gzip.compress(b'<p>') + gzip.compress(b'xxx porn</p>'), 'gzip', 100)
    assert data == b'<p>xxx porn</p>' and complete


def test_benchmark_uses_only_temporary_databases(capsys, monkeypatch):
    from scripts import bench
    calls = []
    async def measure(module, memory, count):
        assert 'aifilter-bench-' in str(memory.path if isinstance(memory, ProxyStore) else memory._db.execute('PRAGMA database_list').fetchone()[2])
        calls.append(count)
        return {'request': {'p50_ms': 1, 'p95_ms': 2}}
    monkeypatch.setattr(bench, 'measure', measure)
    monkeypatch.setattr(bench, 'source_at', lambda _ref, path: (bench.ROOT / path).read_text())
    assert bench.main(['--iterations', '10']) == 0
    result = json.loads(capsys.readouterr().out)
    assert calls == [10, 10]
    assert result['before'] == result['after']


def test_watchdog_scheduled_without_any_restart_or_cloud_action():
    source = (Path(__file__).resolve().parents[1] / 'run.sh').read_text()
    assert 'every 120 check_health &' in source
    assert '--proxy-port "$PORT" --pac-port "$PAC_PORT"' in source
    health = (Path(__file__).resolve().parents[1] / 'scripts/healthcheck.py').read_text()
    assert 'gcloud' not in health
    assert 'launchctl' not in health


def test_concatenated_zstd_frames_are_scanned():
    from mitmproxy.net.encoding import zstd
    from aifilter import bodies
    data, complete = bodies.prefix(zstd.compress(b'<p>') + zstd.compress(b'xxx porn</p>'), 'zstd', 100)
    assert data == b'<p>xxx porn</p>' and complete


def test_startup_strikes_preserve_configurable_window(tmp_path):
    path = tmp_path / 'strikes.sqlite'
    raw = Store(path)
    raw._q('INSERT INTO bad_image_strikes(host,ts) VALUES(?,?)', ('example.com', time.time() - 40 * 86400))
    raw._db.close()
    memory = ProxyStore(path)
    try:
        assert memory.add_strike('example.com', days=60) == 2
        assert memory.flush()
    finally:
        memory.close()


def test_gzip_padding_and_malformed_later_members_keep_reviewable_prefix():
    import gzip
    from aifilter import bodies
    original = b'<p>xxx porn</p>'
    assert bodies.prefix(gzip.compress(original) + b'\0' * 8, 'gzip', 100) == (original, True)
    assert bodies.prefix(gzip.compress(original) + b'broken', 'gzip', 100) == (original, False)


def test_failed_duplicate_appeal_keeps_existing_pending_snapshot(hot, monkeypatch):
    hot.add_appeal('example.com', 'https://example.com/')
    assert hot.flush()
    monkeypatch.setattr(hot, '_enqueue', lambda *a: False)
    hot.add_appeal('example.com', 'https://example.com/')
    assert hot.appeals_for('example.com')
    assert not hot._pending_appeals



@pytest.mark.parametrize('encoding', ['gzip', 'zstd'])
def test_empty_compression_members_and_encoded_input_have_work_bounds(monkeypatch, encoding):
    import gzip
    from mitmproxy.net.encoding import zstd
    from aifilter import bodies
    compressor = gzip.compress if encoding == 'gzip' else zstd.compress
    raw = compressor(b'') * 10_000 + compressor(b'xxx porn')
    factory = bodies.zlib.decompressobj if encoding == 'gzip' else zstd.ZstdDecompressor
    created = []
    def counted(*a, **kw):
        created.append(1)
        return factory(*a, **kw)
    if encoding == 'gzip':
        monkeypatch.setattr(bodies.zlib, 'decompressobj', counted)
    else:
        monkeypatch.setattr(zstd, 'ZstdDecompressor', counted)
    assert bodies.prefix(raw, encoding, 100) == (b'', False)
    assert len(created) == bodies.MAX_MEMBERS
    # The input cap bounds tail copies even when the raw HTTP body is very large.
    monkeypatch.setattr(bodies, 'MAX_COMPRESSED_BYTES', 10)
    data, complete = bodies.prefix(compressor(b'hello' * 100), encoding, 100)
    assert not complete and len(data) <= 100


def test_injected_worker_factory_never_loads_model_stack(monkeypatch):
    import builtins
    import socket
    import struct
    from aifilter.workers import _serve, _read
    original_import = builtins.__import__
    def guarded_import(name, *a, **kw):
        if name == 'aifilter.vision':
            raise AssertionError('unused heavy model stack imported')
        return original_import(name, *a, **kw)
    monkeypatch.setattr(builtins, '__import__', guarded_import)
    parent, child = socket.socketpair()
    parent.settimeout(3)
    thread = threading.Thread(target=_serve, args=(child, {}, FakeReviewer))
    thread.start()
    try:
        parent.sendall(struct.pack('!I', 2) + b'ok')
        size = struct.unpack('!I', _read(parent, 4))[0]
        assert json.loads(_read(parent, size)) == ['ok', []]
    finally:
        parent.close()
        thread.join(timeout=3)
    assert not thread.is_alive()



def test_spawn_fixture_has_no_heavy_imports():
    import ast
    from worker_fixtures import ProcessReviewer
    assert ProcessReviewer.__module__ == 'worker_fixtures'
    source = (Path(__file__).with_name('worker_fixtures.py')).read_text()
    imports = {node.name for node in ast.walk(ast.parse(source)) if isinstance(node, ast.alias)}
    assert imports <= {'os', 'time'}


def test_inline_over_budget_hidden_and_unscannable_pages_forbid_inline(store, monkeypatch):
    monkeypatch.setattr(addon, 'INLINE_REVIEW_MAX', 2)
    flt = make_filter(store, FakeReviewer(bad=False))
    images = [inline(png(40 + i, 40)) for i in range(4)]
    flow = flow_for('https://unknown.example/', 'text/html', b''.join(b'<img src="' + i + b'">' for i in images))
    asyncio.run(flt._review_inline(flow))
    body = flow.response.content
    assert images[0] in body and images[1] in body          # reviewed and clean
    assert images[2] not in body and images[3] not in body  # over budget: hidden, never passed
    big = flow_for('https://unknown.example/', 'text/html', b'x' * (addon.INLINE_SCAN_BYTES + 1))
    asyncio.run(flt._review_inline(big))
    assert 'img-src' in big.response.headers['content-security-policy']
    wide = flow_for('https://unknown.example/', 'text/html; charset=utf-16', '<img src="x">'.encode('utf-16'))
    asyncio.run(flt._review_inline(wide))
    assert 'img-src' in wide.response.headers['content-security-policy']


def test_dropped_site_block_is_retried_until_saved_and_strikes_bounded(tmp_path):
    memory = ProxyStore(tmp_path / 'retry.sqlite', recent_hosts=tmp_path / 'h.log', poll=.01)
    try:
        memory._enqueue = lambda *a, **k: False      # queue "full": the write is dropped
        assert memory.ai_block('dropped.example', 'bad text')
        assert memory.verdict('dropped.example') == BLOCK  # memory enforces at once
        deadline = time.monotonic() + 3
        while memory._ai and time.monotonic() < deadline:
            time.sleep(.02)
        assert not memory._ai                           # durable now
        assert Store(tmp_path / 'retry.sqlite').verdict('dropped.example') == BLOCK
        for i in range(4200):
            memory.add_strike(f'h{i}.example')
        assert len(memory._strikes) <= 4096
    finally:
        memory.close()
