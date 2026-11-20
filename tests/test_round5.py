"""Round 5 regressions. Local fixtures only; never the running filter."""
import asyncio
import gzip
import socket
import threading
from types import SimpleNamespace

import pytest

import addon
from aifilter import config
from mitmproxy import connection
from test_filter import FakeReviewer, flow_for, make_filter, store  # noqa: F401


def test_dns_resolves_while_content_workers_are_busy(monkeypatch):
    from aifilter import selfguard
    release = threading.Event()
    started = [threading.Event() for _ in range(4)]

    def occupy(index):
        started[index].set()
        release.wait(5)

    monkeypatch.setattr(socket, 'getaddrinfo', lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 443))])

    async def check():
        loop = asyncio.get_running_loop()
        jobs = [loop.run_in_executor(addon.CONTENT_EXECUTOR, occupy, i) for i in range(4)]
        try:
            assert await asyncio.to_thread(lambda: all(event.wait(2) for event in started))
            assert await asyncio.wait_for(selfguard.resolve('example.test', 443), .5) == ['192.0.2.1']
        finally:
            release.set()
            await asyncio.gather(*jobs)
    asyncio.run(check())


def test_compressed_image_decode_and_digest_off_loop(store, monkeypatch):
    from test_filter import png
    original_prefix, original_digest = addon.bodies.prefix, addon._image_digest
    threads = []

    def prefix(*args):
        threads.append(threading.current_thread().name)
        return original_prefix(*args)

    def digest(*args):
        threads.append(threading.current_thread().name)
        return original_digest(*args)

    monkeypatch.setattr(addon.bodies, 'prefix', prefix)
    monkeypatch.setattr(addon, '_image_digest', digest)
    data = png()
    flow = flow_for('https://unknown.example/image.png', 'image/png', gzip.compress(data))
    flow.response.headers['content-encoding'] = 'gzip'
    flt = make_filter(store, FakeReviewer(bad=False))
    asyncio.run(flt.response(flow))
    assert flow.response.content == data
    assert len(threads) == 2 and all(name.startswith('aifilter-content') for name in threads)


@pytest.mark.parametrize('on_busy,hidden', [('hide', True), ('allow', False)])
def test_oversized_decoded_image_uses_unreviewed_policy(store, monkeypatch, on_busy, hidden):
    monkeypatch.setattr(addon, 'IMAGE_DECODE_BYTES', 64)
    flt = make_filter(store, FakeReviewer(bad=False))
    monkeypatch.setitem(flt.cfg.raw['vision'], 'on_busy', on_busy)
    flow = flow_for('https://unknown.example/image.svg', 'image/svg+xml', gzip.compress(b'x' * 65))
    flow.response.headers['content-encoding'] = 'gzip'
    asyncio.run(flt.response(flow))
    assert (flow.response.content == addon.pages.PLACEHOLDER_PNG) is hidden
    assert any(kind == 'image-unreviewed' for _, kind, _, _ in store.events(10))


def test_startup_failure_blocks_every_http_path(monkeypatch):
    def failed(*a, **kw):
        raise OSError('policy unavailable')
    monkeypatch.setattr(addon, 'ProxyStore', failed)
    flt = addon.AIFilter(config.load(), reviewer=FakeReviewer())
    with pytest.raises(OSError):
        flt.running()
    for hook in ('request', 'http_connect', 'responseheaders', 'response'):
        flow = flow_for('https://example.com/')
        result = getattr(flt, hook)(flow)
        if result is not None:
            asyncio.run(result)
        assert flow.response.status_code == 503
        assert b'dir="rtl"' in flow.response.content
    server = connection.Server(address=('example.com', 443))
    asyncio.run(flt.server_connect(SimpleNamespace(server=server)))
    assert 'not initialized' in server.error


def test_initialized_policy_keeps_serving_when_refresh_fails(tmp_path, monkeypatch):
    import time
    from aifilter.hotstore import ProxyStore
    from aifilter.store import Store
    path = tmp_path / 'refresh.sqlite'
    admin = Store(path)
    admin.set_verdict('blocked.example', 'block', 'admin')
    hot = ProxyStore(path, poll=.01)
    try:
        flt = make_filter(hot)
        def failed(*args):
            raise OSError('transient DB read failure')
        monkeypatch.setattr(hot, '_refresh', failed)
        admin.set_verdict('another.example', 'block', 'admin')
        deadline = time.monotonic() + 2
        while not hot.errors and time.monotonic() < deadline:
            time.sleep(.01)
        assert hot.errors
        allowed = flow_for('https://example.com/')
        flt.request(allowed)
        assert allowed.response.status_code == 200
        blocked = flow_for('https://blocked.example/')
        flt.request(blocked)
        assert blocked.response.status_code == 403
    finally:
        hot.close()
        admin._db.close()


@pytest.mark.parametrize('host,allowed', [
    ('example.com', False), ('8.8.8.8', False), ('17.1.2.3', True),
    ('1.1.1.3', True), ('mmg.whatsapp.net', True), ('api.telegram.org', True),
    ('push.apple.com', True), ('bank-5.example', True),
])
def test_raw_tcp_only_for_approved_destinations(store, host, allowed):
    flt = make_filter(store)
    killed = []
    flow = SimpleNamespace(server_conn=connection.Server(address=(host, 443)), kill=lambda: killed.append(True))
    flt.tcp_start(flow)
    assert bool(killed) is not allowed


def test_connect_refuses_unapproved_public_ip_but_preserves_approved_nets(store):
    flt = make_filter(store)
    for host, expected in [('8.8.8.8', 403), ('[2001:4860:4860::8888]', 403), ('17.1.2.3', 200)]:
        flow = flow_for('https://' + host + '/')
        asyncio.run(flt.http_connect(flow))
        assert flow.response.status_code == expected


@pytest.mark.parametrize('host', ['google.cat', 'www.google.cat', 'images.google.co.il', 'images.google.com',
                                  'www.google.museum', 'google.co.ao', 'search.google.de'] )
def test_google_search_frontends_share_safe_and_page_only_rules(host):
    from aifilter import safesearch
    assert safesearch.target(host) == 'forcesafesearch.google.com'
    assert addon._page_only_host(host)


@pytest.mark.parametrize('host', ['8.8.8.8', '[2001:4860:4860::8888]'])
def test_backup_refuses_ip_literals_in_both_hooks(host):
    from backup.backup_addon import Backup
    backup = Backup()
    for hook in (backup.http_connect, backup.request):
        flow = flow_for('https://' + host + '/')
        hook(flow)
        assert flow.response.status_code == 403


def test_backup_safe_dial_keeps_tls_identity():
    from backup.backup_addon import Backup
    server = connection.Server(address=('images.google.cat', 443))
    Backup().server_connect(SimpleNamespace(server=server))
    assert server.address == ('forcesafesearch.google.com', 443)
    assert server.sni == 'images.google.cat'


def test_standalone_backup_has_same_safe_endpoints(monkeypatch):
    import builtins
    from aifilter import safesearch
    original = builtins.__import__
    def standalone(name, *args, **kwargs):
        if name == 'aifilter.safesearch':
            raise ModuleNotFoundError(name)
        return original(name, *args, **kwargs)
    monkeypatch.setattr(builtins, '__import__', standalone)
    namespace = {'__file__': 'backup/backup_addon.py'}
    exec(compile(open('backup/backup_addon.py').read(), 'backup/backup_addon.py', 'exec'), namespace)
    names = ['google.cat', 'images.google.com', 'google.co.il', 'mail.google.com', 'example.com']
    names += list(safesearch._FIXED) + list(safesearch._YOUTUBE)
    for name in names:
        assert namespace['safe_target'](name) == safesearch.target(name)


def test_dns_blocks_entire_cname_chain_before_cache_and_rechecks_cached_policy(store, monkeypatch):
    from aifilter.dns import Resolver
    from dnslib import DNSRecord, RR, CNAME, A, QTYPE
    req = DNSRecord.question('alias.example')
    resp = req.reply()
    resp.add_answer(RR('alias.example', QTYPE.CNAME, rdata=CNAME('middle.example')))
    resp.add_answer(RR('middle.example', QTYPE.CNAME, rdata=CNAME('blocked.example')))
    resp.add_answer(RR('blocked.example', QTYPE.A, rdata=A('8.8.8.8')))
    resolver = Resolver(store, [])
    monkeypatch.setattr(resolver, '_forward', lambda data: resp.pack())
    assert len(DNSRecord.parse(resolver.answer(req.pack())).rr) == 3
    assert resolver._cache
    store.set_verdict('blocked.example', 'block', 'admin')
    assert str(DNSRecord.parse(resolver.answer(req.pack())).rr[0].rdata) == '0.0.0.0'
    resolver._cache.clear()
    assert str(DNSRecord.parse(resolver.answer(req.pack())).rr[0].rdata) == '0.0.0.0'
    assert not resolver._cache


def test_dns_log_failure_cannot_bypass_block_and_internal_failure_still_falls_back(store, monkeypatch):
    from aifilter.dns import Resolver, _fallback
    from dnslib import DNSRecord
    store.set_verdict('blocked.example', 'block', 'admin')
    def fail(*a, **kw):
        raise OSError('logging failed')
    monkeypatch.setattr(store, 'log', fail)
    resolver = Resolver(store, [])
    monkeypatch.setattr(resolver, '_forward', lambda data: b'family-filter-answer')
    req = DNSRecord.question('blocked.example').pack()
    assert str(DNSRecord.parse(resolver.answer(req)).rr[0].rdata) == '0.0.0.0'
    assert _fallback(resolver, req) == b'family-filter-answer'


def test_dns_tcp_reads_fragmented_frame_and_sets_deadline():
    from aifilter.dns import _recv_exact
    import time
    class Socket:
        def __init__(self):
            self.parts = iter([b'a', b'b', b'c'])
            self.timeouts = []
        def settimeout(self, value):
            self.timeouts.append(value)
        def recv(self, count):
            return next(self.parts)
    sock = Socket()
    assert _recv_exact(sock, 3, time.monotonic() + 1) == b'abc'
    assert len(sock.timeouts) == 3 and all(0 < t <= 1 for t in sock.timeouts)
    with pytest.raises(TimeoutError):
        _recv_exact(sock, 1, time.monotonic() - 1)


def test_dns_workers_bounded_and_permit_returned(monkeypatch):
    import threading
    import socketserver
    from aifilter import dns
    sem = threading.BoundedSemaphore(1)
    monkeypatch.setattr(dns, 'DNS_WORKERS', sem)
    calls = []
    class Server(dns._BoundedThreads, socketserver.UDPServer):
        def __init__(self):
            pass
        def shutdown_request(self, request):
            calls.append('drop')
    server = Server()
    assert sem.acquire(False)
    server.process_request(None, None)
    assert calls == ['drop']
    monkeypatch.setattr(socketserver.ThreadingMixIn, 'process_request_thread', lambda *a: None)
    server.process_request_thread(None, None)
    assert sem.acquire(False)
    sem.release()


@pytest.mark.parametrize('entity', [b'd&#97;ta', b'&#100;ata', b'd&#x61;ta'])
def test_inline_entities_and_folded_base64_are_reviewed_and_original_markup_preserved(store, entity):
    import base64
    from test_filter import png
    image = png(10, 10)
    encoded = base64.b64encode(image)
    folded = b'\r\n '.join(encoded[i:i+40] for i in range(0, len(encoded), 40))
    url = entity + b':image/png;base64,' + folded
    body = b'<p title="&amp; unchanged">hello</p><img src="' + url + b'">'
    reviewer = FakeReviewer(bad=True)
    flow = flow_for('https://example.com/', 'text/html', body)
    asyncio.run(make_filter(store, reviewer)._review_inline(flow))
    assert reviewer.calls == 1
    assert flow.response.content == body.replace(url, addon.INLINE_PLACEHOLDER)
    assert 'content-security-policy' not in flow.response.headers


def test_small_real_picture_reviewed_but_one_pixel_icon_is_cheap(store):
    import base64
    import io
    from PIL import Image
    urls = []
    for size in (1, 40):
        buf = io.BytesIO()
        Image.new('RGB', (size, size), 'red').save(buf, format='PNG')
        assert len(buf.getvalue()) < 2048
        urls.append(b'data:image/png;base64,' + base64.b64encode(buf.getvalue()))
    body = b'<img src="' + urls[0] + b'"><img src="' + urls[1] + b'">'
    flow = flow_for('https://example.com/', 'text/html', body)
    reviewer = FakeReviewer(bad=True)
    asyncio.run(make_filter(store, reviewer)._review_inline(flow))
    assert reviewer.calls == 1
    assert urls[0] in flow.response.content and urls[1] not in flow.response.content


@pytest.mark.parametrize('status', [200, 404, 500])
@pytest.mark.parametrize('ctype', ['text/html', 'text/plain'])
def test_renderable_error_text_scanned_and_plaintext_tags_not_removed(store, ctype, status):
    flt = make_filter(store)
    flt.terms = {'porn': 4, 'xxx': 3}
    body = b'<script>porn xxx</script>' if ctype == 'text/plain' else b'<p>porn xxx</p>'
    flow = flow_for('https://unknown.example/', ctype, body)
    flow.response.status_code = status
    flt.responseheaders(flow)
    asyncio.run(flt.response(flow))
    assert flow.response.status_code == 403


@pytest.mark.parametrize('offset', [220_000, 262_150, 5 * 1024 * 1024])
def test_large_padded_text_scanned_with_bounded_samples(store, offset):
    from aifilter import text
    flt = make_filter(store)
    flt.terms = {'porn': 4, 'xxx': 3}
    body = b' ' * offset + b'porn xxx'
    flow = flow_for('https://unknown.example/', 'text/plain', body)
    flow.response.headers['content-length'] = str(len(body) + 9 * 1024 * 1024)
    flt.responseheaders(flow)
    assert not flow.response.stream
    samples = asyncio.run(flt._body_samples(flow))
    assert sum(map(len, samples)) <= text.MAX_SCAN_BYTES + text.SAMPLE_WINDOWS * text.SAMPLE_BYTES
    asyncio.run(flt.response(flow))
    assert flow.response.status_code == 403


def test_large_gzip_text_tail_scanned_without_whole_body_decode(store):
    import gzip
    flt = make_filter(store)
    flt.terms = {'porn': 4, 'xxx': 3}
    flow = flow_for('https://unknown.example/', 'text/plain')
    flow.response.raw_content = gzip.compress(b' ' * (9 * 1024 * 1024) + b'porn xxx')
    flow.response.headers['content-encoding'] = 'gzip'
    asyncio.run(flt.response(flow))
    assert flow.response.status_code == 403


def test_ip_context_cannot_poison_another_host_even_with_spoofed_referer(store):
    from test_filter import png
    flt = make_filter(store, FakeReviewer(bad=True))
    flt.responseheaders(flow_for('https://victim.example/', 'text/html'))
    for i in range(3):
        flow = flow_for('https://attacker.example/a.png', 'image/png', png() + bytes([i]),
                        referer='https://victim.example/')
        flt.request(flow)
        asyncio.run(flt.response(flow))
        assert flow.response.content == addon.pages.PLACEHOLDER_PNG
    assert not store._q('SELECT host FROM bad_image_strikes')
    assert store.verdict('victim.example') is None


def test_same_host_referer_still_allows_real_strikes(store):
    from test_filter import png
    flt = make_filter(store, FakeReviewer(bad=True))
    flt.responseheaders(flow_for('https://source.example/', 'text/html'))
    flow = flow_for('https://source.example/a.png', 'image/png', png(), referer='https://source.example/')
    asyncio.run(flt.response(flow))
    assert store._q('SELECT host FROM bad_image_strikes') == [('source.example',)]


@pytest.mark.parametrize('normal,blocked,rcode,healthy', [
    ('17.253.144.10', '0.0.0.0', 0, True),
    ('17.253.144.10', '0.0.0.0', 2, False),
    ('0.0.0.0', '0.0.0.0', 0, False),
    ('17.253.144.10', '8.8.8.8', 0, False),
    ('17.253.144.10', None, 0, False),
])
def test_dns_health_requires_normal_resolution_and_block_canary(monkeypatch, normal, blocked, rcode, healthy):
    from scripts import healthcheck
    from dnslib import DNSRecord, RR, A, QTYPE
    class Sock:
        def __enter__(self):
            return self
        def __exit__(self, *a):
            pass
        def settimeout(self, timeout):
            pass
        def connect(self, address):
            pass
        def send(self, data):
            self.query = DNSRecord.parse(data)
        def recv(self, size):
            reply = self.query.reply()
            is_canary = str(self.query.q.qname).rstrip('.') == healthcheck.BLOCK_CANARY
            reply.header.rcode = rcode if is_canary else 0
            address = blocked if is_canary else normal
            if address:
                reply.add_answer(RR(self.query.q.qname, QTYPE.A, rdata=A(address)))
            return reply.pack()
    monkeypatch.setattr(healthcheck.socket, 'socket', lambda *a: Sock())
    assert healthcheck.check_dns('127.0.0.1', 53, 1)[0] is healthy


@pytest.mark.parametrize('reply,accept', [('blocked\n403', False), ('/__ai-filter/appeal\n200', False),
                                          ('/__ai-filter/appeal\n503', False), ('/__ai-filter/appeal\n403', True)])
def test_heartbeat_requires_own_block_page_before_upload(reply, accept, tmp_path):
    import os
    import subprocess
    from pathlib import Path
    source = Path('backup/failover/heartbeat.sh').read_text()
    # Execute only the canary section with a stub curl. No Tailscale, DNS,
    # live files, cloud command or notification can execute in this harness.
    section = source[source.index('blocked=$(curl'):source.index('(cd "$ROOT"')]
    script = 'curl() { printf "%s" "$TEST_REPLY"; }\n' + section + '\nprintf CANARY_PASSED\n'
    result = subprocess.run(['/bin/bash', '-c', script], env={**os.environ, 'TEST_REPLY': reply},
                            capture_output=True, text=True, timeout=3)
    assert ('CANARY_PASSED' in result.stdout) is accept
    assert source.index('DNS resolution/block canary failed') < source.index('gcloud storage cp')


def test_user_content_is_inspected_without_removing_pinned_services(store):
    flt = make_filter(store)
    for name in ('raw.githubusercontent.com', 'avatars.githubusercontent.com', 'media.githubusercontent.com'):
        assert not flt._passthrough_name(name)
    for name in ('mmg.whatsapp.net', 'api.telegram.org', 'push.apple.com', 'bank-5.example', 'chatgpt.com'):
        assert flt._passthrough_name(name)


def test_every_google_country_search_hit_is_only_a_page_block(store):
    flt = make_filter(store)
    flt.terms = {'porn': 4, 'xxx': 3}
    for host in ('www.google.de', 'images.google.cat', 'google.co.ao'):
        flow = flow_for('https://' + host + '/search?q=terms', 'text/html', b'<p>porn xxx</p>')
        asyncio.run(flt.response(flow))
        assert flow.response.status_code == 403
        assert store.verdict(host) is None


def test_v6_listener_accepts_own_alias_but_not_strangers(monkeypatch):
    from aifilter import dns
    out = ("lo0: flags\n\tinet6 ::1 prefixlen 128 \n\tinet6 2001:db8:9::162 prefixlen 128 \n"
           "en1: flags\n\tinet6 fe80::1%en1 prefixlen 64 scopeid 0xf \n\tinet6 2001:db8:1::5 prefixlen 64 autoconf \n")
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: type("R", (), {"stdout": out})())
    monkeypatch.setattr(dns, "_v6_nets", (0, []))
    assert dns._client_ok("2001:db8:9::162")      # the Mac's own taken-over address
    assert dns._client_ok("2001:db8:1::77")       # a neighbour on the home /64
    assert not dns._client_ok("2001:db8:9::163")  # same far network, not ours
    assert not dns._client_ok("2001:db8:2::1")


def test_round7_safe_search_covers_ipv4_ipv6_frontends():
    from aifilter import safesearch
    assert safesearch.target("ipv4.google.com") == "forcesafesearch.google.com"
    assert safesearch.target("ipv6.google.co.il") == "forcesafesearch.google.com"
    assert safesearch.target("mail.google.com") is None


def test_round7_inline_image_forms_are_seen():
    import addon
    for prefix in (b"data:image/jpeg;charset=utf-8;base64,", b"data:application/octet-stream;base64,",
                   b"data:image/png;base64,"):
        assert addon.INLINE_IMAGE.search(b'<img src="' + prefix + b'AAAA">'), prefix
    assert not addon.INLINE_IMAGE.search(b'<a href="data:text/plain;base64,AAAA">')


def test_round7_only_own_tailnet_is_passthrough(policy_config_path):
    import tomllib
    from pathlib import Path
    hosts = tomllib.loads(policy_config_path.read_text())
    flat = str(hosts)
    assert "'ts.net'" not in flat and "filter.example.ts.net" in flat


def test_app_store_hosts_are_never_decrypted(policy_config_path):
    """Inspecting Apple's App Store fraud check stalled downloads on the iPhone (2026-11-12)."""
    import tomllib
    from pathlib import Path
    from addon import _suffix_match
    hosts = tomllib.loads(policy_config_path.read_text())["passthrough"]["hosts"]
    for name in ("afs.ampaeservices.com", "iosapps.itunes.apple.com", "is1-ssl.mzstatic.com",
                 "afs.ampservices.v.aaplimg.com", "appldnld.apple.com"):
        assert _suffix_match(name, hosts), name
    assert not _suffix_match("ampaeservices.com.evil.example", hosts)


def test_round7_own_probes_stay_out_of_the_report():
    from aifilter import dns
    from dnslib import DNSRecord

    class S:
        def __init__(self): self.rows = []
        def log(self, kind, host="", detail=""): self.rows.append((kind, host))
        def network_blocked(self, name): return name in ("bet365.com", "other-casino.example")
        def policy_blocked(self, name): return False
    s = S()
    r = dns.Resolver(s, ["127.0.0.1"])
    from aifilter import probe
    from dnslib import EDNS0, EDNSOption
    r.answer(probe.dns_query("bet365.com").pack(), "127.0.0.1")
    # Real lookups of the very same name, from this Mac too, are household visits.
    r.answer(DNSRecord.question("bet365.com").pack(), "127.0.0.1")
    r.answer(DNSRecord.question("bet365.com").pack(), "203.0.113.10")
    forged = DNSRecord.question("bet365.com")
    forged.add_ar(EDNS0(opts=[EDNSOption(probe.EDNS_CODE, b"not-the-token")]))
    r.answer(forged.pack(), "127.0.0.1")
    assert s.rows == [("probe-blocked", "bet365.com"), ("dns-blocked", "bet365.com"),
                      ("dns-blocked", "bet365.com"), ("dns-blocked", "bet365.com")]


def test_real_mac_browsing_to_a_test_site_stays_in_the_report():
    """Guard: only marked test traffic is excluded, never the site or the Mac as such."""
    import types
    import addon
    from aifilter import probe

    def flow(headers):
        conn = types.SimpleNamespace(peername=("127.0.0.1", 5), sockname=("127.0.0.1", 8118))
        return types.SimpleNamespace(client_conn=conn, request=types.SimpleNamespace(headers=headers))
    token = probe.token(create=True).decode()
    assert token
    assert addon.AIFilter._own_probe(flow({probe.HEADER: token}))
    assert not addon.AIFilter._own_probe(flow({}))
    assert not addon.AIFilter._own_probe(flow({probe.HEADER: "wrong"}))


def test_no_probe_token_means_nothing_is_a_probe(monkeypatch, tmp_path):
    from aifilter import probe
    from dnslib import DNSRecord
    monkeypatch.setattr(probe, "token_file", lambda: tmp_path / "missing.token")
    assert not probe.matches("")
    assert not probe.matches(b"anything")
    assert not probe.dns_marked(DNSRecord.question("bet365.com"))


def test_watchdog_and_selftest_mark_only_blocked_canaries(monkeypatch):
    from aifilter import probe
    from dnslib import DNSRecord
    from scripts import healthcheck, selftest
    sent = []

    class Sock:
        def __init__(self, *a): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def settimeout(self, t): pass
        def connect(self, addr): pass
        def send(self, data): sent.append(DNSRecord.parse(data))
        def recv(self, n):
            q = sent[-1]
            reply = q.reply()
            name = str(q.q.qname).rstrip(".")
            from dnslib import RR, A
            reply.add_answer(RR(q.q.qname, rdata=A("0.0.0.0" if name == healthcheck.BLOCK_CANARY else "17.253.144.10")))
            return reply.pack()
    monkeypatch.setattr(healthcheck.socket, "socket", Sock)
    assert healthcheck.check_dns("127.0.0.1", 53, 1.0) == (True, "DNS resolution and block canary succeeded")
    assert [probe.dns_marked(q) for q in sent] == [False, True]

    calls = []
    def run(cmd, **kw):
        calls.append((cmd, kw.get("input")))
        return __import__("types").SimpleNamespace(stdout=b"x\n403")
    monkeypatch.setattr(selftest.subprocess, "run", run)
    selftest.fetch(selftest.PAGE_BLOCKED[0], 8118, "ca")
    selftest.fetch(selftest.PAGE_OPEN[0], 8118, "ca")
    (blocked_cmd, blocked_in), (open_cmd, open_in) = calls
    assert "@-" in blocked_cmd and probe.token() in blocked_in
    assert probe.token().decode() not in " ".join(blocked_cmd)
    assert "@-" not in open_cmd and open_in is None


def test_round7_mac_lookups_have_their_own_dns_quota():
    from aifilter import dns
    assert dns._permits(("127.0.0.1", 5)) is dns.LOCAL_WORKERS
    assert dns._permits(("203.0.113.10", 5)) is dns.DNS_WORKERS


def test_round7_placeholder_is_never_cached():
    import addon
    from mitmproxy.test import tflow, tutils
    flow = tflow.tflow(resp=tutils.tresp(content=b"x"))
    flow.response.headers["cache-control"] = "public, max-age=31536000, immutable"
    flow.response.headers["etag"] = '"abc"'
    addon.AIFilter._hide_image(flow)
    assert flow.response.headers["cache-control"] == "no-store"
    assert "etag" not in flow.response.headers
    assert flow.response.headers["content-type"] == "image/png"


def test_round7_image_redirect_is_left_alone(store):
    """A 302 for a .jpg has no body; turning it into a placeholder cut the real picture off."""
    flt = make_filter(store)
    flow = flow_for('https://frame.example/_f/1/storyboard.jpg', '', b'')
    flow.response.status_code = 302
    flow.response.headers.pop('content-type', None)
    flow.response.headers['location'] = 'https://cdn.example/real.jpg'
    flt.responseheaders(flow)
    asyncio.run(flt.response(flow))
    assert flow.response.status_code == 302
    assert flow.response.headers['location'] == 'https://cdn.example/real.jpg'
    assert flow.response.content == b''



def test_tls_watch_unlocks_only_apple_and_reports_the_rest(tmp_path, monkeypatch, policy_config_path):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    import tls_watch
    from aifilter.store import Store
    monkeypatch.setattr(tls_watch, "static_passthrough",
                        lambda: config.load(policy_config_path).get("passthrough", "hosts", []))
    store = Store(tmp_path / "f.db")
    for host, n in [("afs.newapple.com", 1), ("ingest.apple-ip.example", 2), ("web.facebook.com", 9),
                    ("relay.anydesk.com", 1), ("x.cdn-apple.com", 5), ("evil.example", 4)]:
        for _ in range(n):
            store.record_tls_failure(host)
    answers = {("newapple.com", "NS"): ["a.ns.apple.com", "b.ns.apple.com"],
               ("apple-ip.example", "NS"): ["ns1.example-dns.net"],
               ("ingest.apple-ip.example", "A"): ["cname.aaplimg.com", "17.36.202.27"],
               ("facebook.com", "NS"): ["a.ns.facebook.com"], ("web.facebook.com", "A"): ["157.240.1.35"],
               ("evil.example", "NS"): ["ns.apple.com.evil.example"], ("evil.example", "A"): ["17.0.0.1", "8.8.8.8"]}
    dig = lambda name, rtype: answers.get((name, rtype), [])
    reports = []
    state = tmp_path / "state.json"
    out = tls_watch.run(store, state, dig=dig, report=lambda h, c: reports.append(h))
    assert sorted(out["auto"]) == ["ingest.apple-ip.example", "newapple.com"]   # whole domain only with Apple NS
    assert "x.cdn-apple.com" not in str(out)                                   # already in config.toml
    assert sorted(reports) == ["evil.example", "web.facebook.com"]            # never auto-passed; anydesk under 3
    assert {"newapple.com", "ingest.apple-ip.example"} <= store.passthrough_hosts()
    assert "web.facebook.com" not in store.passthrough_hosts()
    store.record_tls_failure("web.facebook.com")
    assert tls_watch.run(store, state, dig=dig, report=lambda h, c: reports.append(h)) == {"auto": [], "reported": []}


def test_connect_error_records_logical_host_via_write_queue(tmp_path):
    from aifilter.hotstore import ProxyStore
    from aifilter.store import Store
    path = tmp_path / 'connect.db'
    hot = ProxyStore(path)
    try:
        flt = make_filter(hot)
        server = SimpleNamespace(address=('2001:db8::1', 443), peername=None,
                                 _aifilter_host='cdn.example', error='connection timed out')
        flt.server_connect_error(SimpleNamespace(server=server))
        assert hot.flush()
        store = Store(path)
        try:
            host, count, _, detail = store.connect_failures()[0]
            assert (host, count) == ('cdn.example', 1)
            assert 'IPv6 2001:db8::1' in detail and 'connection timed out' in detail
        finally:
            store._db.close()
    finally:
        hot.close()


def test_connect_watch_reports_new_failures_once_without_policy_changes(tmp_path):
    from scripts import tls_watch
    from aifilter.store import Store
    store = Store(tmp_path / 'connect.db')
    state = tmp_path / 'state.json'
    reports = []
    def report(*args):
        reports.append(args)
    def no_dns(*args):
        raise AssertionError('connection failures must not trigger DNS or policy changes')
    for _ in range(3):
        store.record_connect_failure('cdn.example', 'IPv6 2001:db8::1: timed out')
    for _ in range(2):
        store.record_connect_failure('other.example', 'refused')
    out = tls_watch.run(store, state, dig=no_dns, report=report)
    assert out == {'auto': [], 'reported': ['cdn.example']}
    assert reports == [('cdn.example', 3, 'IPv6 2001:db8::1: timed out')]
    for _ in range(3):
        store.record_connect_failure('cdn.example', 'timed out again')
    store.record_connect_failure('other.example', 'refused again')
    assert tls_watch.run(store, state, dig=no_dns, report=report) == {'auto': [], 'reported': []}
    assert len(reports) == 1
    assert not store.passthrough_hosts()


def test_pinned_dial_tries_ipv4_before_ipv6():
    """A dead IPv6 edge of Apple's CDN stalled App Store downloads at home (2026-11-12)."""
    import socket
    from aifilter import selfguard
    pinned = selfguard.PinnedHost("iosapps.itunes.apple.com", 443,
                                  ["2a01:b740:a16:f000::137", "17.253.15.142", "2a01:b740:a41:632::2:1", "17.253.15.150"])
    fams = [i[0] for i in pinned.addrinfos]
    assert fams == [socket.AF_INET, socket.AF_INET, socket.AF_INET6, socket.AF_INET6]
    assert [i[4][0] for i in pinned.addrinfos][:2] == ["17.253.15.142", "17.253.15.150"]


def test_own_refusals_are_not_connect_failures():
    from types import SimpleNamespace
    calls = []
    flt = SimpleNamespace(_store=object(), store=SimpleNamespace(record_connect_failure=lambda *a: calls.append(a)))
    import addon
    hook = addon.AIFilter.server_connect_error.__wrapped__ if hasattr(addon.AIFilter.server_connect_error, "__wrapped__") else addon.AIFilter.server_connect_error
    server = SimpleNamespace(address=("blocked.example", 443), _aifilter_host="blocked.example", peername=None,
                             error="ai-filter: destination refused (local)")
    hook(flt, SimpleNamespace(server=server))
    assert calls == []
    server.error = "Connection refused"
    hook(flt, SimpleNamespace(server=server))
    assert calls and calls[0][0] == "blocked.example"


def test_proxy_gets_enough_open_files():
    """256 open files (launchd default) froze browsing on 2026-11-12: two per proxied connection."""
    import re
    from pathlib import Path
    root = Path(__file__).parent.parent
    m = re.search(r"ulimit -n (\d+)", (root / "run.sh").read_text())
    assert m and int(m.group(1)) >= 4096
    assert "NumberOfFiles" in (root / "deploy/com.example.ai-filter.plist").read_text()


def test_watch_reports_proxy_freezes_once(tmp_path, monkeypatch):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
    import tls_watch
    from aifilter import config
    from aifilter.store import Store
    monkeypatch.setattr(config, "db_path", lambda: tmp_path / "f.db")
    (tmp_path / "proxy.log").write_text("x\nOSError: [Errno 24] Too many open files\n" * 3)
    store, state, reports = Store(tmp_path / "f.db"), tmp_path / "s.json", []
    out = tls_watch.run(store, state, dig=lambda *a: [], report=lambda *a: reports.append(a))
    assert "proxy ran out of open files" in out["reported"] and reports[0][1] == 3
    assert tls_watch.run(store, state, dig=lambda *a: [], report=lambda *a: reports.append(a))["reported"] == []


@pytest.mark.parametrize('problem', ['slow', 'broken'])
def test_browse_probe_requires_consecutive_failures_and_reports_once_per_day(tmp_path, monkeypatch, problem):
    import datetime
    import json
    from scripts import browse_probe
    monkeypatch.setattr(browse_probe, 'PAGES', ('https://one.example/', 'https://two.example/'))
    reports = []
    faulty = True
    def fetch(url, download):
        bad = faulty and url == 'https://one.example/'
        return {'url': url, 'ok': not (bad and problem == 'broken'),
                'ttfb_s': .1, 'total_s': 5 if bad and problem == 'slow' else 1,
                'mbit_s': 30 if download else None}
    now = datetime.datetime(2026, 11, 13, 12)
    run = lambda: browse_probe.run(tmp_path, fetcher=fetch, report=lambda *a: reports.append(a), now=now)
    run()
    assert reports == []
    run()
    assert len(reports) == 1 and problem in reports[0][2]
    run()
    assert len(reports) == 1
    assert len((tmp_path / 'browse-probe.log').read_text().splitlines()) == 3
    assert len(json.loads((tmp_path / 'browse-probe.json').read_text())['reported']) == 1
    faulty = False
    run()
    faulty = True
    run()
    assert len(reports) == 1


def test_browse_probe_detects_slow_download(tmp_path, monkeypatch):
    from scripts import browse_probe
    monkeypatch.setattr(browse_probe, 'PAGES', ())
    reports = []
    def fetch(url, download):
        return {'url': url, 'ok': True, 'ttfb_s': .1, 'total_s': 5, 'mbit_s': 10}
    for _ in range(2):
        browse_probe.run(tmp_path, fetcher=fetch, report=lambda *a: reports.append(a))
    assert len(reports) == 1 and '10.0 Mbit/s' in reports[0][2]


def test_browse_fetch_uses_proxy_ca_range_and_deadline(monkeypatch):
    from scripts import browse_probe
    calls = []
    def curl(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout='206 0.5 2.0 5242880', stderr='')
    monkeypatch.setattr(browse_probe.subprocess, 'run', curl)
    result = browse_probe.fetch(browse_probe.DOWNLOAD_URL, True)
    cmd, kwargs = calls[0]
    assert result['ok'] and result['mbit_s'] > 20
    assert cmd[cmd.index('--proxy') + 1] == 'http://127.0.0.1:8118'
    assert cmd[cmd.index('--cacert') + 1] == str(browse_probe.CA)
    assert cmd[cmd.index('--range') + 1] == '0-5242879'
    assert kwargs['timeout'] == 10 and '--header' not in cmd


def test_dns_lock_cannot_be_removed_by_the_profile_tool():
    """(maintainer decision)."""
    from pathlib import Path
    src = (Path(__file__).parent.parent / "deploy/add_dns_layer.py").read_text()
    assert "--remove" not in src and '"ProhibitDisablement": True' in src
