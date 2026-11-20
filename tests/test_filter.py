import asyncio
import io
import sys
from ipaddress import ip_network
from pathlib import Path

import pytest
from mitmproxy import http
from mitmproxy.test import tflow
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import addon as addon_mod  # noqa: E402
import admin  # noqa: E402
from aifilter import config, pages  # noqa: E402
from aifilter.store import ALLOW, BLOCK, TRUSTED, Store, registrable  # noqa: E402


class FakeReviewer:
    def __init__(self, bad=False, delay=0.0):
        self.bad, self.delay, self.calls = bad, delay, 0

    def review(self, data):
        import time

        self.calls += 1
        time.sleep(self.delay)
        return self.bad, (["FEMALE_BREAST_EXPOSED:0.90"] if self.bad else [])


def png(w=200, h=200, color=(120, 80, 60)) -> bytes:
    buf = io.BytesIO()
    # noisy image so it is above the min_bytes threshold
    img = Image.effect_noise((w, h), 80).convert("RGB")
    img.save(buf, "PNG")
    return buf.getvalue()


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "t.db")


def make_filter(store, reviewer=None):
    cfg = config.load()
    cfg.raw.setdefault("x", {})["enabled"] = False  # tests start from text-only X; the live switch is the owner's
    return addon_mod.AIFilter(cfg, store, reviewer or FakeReviewer())


def flow_for(url, ctype=None, body=b"", referer=None, accept="text/html"):
    f = tflow.tflow(resp=True)
    f.request.url = url
    f.client_conn.sni = f.request.pretty_host  # as on a real TLS connection
    f.server_conn.address = (f.request.pretty_host, 443)
    f.request.headers["accept"] = accept
    if referer:
        f.request.headers["referer"] = referer
    f.response = http.Response.make(200, body, {"content-type": ctype} if ctype else {})
    return f


def test_registrable():
    assert registrable("www.ynet.co.il") == "ynet.co.il"
    assert registrable("a.b.example.com") == "example.com"


def test_blocked_site_gets_hebrew_block_page(store):
    store.set_verdict("bad.example", BLOCK, "admin")
    flt = make_filter(store)
    f = flow_for("https://www.bad.example/x")
    f.response = None
    flt.request(f)
    assert f.response.status_code == 403
    assert "האתר חסום" in f.response.get_text()
    assert 'dir="rtl"' in f.response.get_text()


def test_appeal_creates_pending_request(store):
    flt = make_filter(store)
    f = tflow.tflow()
    f.request.url = f"http://{pages.APPEAL_HOST}/appeal"
    f.request.method = "POST"
    f.request.text = "url=https%3A%2F%2Fwww.wiki.example%2Fpage&note=school"
    flt.request(f)
    assert f.response.status_code == 200
    (row,) = store.appeals()
    assert row[1] == "www.wiki.example" and row[3] == "school"  # the exact appealed host
    store.resolve_appeal(row[0], True, days=1)
    assert store.verdict("www.wiki.example") == ALLOW
    assert store.verdict("wiki.example") is None and store.verdict("cdn.wiki.example") is None


def test_bad_image_is_replaced_and_repeat_offender_blocked(store):
    rev = FakeReviewer(bad=True)
    flt = make_filter(store, rev)
    flt.responseheaders(flow_for("https://shady.example/page", "text/html"))
    for i in range(3):
        f = flow_for(f"https://shady.example/img{i}.png", "image/png", png(color=(i, i, i)) + bytes([i]),
                     referer="https://shady.example/page")
        asyncio.run(flt.response(f))
        assert f.response.content == pages.PLACEHOLDER_PNG
    assert store.verdict("shady.example") == BLOCK


def test_same_image_reviewed_once(store):
    rev = FakeReviewer(bad=False)
    flt = make_filter(store, rev)
    data = png()
    for _ in range(2):
        f = flow_for("https://cdn.example/a.png", "image/png", data)
        asyncio.run(flt.response(f))
        assert f.response.content == data
    assert rev.calls == 1


def test_mislabelled_image_still_reviewed(store):
    rev = FakeReviewer(bad=True)
    flt = make_filter(store, rev)
    f = flow_for("https://cdn.example/x/photo.jpg", "application/octet-stream", png(), accept="*/*")
    flt.responseheaders(f)
    assert not f.response.stream
    asyncio.run(flt.response(f))
    assert f.response.content == pages.PLACEHOLDER_PNG


def test_trusted_site_images_not_reviewed(store):
    store.set_verdict("trusted.example", TRUSTED, "admin")
    rev = FakeReviewer(bad=True)
    flt = make_filter(store, rev)
    f = flow_for("https://img.trusted.example/a.png", "image/png", png())
    asyncio.run(flt.response(f))
    assert rev.calls == 0


def test_small_images_are_reviewed(store):
    rev = FakeReviewer(bad=True)
    flt = make_filter(store, rev)
    f = flow_for("https://cdn.example/icon.png", "image/png", png(40, 40))
    asyncio.run(flt.response(f))
    assert rev.calls == 1
    assert f.response.content == pages.PLACEHOLDER_PNG


def test_slow_review_fails_closed(store, monkeypatch):
    rev = FakeReviewer(bad=False, delay=0.5)
    flt = make_filter(store, rev)
    flt.cfg.raw["vision"]["timeout_seconds"] = 0.05
    f = flow_for("https://cdn.example/slow.png", "image/png", png())
    asyncio.run(flt.response(f))
    assert f.response.content == pages.PLACEHOLDER_PNG


def test_adult_text_blocks_unknown_site(store):
    flt = make_filter(store)
    page = "<html><body>free porn xxx videos, nude, porn</body></html>".encode()
    f = flow_for("https://unknown-adult.example/", "text/html", page)
    asyncio.run(flt.response(f))
    assert f.response.status_code == 403
    assert store.verdict("unknown-adult.example") == BLOCK


def test_normal_page_passes(store):
    flt = make_filter(store)
    page = "<html><body>חדשות היום: מזג האוויר, ספורט ותרבות. dating back to 1990.</body></html>".encode()
    f = flow_for("https://news.example/", "text/html; charset=utf-8", page)
    asyncio.run(flt.response(f))
    assert f.response.status_code == 200
    assert store.verdict("news.example") is None


def test_ai_never_overrides_admin(store):
    store.set_verdict("medical.example", ALLOW, "admin")
    assert store.ai_block("www.medical.example", "x") is False
    assert store.verdict("medical.example") == ALLOW


def test_video_blocked_unless_trusted(store):
    flt = make_filter(store)
    f = flow_for("https://vid.example/a.mp4", "video/mp4")
    flt.responseheaders(f)
    assert f.response.status_code == 403
    store.set_verdict("torah.example", TRUSTED, "admin")
    f = flow_for("https://cdn.torah.example/a.mp4", "video/mp4")
    flt.responseheaders(f)
    assert f.response.status_code == 200 and f.response.stream


def test_passthrough_and_tls_failures(store):
    flt = make_filter(store)

    class Ctx:
        class client:
            sni = "api.bank.example"

    class Data:
        context = Ctx
        ignore_connection = False

    flt.tls_failed_client(Data)
    assert store.tls_failures()[0][0] == "api.bank.example"
    d = Data()
    flt.tls_clienthello(d)
    assert d.ignore_connection is False
    store.add_passthrough("bank.example")
    flt.tls_clienthello(d)
    assert d.ignore_connection is True
    Ctx.client.sni = "gateway.icloud.com"
    d2 = Data()
    flt.tls_clienthello(d2)
    assert d2.ignore_connection is True


def test_admin_page_renders_rtl(store):
    store.add_appeal("site.example", "https://site.example/", "צריך לשיעורי בית")
    body = admin.render(store).decode()
    assert 'dir="rtl"' in body and "site.example" in body and "צריך לשיעורי בית" in body


def test_real_model_loads_and_passes_plain_image():
    from aifilter.vision import Reviewer

    bad, labels = Reviewer().review(png())
    assert bad is False and labels == []


# Guards for the independent-review findings ------------------------------

def test_spoofed_referer_does_not_grant_trust(store):
    store.set_verdict("trusted.example", TRUSTED, "admin")
    rev = FakeReviewer(bad=True)
    flt = make_filter(store, rev)
    f = flow_for("https://cdn.shady.example/a.png", "image/png", png(), referer="https://trusted.example/")
    asyncio.run(flt.response(f))
    assert rev.calls == 1 and f.response.content == pages.PLACEHOLDER_PNG
    v = flow_for("https://cdn.shady.example/v.mp4", "video/mp4", referer="https://trusted.example/")
    flt.responseheaders(v)
    assert v.response.status_code == 403


def test_host_header_spoof_still_blocked(store):
    store.set_verdict("blocked.example", BLOCK, "admin")
    flt = make_filter(store)
    f = flow_for("https://allowed.example/")
    f.response = None
    f.server_conn.address = ("www.blocked.example", 443)
    flt.request(f)
    assert f.response.status_code == 403


def test_plain_text_and_untyped_pages_are_scored(store):
    flt = make_filter(store)
    for i, ctype in enumerate(["text/plain", None, "application/xhtml+xml"]):
        f = flow_for(f"https://adult{i}.example/", ctype, b"porn xxx porn nude")
        flt.responseheaders(f)
        assert not f.response.stream
        asyncio.run(flt.response(f))
        assert store.verdict(f"adult{i}.example") == BLOCK


def test_video_detected_by_extension(store):
    flt = make_filter(store)
    f = flow_for("https://cdn.example/clip.m3u8", "application/octet-stream")
    flt.responseheaders(f)
    assert f.response.status_code == 403


def test_partial_image_hidden(store):
    flt = make_filter(store)
    f = flow_for("https://cdn.example/a.jpg", "image/jpeg", png())
    f.response.status_code = 206
    asyncio.run(flt.response(f))
    assert f.response.content == pages.PLACEHOLDER_PNG


def test_svg_with_embedded_raster_hidden(store):
    flt = make_filter(store)
    f = flow_for("https://cdn.example/a.svg", "image/svg+xml", b'<svg><image href="data:image/jpeg;base64,AAAA"/></svg>')
    asyncio.run(flt.response(f))
    assert f.response.content == pages.PLACEHOLDER_PNG
    g = flow_for("https://cdn.example/logo.svg", "image/svg+xml", b"<svg><circle r='4'/></svg>")
    asyncio.run(flt.response(g))
    assert g.response.content.startswith(b"<svg")


def test_timeouts_never_exceed_parallel_limit(store):
    rev = FakeReviewer(delay=0.3)
    flt = make_filter(store, rev)
    flt.cfg.raw["vision"]["timeout_seconds"] = 0.01

    async def run():
        flows = [flow_for(f"https://cdn.example/{i}.png", "image/png", png() + bytes([i])) for i in range(4)]
        await asyncio.gather(*(flt.response(f) for f in flows))
        assert flt._sem._value <= 2  # permits still held by running threads
        await asyncio.sleep(1.0)
        assert flt._sem._value == 2

    asyncio.run(run())


def _admin_request(store, allowed, method, path, body=b"", origin=None, device="approved-client"):
    import email.message

    handler_cls = admin.make_handler(store, allowed, resolve=lambda ip: device)
    h = handler_cls.__new__(handler_cls)
    h.client_address = ("100.1.1.1", 1)
    h.path, h.command = path, method
    msg = email.message.Message()
    msg["host"] = "203.0.113.10:8090"
    msg["content-length"] = str(len(body))
    if origin:
        msg["origin"] = origin
    h.headers = msg
    h.rfile, h.wfile = io.BytesIO(body), io.BytesIO()
    h.request_version, h.requestline = "HTTP/1.1", f"{method} {path} HTTP/1.1"
    getattr(h, f"do_{method}")()
    return int(h.wfile.getvalue().split(b" ")[1])


def test_admin_only_for_allowed_devices(store):
    allowed = {"approved-client"}
    assert _admin_request(store, allowed, "GET", "/") == 200
    assert _admin_request(store, allowed, "GET", "/", device="unapproved-client") == 403
    body = b"host=x.example&verdict=allow&days=7"
    assert _admin_request(store, allowed, "POST", "/domain", body, origin="http://203.0.113.10:8090",
                          device="unapproved-client") == 403
    assert _admin_request(store, allowed, "POST", "/domain", body) == 403  # no Origin
    assert _admin_request(store, allowed, "POST", "/domain", body, origin="http://evil.example") == 403
    assert _admin_request(store, allowed, "POST", "/domain", body, origin="http://203.0.113.10:8090") == 303
    assert store.verdict("x.example") == ALLOW


def test_blocklist_covers_subdomains_and_admin_overrides(store):
    from aifilter import lists

    store.replace_blocklists(lists.parse(["# c", "*.adult.example", "bets.example", "bad line!"], "t"))
    assert store.verdict("www.adult.example") == BLOCK
    assert store.verdict("m.cdn.bets.example") == BLOCK
    assert store.verdict("example") is None and store.verdict("news.example") is None
    store.set_verdict("bets.example", ALLOW, "admin")
    assert store.verdict("m.cdn.bets.example") == ALLOW


def test_broken_list_never_replaces_good_one(store, monkeypatch):
    from aifilter import lists

    store.replace_blocklists([("adult.example", "t")])
    monkeypatch.setattr(lists, "fetch", lambda url: ["only.example"])
    with pytest.raises(RuntimeError):
        lists.update(store, {"t": "x"})
    assert store.verdict("adult.example") == BLOCK


# Home-network DNS filter -------------------------------------------------

def _dns(resolver, name, qtype="A"):
    from dnslib import DNSRecord

    return DNSRecord.parse(resolver.answer(DNSRecord.question(name, qtype).pack()))


def test_dns_blocks_listed_and_canaries(store, monkeypatch):
    from dnslib import RCODE

    from aifilter.dns import Resolver

    store.replace_blocklists([("adult.example", "t")])
    r = Resolver(store, ["127.0.0.1"])
    monkeypatch.setattr(r, "_forward", lambda data: pytest.fail("must not forward"))
    resp = _dns(r, "www.adult.example")
    assert str(resp.rr[0].rdata) == "0.0.0.0"
    assert _dns(r, "www.adult.example", "AAAA").rr == []
    assert _dns(r, "mask.icloud.com").header.rcode == RCODE.NXDOMAIN
    assert _dns(r, "use-application-dns.net").header.rcode == RCODE.NXDOMAIN


def test_dns_forces_safe_search_and_forwards_rest(store, monkeypatch):
    from dnslib import QTYPE, RR, A, DNSRecord

    from aifilter.dns import Resolver

    asked = []

    def fake_forward(data):
        q = DNSRecord.parse(data)
        asked.append(str(q.q.qname))
        reply = q.reply()
        reply.add_answer(RR(q.q.qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=300))
        return reply.pack()

    r = Resolver(store, ["127.0.0.1"])
    monkeypatch.setattr(r, "_forward", fake_forward)
    resp = _dns(r, "www.youtube.com")
    assert str(resp.rr[0].rdata) == "restrict.youtube.com."
    assert asked == ["restrict.youtube.com."]
    _dns(r, "news.example")
    _dns(r, "news.example")  # second answer from cache
    assert asked.count("news.example.") == 1


def test_dns_ignores_public_clients():
    from aifilter.dns import _client_ok

    assert _client_ok(str(ip_network("192.168.0.0/16")[5])) and _client_ok(str(ip_network("100.64.0.0/10")[5]))
    assert not _client_ok("192.0.2.10")


def test_dns_never_blocks_protected_or_ai_decisions(store, monkeypatch):
    from dnslib import QTYPE, RR, A, DNSRecord

    from aifilter.dns import Resolver

    def fake_forward(data):
        q = DNSRecord.parse(data)
        reply = q.reply()
        reply.add_answer(RR(q.q.qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=300))
        return reply.pack()

    store.replace_blocklists([("github.com", "t"), ("adult.example", "t")])
    store.ai_block("blog.example", "text")
    r = Resolver(store, ["127.0.0.1"])
    monkeypatch.setattr(r, "_forward", fake_forward)
    assert str(_dns(r, "api.github.com").rr[0].rdata) == "1.2.3.4"   # protected beats a list
    assert str(_dns(r, "blog.example").rr[0].rdata) == "1.2.3.4"     # AI verdict stays off the network
    assert str(_dns(r, "adult.example").rr[0].rdata) == "0.0.0.0"
    store.set_verdict("blog.example", BLOCK, "admin")
    assert str(_dns(r, "blog.example").rr[0].rdata) == "0.0.0.0"     # admin block applies house-wide


def test_committee_approval_expires_and_list_returns(store, monkeypatch):
    import time as _t

    store.replace_blocklists([("forum.example", "t")])
    now = _t.time()
    clock = [now]
    monkeypatch.setattr(_t, "time", lambda: clock[0])
    store.set_verdict("forum.example", ALLOW, "admin", "committee: homework", days=1)
    assert store.verdict("forum.example") == ALLOW and not store.network_blocked("forum.example")
    # Tightened: an approval covers subdomains only when the parent scope is explicit.
    assert store.verdict("www.forum.example") == BLOCK
    store.set_override("forum.example", ALLOW, "admin", "committee: homework", 1, domain=True)
    assert store.verdict("www.forum.example") == ALLOW
    clock[0] = now + 2 * 86400
    assert store.verdict("forum.example") == BLOCK and store.verdict("www.forum.example") == BLOCK  # lapsed


def test_weekly_report_counts_and_committee(store):
    import report

    store.log("image-blocked", "a.example", "x")
    store.log("dns-blocked", "bad.example", "")
    store.log("appeal", "docs.example", "u")
    store.set_verdict("docs.example", ALLOW, "admin", "committee: school project", days=3)
    text = report.build(store)
    assert "תמונות שהוסתרו: 1" in text and "בקשות לפתיחת אתר: 1" in text
    assert "docs.example: נפתח (school project" in text and "bad.example" in text


def test_social_policy_blocks_devices_not_house(store):
    import policy

    policy.apply(store)
    assert store.verdict("www.instagram.com") == BLOCK
    assert store.verdict("mobile.x.com") == "textonly"
    assert not store.network_blocked("instagram.com")  # the Mac and the agents keep working
    assert store.ai_block("x.com", "t") is False       # AI cannot touch a policy decision
    store.set_verdict("reddit.com", ALLOW, "admin", "committee: one thread", days=1)
    policy.apply(store)
    assert store.verdict("reddit.com") == ALLOW        # re-applying keeps committee approvals


def test_text_only_site_hides_every_image_and_video(store):
    import policy

    policy.apply(store)
    rev = FakeReviewer(bad=False)
    flt = make_filter(store, rev)
    page = flow_for("https://x.com/home", "text/html", b"<html>hello world</html>")
    page.response = None
    flt.request(page)
    assert page.response is None                        # the page itself opens
    for url, ref in (("https://pbs.twimg.com/media/a.jpg", None),          # CDN, no referer (app)
                     ("https://cdn.other.example/b.png", "https://x.com/home")):
        f = flow_for(url, "image/jpeg", png(), referer=ref)
        asyncio.run(flt.response(f))
        assert f.response.content == pages.PLACEHOLDER_PNG
    assert rev.calls == 0                               # hidden without asking the AI
    v = flow_for("https://video.twimg.com/a.mp4", "video/mp4")
    flt.responseheaders(v)
    assert v.response.status_code == 403


def test_x_switch_on_checks_pictures_and_gates_video(store):
    import policy

    policy.apply(store)
    cfg = config.load()
    cfg.raw["x"]["enabled"] = True

    class XGate:
        def known(self, url):
            return None  # unknown: the addon must hold the flow and check asynchronously

        async def allowed(self, url):
            assert "/ext_tw_video/123/" in url
            return True, "checked", "123"

    rev = FakeReviewer(bad=False)
    flt = addon_mod.AIFilter(cfg, store, rev, x_gate=XGate())
    image = flow_for("https://pbs.twimg.com/media/a.jpg", "image/jpeg", png(),
                     referer="https://x.com/home")
    asyncio.run(flt.response(image))
    assert image.response.content != pages.PLACEHOLDER_PNG
    assert rev.calls == 1

    video = flow_for("https://video.twimg.com/ext_tw_video/123/a.mp4", "video/mp4")

    async def run():
        flt.responseheaders(video)  # must return at once (never blocks the event loop)
        assert video.intercepted
        for _ in range(5):
            await asyncio.sleep(0)
        assert not video.intercepted

    asyncio.run(run())
    assert video.response.status_code == 200
    assert any(kind == "x-approved" and host == "123" for _at, kind, host, _detail in store.events(10))


def test_x_switch_on_blocks_rejected_video_and_live_host(store):
    cfg = config.load()
    cfg.raw["x"]["enabled"] = True

    class XGate:
        def known(self, _url):
            return False, "FACE_FEMALE", "456"

    flt = addon_mod.AIFilter(cfg, store, FakeReviewer(), x_gate=XGate())
    video = flow_for("https://video.twimg.com/amplify_video/456/a.mp4", "video/mp4")
    flt.responseheaders(video)
    assert video.response.status_code == 403
    assert b"FACE_FEMALE" in video.response.content

    live = flow_for("https://prod-fastly.video.pscp.tv/live.m3u8", "video/mp4")
    live.response = None
    flt.request(live)
    assert live.response.status_code == 403


def test_x_switch_controls_live_hosts_and_disables_conditional_media(store):
    cfg = config.load()
    cfg.raw.setdefault("x", {})["enabled"] = False
    flt = addon_mod.AIFilter(cfg, store, FakeReviewer())
    live = flow_for("https://prod-fastly.video.pscp.tv/live.m3u8", "video/mp4")
    live.response = None
    flt.request(live)
    assert live.response is None

    cfg.raw["x"]["enabled"] = True
    image = flow_for("https://pbs.twimg.com/media/a.jpg", "image/jpeg", png())
    image.response = None
    image.request.headers["if-none-match"] = '"old"'
    image.request.headers["if-modified-since"] = "yesterday"
    image.request.headers["if-range"] = '"old"'
    flt.request(image)
    assert not any(name in image.request.headers for name in
                   ("if-none-match", "if-modified-since", "if-range"))
    image.response = http.Response.make(304, b"", {})
    flt.responseheaders(image)
    assert image.response.status_code == 403


def test_dns_social_policy_house_wide_except_mac(store, monkeypatch):
    from dnslib import QTYPE, RR, A, DNSRecord

    import policy
    from aifilter.dns import Resolver

    def fake_forward(data):
        q = DNSRecord.parse(data)
        reply = q.reply()
        reply.add_answer(RR(q.q.qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=300))
        return reply.pack()

    policy.apply(store)
    r = Resolver(store, ["127.0.0.1"], policy_exempt=["192.0.2.10"])
    monkeypatch.setattr(r, "_forward", fake_forward)
    ask = lambda name, client: str(DNSRecord.parse(r.answer(DNSRecord.question(name).pack(), client)).rr[0].rdata)
    assert ask("www.instagram.com", "192.0.2.11") == "0.0.0.0"
    assert ask("x.com", "192.0.2.11") == "0.0.0.0"          # text-only needs the proxy; DNS can only block
    assert ask("x.com", "192.0.2.10") == "1.2.3.4"         # the Mac keeps working


def test_text_score_ignores_code_and_placeholders():
    # Regression 2026-11-10: a Cloud Console page blocked all of google.com on "xxx" in JS/placeholders.
    from aifilter import text
    terms = {"xxx": 3, "porn": 4}
    page = "<script>var mask='xxx-xxx-xxxx'; porn porn porn</script><p>Phone: xxx-xxx-xxxx</p>"
    assert text.score(page, terms) == (0, [])
    assert text.score("<p>free xxx porn</p>", terms)[1] == ["xxx", "porn"]


def test_importing_addon_never_opens_a_database(tmp_path):
    # Audit 2026-11-10: importing addon.py opened the live data/filter.db during test collection.
    import subprocess

    db = tmp_path / "never.db"
    code = "import addon; assert all(a._store is None for a in addon.addons)"
    env = {**__import__("os").environ, "AIFILTER_DB": str(db)}
    subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env, check=True)
    assert not db.exists()


# Audit 2026-11-10 #1: the proxy must never reach the Mac's own admin/PAC/DNS ports.

class _Server:
    def __init__(self, host, port):
        self.address, self.error = (host, port), None


class _ConnData:
    def __init__(self, host, port):
        self.server = _Server(host, port)


def _connect(flt, host, port):
    d = _ConnData(host, port)
    asyncio.run(flt.server_connect(d))
    return d.server.error


def test_proxy_refuses_loopback_and_own_service_ports(store, monkeypatch):
    from aifilter import selfguard

    mac_ips = {"192.0.2.30", "198.51.100.30"}
    monkeypatch.setattr(selfguard, "is_local_address", lambda ip: ip in mac_ips)
    names = {"filter.example.ts.net": ["198.51.100.30"],
             "rebind.example": ["93.184.216.34", "127.0.0.1"], "news.example": ["93.184.216.34"]}

    real = selfguard.resolve

    async def fake_resolve(host, port, timeout=3.0):  # names from the table, literals/localhost for real (no network)
        return names[host] if host in names else await real(host, port, timeout)

    monkeypatch.setattr(selfguard, "resolve", fake_resolve)
    flt = make_filter(store)
    for host, port in [("127.0.0.1", 8090), ("127.0.0.1", 5432), ("::1", 22), ("localhost", 8090),
                       ("0.0.0.0", 8119), ("::ffff:127.0.0.1", 80), ("198.51.100.30", 8090),
                       ("192.0.2.30", 8119), ("192.0.2.30", 53), ("198.51.100.30", 8118),
                       ("filter.example.ts.net", 8090), ("rebind.example", 443)]:
        assert _connect(flt, host, port), (host, port)
    # Tailnet services on other ports keep working (Telegram bridge panel, Serve previews).
    assert _connect(flt, "filter.example.ts.net", 10000) is None
    assert _connect(flt, "filter.example.ts.net", 443) is None
    assert _connect(flt, "news.example", 443) is None
    assert _connect(flt, "8.8.8.8", 443) is None


def test_proxy_refuses_connect_to_admin_with_403(store, monkeypatch):
    from aifilter import selfguard

    monkeypatch.setattr(selfguard, "is_local_address", lambda ip: ip == "203.0.113.10")
    flt = make_filter(store)
    f = tflow.tflow()
    f.request.method, f.request.host, f.request.port = "CONNECT", "203.0.113.10", 8090
    asyncio.run(flt.http_connect(f))
    assert f.response.status_code == 403


def test_local_address_detection_is_real():
    from aifilter import selfguard

    assert selfguard.is_local_address("127.0.0.1")
    assert not selfguard.is_local_address("203.0.113.9")  # TEST-NET-3, never assigned here


# Audit 2026-11-10 #2: passthrough never overrides a block, and must match the CONNECT target.

def _hello(flt, sni, dest=None):
    class Client:
        pass

    class Server:
        address = (dest, 443) if dest else None

    class Ctx:
        client, server = Client(), Server()

    Ctx.client.sni = sni

    class Data:
        context = Ctx
        ignore_connection = False

    d = Data()
    flt.tls_clienthello(d)
    return d.ignore_connection


def test_passthrough_honors_block_and_connect_target(store):
    flt = make_filter(store)
    store.add_passthrough("pinned.example")
    assert _hello(flt, "api.pinned.example", "api.pinned.example") is True
    store.set_verdict("bad.pinned.example", BLOCK, "admin")
    assert _hello(flt, "bad.pinned.example", "bad.pinned.example") is False   # own block wins
    store.replace_blocklists([("adult.pinned.example", "t"), ("whatsapp.net", "t")])
    assert _hello(flt, "adult.pinned.example") is False                       # list beats admin exception
    assert _hello(flt, "g.whatsapp.net", "g.whatsapp.net") is True             # curated static list kept
    store.set_verdict("whatsapp.net", BLOCK, "admin")
    assert _hello(flt, "g.whatsapp.net") is False                              # own block beats static list
    assert _hello(flt, "gateway.icloud.com", "blocked-site.example") is False  # SNI/CONNECT mismatch
    assert _hello(flt, "gateway.icloud.com", "17.1.2.3") is True               # IP target keeps working
    assert _hello(flt, "gateway.icloud.com", "5.6.7.8") is False               # Apple SNI to a non-Apple IP is inspected
    assert _hello(flt, "family.cloudflare-dns.com", "1.1.1.3") is True         # locked DoH resolver tunnels
    assert _hello(flt, "filter.example.ts.net",
                  "filter.example.ts.net") is True           # bridge panel stays tunnelled


# Audit 2026-11-10 #3 and #8: errors are not strikes, strikes expire, escalation is exact-host,
# and waiting for the reviewer is bounded.

class BrokenReviewer:
    def review(self, data):
        raise RuntimeError("model crashed")


def _image(flt, i, page):
    flt.responseheaders(flow_for(f"https://{page}/", "text/html"))
    f = flow_for(f"https://{page}/{i}.png", "image/png", png() + i.to_bytes(2, "big"),
                 referer=f"https://{page}/")
    asyncio.run(flt.response(f))
    return f


def test_timeouts_and_errors_never_count_as_bad_images(store):
    flt = make_filter(store, FakeReviewer(delay=0.3))
    flt.cfg.raw["vision"]["timeout_seconds"] = 0.01
    flt.cfg.raw["vision"]["queue_wait_seconds"] = 5
    for i in range(4):
        f = _image(flt, i, "www.google.com")
        assert f.response.content == pages.PLACEHOLDER_PNG  # hidden this time
    flt = make_filter(store, BrokenReviewer())
    for i in range(4, 8):
        assert _image(flt, i, "images.example").response.content == pages.PLACEHOLDER_PNG
    assert store.verdict("google.com") is None and store.verdict("www.google.com") is None
    assert store.verdict("images.example") is None
    assert store._q("SELECT count(*) FROM images")[0][0] == 0  # failures are never cached
    assert flt._sem._value == 2


def test_strikes_expire_and_block_only_the_exact_host(store, monkeypatch):
    import time as _t

    flt = make_filter(store, FakeReviewer(bad=True))
    real, offset = _t.time, [0.0]
    monkeypatch.setattr(_t, "time", lambda: real() + offset[0])
    for i in range(2):
        _image(flt, i, "a.shady.example")
    offset[0] = 8 * 86400  # a week later the old strikes are gone
    _image(flt, 2, "a.shady.example")
    assert store.verdict("a.shady.example") is None
    for i in range(3, 5):
        _image(flt, i, "a.shady.example")
    assert store.verdict("a.shady.example") == BLOCK
    assert store.verdict("b.shady.example") is None and store.verdict("shady.example") is None


def test_infrastructure_hosts_never_auto_blocked_by_images(store):
    flt = make_filter(store, FakeReviewer(bad=True))
    for i in range(5):
        assert _image(flt, i, "www.google.com").response.content == pages.PLACEHOLDER_PNG
    assert store.verdict("www.google.com") is None


def test_busy_reviewer_never_hangs_and_permits_come_back(store):
    rev = FakeReviewer(delay=0.6)
    flt = make_filter(store, rev)
    flt.cfg.raw["vision"].update(max_parallel=1, timeout_seconds=5, queue_wait_seconds=0.05)
    flt._sem = asyncio.Semaphore(1)
    busy_data = png()

    async def run():
        import time as _t

        slow = flow_for("https://cdn.example/slow.png", "image/png", png() + b"1")
        busy = flow_for("https://cdn.example/busy.png", "image/png", busy_data)
        t0 = _t.monotonic()
        first = asyncio.ensure_future(flt.response(slow))
        await asyncio.sleep(0.05)
        await flt.response(busy)
        assert _t.monotonic() - t0 < 0.4                       # did not wait for the stuck review
        assert busy.response.content != busy_data          # on_busy = "hide" (config.toml): replaced, never shown unreviewed
        await first
        assert flt._sem._value == 1

    asyncio.run(run())
    assert store.image_verdict(__import__("hashlib").sha1(busy_data).hexdigest()) is None
    assert any(k == "image-unreviewed" for _t, k, _h, _d in store.events(10))


# Audit 2026-11-10 #6 and #7: approvals are finite and expiry restores the standing decision.

def test_expired_approval_restores_policy_and_ai_decisions(store, monkeypatch):
    import time as _t

    import policy

    policy.apply(store)
    store.ai_block("blog.example", "text")
    now = _t.time()
    clock = [now]
    monkeypatch.setattr(_t, "time", lambda: clock[0])
    store.set_override("reddit.com", ALLOW, "admin", "committee: one thread", 1, domain=True)  # explicit parent scope
    store.set_verdict("blog.example", ALLOW, "admin", "committee: homework", days=1)
    assert store.verdict("www.reddit.com") == ALLOW and not store.policy_blocked("reddit.com")
    assert store.verdict("blog.example") == ALLOW
    assert policy.apply(store) == 0                     # re-applying changes nothing, keeps the approval
    assert store.verdict("reddit.com") == ALLOW
    clock[0] = now + 2 * 86400
    assert store.verdict("www.reddit.com") == "textonly" and store.policy_blocked("reddit.com")
    assert store.verdict("blog.example") == BLOCK      # the AI block was never erased


def test_approvals_need_finite_durations(store):
    import math

    for bad in (0, -1, 31, math.inf, math.nan):
        with pytest.raises(ValueError):
            store.set_verdict("x.example", ALLOW, "admin", "t", days=bad)
    store.add_appeal("y.example", "https://y.example/")
    (row,) = store.appeals()
    with pytest.raises(ValueError):
        store.resolve_appeal(row[0], True)              # no permanent approval by appeal
    store.resolve_appeal(row[0], True, days=3)
    assert store.overrides()[0][0] == "y.example"


def test_committee_cli_rejects_zero_and_huge_days(store, monkeypatch, tmp_path):
    import committee

    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "c.db"))
    for days in ("0", "0.5", "31", "inf", "nan"):
        with pytest.raises(SystemExit):
            committee.main(["approve", "site.example", "--days", days, "--reason", "r"])
    committee.main(["approve", "site.example", "--days", "3", "--reason", "school"])
    assert Store(tmp_path / "c.db").verdict("site.example") == ALLOW


def test_admin_approval_requires_days(store):
    allowed = {"approved-client"}
    origin = "http://203.0.113.10:8090"
    for body in (b"host=a.example&verdict=allow", b"host=a.example&verdict=trusted&days=0",
                 b"host=a.example&verdict=allow&days=31"):
        assert _admin_request(store, allowed, "POST", "/domain", body, origin=origin) == 400
    assert _admin_request(store, allowed, "POST", "/domain", b"host=a.example&verdict=block", origin=origin) == 303
    store.add_appeal("b.example", "https://b.example/")
    (row,) = store.appeals()
    assert _admin_request(store, allowed, "POST", "/appeal", f"id={row[0]}&approve=1".encode(), origin=origin) == 400
    assert _admin_request(store, allowed, "POST", "/appeal", f"id={row[0]}&approve=1&days=7".encode(),
                          origin=origin) == 303
    assert store.verdict("b.example") == ALLOW and store.overrides()


def test_admin_textonly_over_block_is_temporary_and_policy_cannot_be_weakened(store):
    allowed = {"approved-client"}
    origin = "http://203.0.113.10:8090"
    store.set_verdict("shop.example", BLOCK, "admin", "denied")
    store._q("DELETE FROM domain_denials")
    assert _admin_request(store, allowed, "POST", "/domain", b"host=shop.example&verdict=textonly",
                          origin=origin) == 400  # a loosening is never standing
    assert store.verdict("shop.example") == BLOCK
    assert _admin_request(store, allowed, "POST", "/domain", b"host=shop.example&verdict=textonly&days=2",
                          origin=origin) == 303
    assert store.verdict("shop.example") == "textonly" and store.overrides()
    store.set_verdict("instagram.com", BLOCK, "policy", "feed")
    assert _admin_request(store, allowed, "POST", "/domain", b"host=instagram.com&verdict=textonly",
                          origin=origin) == 400
    assert store.verdict("instagram.com") == BLOCK


def test_legacy_expiring_rows_move_to_overrides(tmp_path):
    import sqlite3
    import time as _t

    db = tmp_path / "legacy.db"
    Store(db)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO domains(host,verdict,source,reason,updated,expires) VALUES"
                "('reddit.com','allow','admin','committee: x',?,?)", (_t.time(), _t.time() + 86400))
    con.commit()
    con.close()
    s = Store(db)
    assert s.standing("reddit.com") is None and s.verdict("reddit.com") == ALLOW
    assert s.overrides()[0][0] == "reddit.com"


# Audit 2026-11-10 #9: code is stripped before truncation, statefully.

def test_script_cut_by_the_size_limit_is_never_scored():
    from aifilter import text

    terms = {"xxx": 3, "porn": 4}
    filler = "var a = 1;\n" * 30_000  # the closing tag lies far beyond the old 200,000-char cut
    page = f"<html><p>Weather today</p><script>{filler} var m='porn xxx porn';{filler}</script><p>end</p></html>"
    assert text.score(page, terms) == (0, [])
    cut = f"<p>hello</p><script>{filler} 'porn xxx'"  # never closed at all
    assert text.score(cut, terms) == (0, [])
    assert text.score("<style>.xxx{}</style><noscript>porn porn</noscript><p>ok</p>", terms) == (0, [])
    assert text.score("<p>free xxx &amp; porn</p>", terms)[1] == ["xxx", "porn"]
    split = "<p>" + "a" * 65_531 + " porn xxx</p>"            # "po|rn" across the parser's read boundary
    assert split.index("porn") == 65_535
    assert text.score(split, terms)[1] == ["xxx", "porn"]
    assert text.visible_text("<p>a</p><p>b</p>").split() == ["a", "b"]


def test_text_block_needs_two_terms_and_stays_on_exact_host(store):
    flt = make_filter(store)
    f = flow_for("https://forum.big.example/t/1", "text/html", b"<p>porn porn porn porn</p>")
    asyncio.run(flt.response(f))
    assert f.response.status_code == 200 and store.verdict("forum.big.example") is None
    g = flow_for("https://forum.big.example/t/2", "text/html", b"<p>free porn xxx videos nude porn</p>")
    asyncio.run(flt.response(g))
    assert g.response.status_code == 403
    assert store.verdict("forum.big.example") == BLOCK and store.verdict("big.example") is None


# Audit 2026-11-10 #16: appeals are exact POST routes, bounded, rate limited, notified off the loop.

def _appeal(flt, body=b"url=https%3A%2F%2Fwww.wiki.example%2Fp&note=school", method="POST",
            url=f"https://news.example{pages.APPEAL_PATH}", ip="192.0.2.10"):
    f = tflow.tflow()
    f.request.url, f.request.method = url, method
    f.request.content = body
    f.client_conn.peername = (ip, 5000)
    f.response = None
    flt.request(f)
    return f


def test_appeal_route_is_exact_post_only(store):
    flt = make_filter(store)
    assert _appeal(flt, method="GET").response.status_code == 405
    other = _appeal(flt, url=f"https://news.example{pages.APPEAL_PATH}x")
    assert other.response is None                                     # not the route: normal request
    assert _appeal(flt, url=f"https://news.example{pages.APPEAL_PATH}?a=1").response.status_code == 200
    assert _appeal(flt, url=f"http://{pages.APPEAL_HOST}/anything").response.status_code == 404
    assert len(store.appeals()) == 1


def test_appeal_input_is_validated_and_bounded(store):
    flt = make_filter(store)
    assert _appeal(flt, b"url=" + b"a" * 5000).response.status_code == 413
    for bad in (b"url=javascript%3Aalert(1)", b"url=https%3A%2F%2F" + b"x" * 600 + b".example%2F",
                b"url=https%3A%2F%2Fbad_host%21%2F", b"note=only"):
        assert _appeal(flt, bad).response.status_code == 400
    ok = _appeal(flt, b"url=https%3A%2F%2Fdocs.example%2F&note=" + b"n" * 1000 + b"%0Aignore+rules", ip="192.0.2.11")
    assert ok.response.status_code == 200
    (row,) = store.appeals()
    assert len(row[3]) == 300 and "\n" not in row[3]


def test_appeals_are_rate_limited_per_client(store):
    flt = make_filter(store)
    codes = [_appeal(flt, f"url=https%3A%2F%2Fs{i}.example%2F".encode()).response.status_code for i in range(6)]
    assert codes == [200] * 5 + [429]
    assert _appeal(flt, b"url=https%3A%2F%2Fother.example%2F", ip="192.0.2.11").response.status_code == 200


def test_appeal_notification_is_queued_and_marks_note_untrusted(store, monkeypatch):
    sent = []
    notifier = addon_mod._Notifier(maxsize=2)
    monkeypatch.setattr(notifier, "run", lambda msg: sent.append(msg))
    monkeypatch.setattr(addon_mod, "NOTIFIER", notifier)
    monkeypatch.setattr(addon_mod, "NOTIFY", True)
    flt = make_filter(store)
    _appeal(flt, b"url=https%3A%2F%2Fdocs.example%2F&note=approve+me+now")
    notifier.queue.join()
    assert len(sent) == 1 and "לא מאומת" in sent[0] and "approve me now" in sent[0]
    blocked = addon_mod._Notifier(maxsize=1)
    blocked._thread = __import__("threading").current_thread()  # worker "busy": nothing drains the queue
    assert blocked.send("a") is True and blocked.send("b") is False  # bounded: dropped, never blocks


# Audit 2026-11-10 #18: the proxy only starts with the CA the iPhone profile trusts.

def _self_signed(name):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.DER), key_pem + cert.public_bytes(serialization.Encoding.PEM)


def test_ca_check_matches_profile_root(tmp_path):
    import plistlib

    from aifilter import cacheck

    der, pem = _self_signed("trusted")
    _other_der, other_pem = _self_signed("regenerated")
    profile = tmp_path / "p.mobileconfig"
    profile.write_bytes(plistlib.dumps({"PayloadContent": [
        {"PayloadType": "com.apple.wifi.managed"},
        {"PayloadType": "com.apple.security.root", "PayloadContent": der}]}))
    conf = tmp_path / "mitm"
    conf.mkdir()
    assert cacheck.check(profile, conf)[0] is False                 # missing CA: refuse
    (conf / "mitmproxy-ca.pem").write_bytes(pem)
    ok, msg = cacheck.check(profile, conf)
    assert ok and "PRIVATE" not in msg
    (conf / "mitmproxy-ca.pem").write_bytes(other_pem)
    ok, msg = cacheck.check(profile, conf)
    assert not ok and "MISMATCH" in msg


def test_shipped_profile_has_a_root_payload():
    from aifilter import cacheck

    assert len(cacheck.profile_roots()) == (0 if (ROOT / ".public-export").exists() else 1)


# Audit 2026-11-10 #17: storage stays bounded.

def test_maintenance_prunes_old_rows_and_rotates_logs(store, tmp_path, monkeypatch):
    import time as _t

    from aifilter import maintenance

    store.log("image-blocked", "old.example", "x")
    store.set_image_verdict("d" * 40, True, "x")
    store.add_strike("old.example")
    real = _t.time
    monkeypatch.setattr(_t, "time", lambda: real() + 61 * 86400)
    store.log("image-blocked", "new.example", "y")
    counts = maintenance.prune(store)
    assert counts == {"events": 1, "images": 1, "strikes": 1, "overrides": 0}
    assert [r[2] for r in store.events()] == ["new.example"]
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "pac.log").write_bytes(b"x" * 2000)
    (logs / "dns.log").write_bytes(b"y" * 10)
    assert maintenance.rotate_logs(logs, max_bytes=1000) == ["pac.log"]
    assert (logs / "pac.log").stat().st_size == 0 and (logs / "pac.log.1").stat().st_size == 2000
    assert (logs / "dns.log").stat().st_size == 10


# Audit 2026-11-10 #13, #14, #18: run.sh supervises children, refreshes lists on a schedule
# and checks the CA before the proxy starts.

def _run_sh_functions() -> str:
    src = (ROOT / "run.sh").read_text()
    start = src.index("log() {")
    return src[start:src.index("PORT=$(cfg")]


def test_run_sh_restarts_a_dead_child(tmp_path):
    import subprocess
    import time as _t

    (tmp_path / "data").mkdir()
    script = tmp_path / "t.sh"
    script.write_text("PY=true\n" + _run_sh_functions() +
                      "supervise svc 1 sh -c 'echo run >> data/count; exit 3' &\nS=$!\n"
                      "sleep 2.6\nkill $S\nwait $S\n")
    subprocess.run(["bash", str(script)], cwd=tmp_path, check=True, timeout=20,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    runs = (tmp_path / "data" / "count").read_text().split()
    assert len(runs) >= 2                                   # it came back after dying
    assert "svc exited (rc=3); restarting" in (tmp_path / "data" / "supervisor.log").read_text()
    _t.sleep(1.2)
    assert len((tmp_path / "data" / "count").read_text().split()) == len(runs)  # stopped with its supervisor


def test_run_sh_order_and_schedules():
    src = (ROOT / "run.sh").read_text()
    assert src.index("supervise pac") < src.index("aifilter.cacheck") < src.index("mitmdump")
    assert "--set confdir=" in src
    assert "return 1" in src[src.index("aifilter.cacheck"):src.index("mitmdump")]
    assert "supervise proxy 10 start_proxy" in src
    for needed in ("supervise admin", "supervise dns", "every 21600 refresh_lists", "aifilter.maintenance",
                   "policy.py"):
        assert needed in src



def test_blocked_video_cuts_the_stream_at_once(store):
    """A replaced response would still pull the whole video (a live stream forever) before the 403."""
    flt = make_filter(store)
    f = flow_for("https://vid.example/live.m3u8", "application/vnd.apple.mpegurl")
    flt.responseheaders(f)
    assert f.response.status_code == 403 and f.error and not f.killable


def test_websocket_history_stays_short(store):
    from mitmproxy.test import tflow
    from mitmproxy import websocket
    import addon as addon_mod
    flt = make_filter(store)
    f = tflow.twebsocketflow(messages=False)
    for i in range(addon_mod.WS_KEEP + 30):
        f.websocket.messages.append(websocket.WebSocketMessage(1, True, f"m{i}".encode()))
        flt.websocket_message(f)
    assert len(f.websocket.messages) == addon_mod.WS_KEEP
    assert f.websocket.messages[-1].content == f"m{addon_mod.WS_KEEP + 29}".encode()


def test_youtube_stream_formats_count_as_video():
    import addon
    f = tflow.tflow(resp=True)
    f.request.host = "rr3---sn-ivuoxu-ua8s.googlevideo.com"
    f.request.path = "/videoplayback?expire=1&ei=x"
    f.response.headers["content-type"] = "application/octet-stream"
    assert addon._looks_like_video(f)
    g = tflow.tflow(resp=True)
    g.request.host = "example.com"
    g.request.path = "/stream"
    g.response.headers["content-type"] = "application/vnd.yt-ump"
    assert addon._looks_like_video(g)
    h = tflow.tflow(resp=True)
    h.request.host = "googlevideo.com.evil.example"
    h.request.path = "/videoplayback"
    h.response.headers["content-type"] = "text/html"
    assert not addon._looks_like_video(h)


def test_audit_media_hosts_are_inspected_and_telegram_public_feed_blocked(store):
    flt = make_filter(store)

    class Ctx:
        class client:
            sni = "cdn4.telesco.pe"
            peername = ("203.0.113.10", 12345)
        server = None

    class Data:
        context = Ctx
        ignore_connection = False

    hello = Data()
    flt.tls_clienthello(hello)
    assert hello.ignore_connection is False
    Ctx.client.sni = "images.openai.com"
    hello = Data()
    flt.tls_clienthello(hello)
    assert hello.ignore_connection is False

    feed = flow_for("https://t.me/s/anychannel")
    feed.response = None
    flt.request(feed)
    assert feed.response.status_code == 403


def test_openai_image_response_goes_through_review(store):
    reviewer = FakeReviewer()
    flt = make_filter(store, reviewer)
    image = flow_for("https://images.openai.com/generated.jpg", "image/jpeg", png(), accept="image/*")
    flt.responseheaders(image)
    asyncio.run(flt.response(image))
    assert reviewer.calls == 1
