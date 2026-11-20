import asyncio
import io
import json
import sys
from pathlib import Path

import pytest
from mitmproxy import http
from mitmproxy.test import tflow
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from aifilter import sitejudge  # noqa: E402


def jpeg():
    buf = io.BytesIO()
    Image.new("RGB", (64, 48), "white").save(buf, "JPEG")
    return buf.getvalue()


def test_page_parts():
    html = ('<html><head><title> Shop  of shoes </title><meta property="og:image" content="/og.jpg"></head>'
            '<img src="https://cdn.example/a.jpg"><img src="http://plain.example/b.jpg"><img src="data:x">'
            '<img src="c.png"><img src="d.png"><img src="e.png">')
    title, urls = sitejudge.page_parts(html, "https://shop.example/x/")
    assert title == "Shop of shoes"
    assert urls == ["https://shop.example/og.jpg", "https://cdn.example/a.jpg", "https://shop.example/x/c.png",
                    "https://shop.example/x/d.png"]


def test_private_addresses_are_never_fetched():
    assert not sitejudge.public_host("localhost")
    assert not sitejudge.public_host("203.0.113.10")
    with pytest.raises(ValueError):
        sitejudge._get_image("https://127.0.0.1/x.jpg")


def test_reviewer_sends_text_and_pictures_and_maps_the_verdict():
    seen = []

    def ask(model, system, text, pic):
        seen.append((model, "Title: T" in text, pic is not None))
        return {"verdict": "block", "reason": "gambling"}

    r = sitejudge.SiteReviewer(model="m", get_image=lambda u: jpeg(), ask=ask)
    job = json.dumps({"host": "x.example", "url": "https://x.example/", "title": "T", "text": "hello",
                      "images": ["https://x.example/a.jpg"]}).encode()
    assert r.review(job) == (True, ["gambling"])
    assert seen == [("m", True, True)]
    r2 = sitejudge.SiteReviewer(model="m", get_image=lambda u: (_ for _ in ()).throw(OSError()),
                                ask=lambda *a: {"verdict": "allow", "reason": "shop"})
    assert r2.review(job) == (False, ["shop"])  # pictures that fail to load only mean less to look at
    with pytest.raises(ValueError):
        sitejudge.SiteReviewer(model="").review(job)


class _Pool:
    def __init__(self, status):
        self.status, self.jobs = status, []

    async def review(self, data, timeout):
        self.jobs.append(json.loads(data))
        return self.status, ["why"]


def _addon(tmp_path, status, monkeypatch):
    import addon

    class Store:
        def __init__(self):
            self.rows, self.blocked = [], []

        def log(self, *a):
            self.rows.append(a)

        def ai_block(self, host, reason):
            self.blocked.append(host)
            return True

    monkeypatch.setattr(addon, "SITE_JUDGED_FILE", tmp_path / "judged.json")
    a = addon.AIFilter.__new__(addon.AIFilter)
    a._store = Store()
    a.cfg = type("C", (), {"get": lambda self, sec, key, default=None:
                           {"ai_judge": True, "ai_model": "m"}.get(key, default) if sec == "sites" else default})()
    a._trusted = lambda flow: False
    a._site_pool = _Pool(status)
    return a


def _page(host="shop.example", dest="document"):
    f = tflow.tflow(resp=True)
    f.request.scheme, f.request.host, f.request.port, f.request.path = "https", host, 443, "/"
    if dest:
        f.request.headers["sec-fetch-dest"] = dest
    f.response = http.Response.make(200, b"<title>Hi</title><p>Shoes</p>", {"content-type": "text/html"})
    return f


async def _run(a, flow):
    a._schedule_site_judge(flow, flow.request.pretty_host, flow.response.content, "utf-8")
    await asyncio.gather(*list(getattr(a, "_site_tasks", ())))


@pytest.mark.parametrize("status,blocked", [("bad", True), ("ok", False)])
def test_addon_judges_a_new_site_once(tmp_path, monkeypatch, status, blocked):
    a = _addon(tmp_path, status, monkeypatch)
    asyncio.run(_run(a, _page()))
    assert a._site_pool.jobs[0]["title"] == "Hi" and "shoes" in a._site_pool.jobs[0]["text"].lower()
    assert a._store.blocked == (["shop.example"] if blocked else [])
    asyncio.run(_run(a, _page()))
    assert len(a._site_pool.jobs) == 1  # remembered: not asked again
    assert "shop.example" in json.loads((tmp_path / "judged.json").read_text())


def test_addon_keeps_no_verdict_when_the_model_fails(tmp_path, monkeypatch):
    a = _addon(tmp_path, "error", monkeypatch)
    asyncio.run(_run(a, _page()))
    asyncio.run(_run(a, _page()))
    assert len(a._site_pool.jobs) == 2 and a._store.blocked == []


def test_addon_skips_subresources_big_portals_and_when_off(tmp_path, monkeypatch):
    a = _addon(tmp_path, "bad", monkeypatch)
    asyncio.run(_run(a, _page(dest="iframe")))
    asyncio.run(_run(a, _page(host="www.google.com")))
    a.cfg = type("C", (), {"get": lambda self, sec, key, default=None: default})()
    asyncio.run(_run(a, _page(host="other.example")))
    assert a._site_pool.jobs == []
