import asyncio
from types import SimpleNamespace

import pytest

import addon
from aifilter.image_url import image_url_key


@pytest.mark.parametrize("url,key", [
    ("https://yt3.googleusercontent.com/a/abc=w120-h120-l90-rj", "yt3.googleusercontent.com/a/abc"),
    ("https://lh3.googleusercontent.com/a/abc=s20", "lh3.googleusercontent.com/a/abc"),
    ("https://yt3.ggpht.com/a/abc=s20", "yt3.ggpht.com/a/abc"),
    ("https://lh3.ggpht.com/a/abc=s20", "lh3.ggpht.com/a/abc"),
    ("https://i.ytimg.com/vi/mIlix_3dKsk/hqdefault.jpg", "ytimg:mIlix_3dKsk"),
    ("https://i9.ytimg.com/vi_webp/mIlix_3dKsk/mqdefault.webp", "ytimg:mIlix_3dKsk"),
    ("https://evil.example/vi/mIlix_3dKsk/hq.jpg", ""),
    ("https://i.ytimg.com/vi/invalid/hq.jpg", ""),
])
def test_url_identity(url, key):
    assert image_url_key(url) == key


class MemoryStore:
    def __init__(self):
        self.values = {}

    def image_verdict(self, key):
        return self.values.get(key)

    def set_image_verdict(self, key, bad, labels):
        self.values[key] = bad

    def log(self, *args):
        pass


def make_filter():
    f = addon.AIFilter.__new__(addon.AIFilter)
    f._store = MemoryStore()
    f.level = "modest"
    f.cfg = SimpleNamespace(get=lambda section, key, default=None: f.level if key == "level" else default)
    f._strike = lambda page: None
    return f


def flow(url):
    return SimpleNamespace(request=SimpleNamespace(pretty_url=url), response=SimpleNamespace(headers={}, status_code=200))


def test_url_key_only_blocks_and_policy_changes_invalidate_it():
    f = make_filter()
    calls = []
    verdicts = {b"one": "ok", b"two": "bad", b"three": "ok", b"four": "ok", b"five": "ok", b"six": "ok"}
    async def review(data):
        calls.append(data)
        return verdicts[data], []
    f._run_review = review
    async def run():
        # A good thumbnail never vouches for another picture of the same video (review of PR #4).
        assert not await f._image_bad(b"one", flow("https://i.ytimg.com/vi/mIlix_3dKsk/hqdefault.jpg"), "")
        assert await f._image_bad(b"two", flow("https://i.ytimg.com/vi/mIlix_3dKsk/hq2.jpg"), "")
        # One bad picture hides every other size or thumbnail of it without review.
        assert await f._image_bad(b"three", flow("https://i9.ytimg.com/vi_webp/mIlix_3dKsk/b.webp"), "")
        f.level = "strict"
        assert not await f._image_bad(b"four", flow("https://i.ytimg.com/vi/mIlix_3dKsk/c.jpg"), "")
        assert not await f._image_bad(b"five", flow("https://other.example/a=x"), "")
        assert not await f._image_bad(b"six", flow("https://other.example/a=y"), "")
    asyncio.run(run())
    assert calls == [b"one", b"two", b"four", b"five", b"six"]


@pytest.mark.parametrize("bad_first", [True, False])
def test_concurrent_bad_always_wins(bad_first):
    f = make_filter()
    ready = asyncio.Event()
    release = asyncio.Event()
    count = 0
    async def review(data):
        nonlocal count
        count += 1
        if count == 2:
            ready.set()
        await ready.wait()
        if (data == b"bad") != bad_first:
            await release.wait()
        else:
            release.set()
        return ("bad" if data == b"bad" else "ok"), []
    f._run_review = review
    async def run():
        a = flow("https://yt3.ggpht.com/abc=w100")
        b = flow("https://yt3.ggpht.com/abc=w200")
        await asyncio.gather(f._image_bad(b"bad", a, ""), f._image_bad(b"good", b, ""))
        assert await f._image_bad(b"good", b, "")
        assert await f._image_bad(b"third", b, "")
    asyncio.run(run())
    assert count == 2
