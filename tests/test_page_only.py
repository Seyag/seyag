import addon


def test_search_engines_are_page_only():
    for h in ("www.google.com", "google.com", "www.google.co.il", "www.bing.com", "he.wikipedia.org"):
        assert addon._page_only_host(h)


def test_other_hosts_still_get_site_verdicts():
    for h in ("example.com", "notgoogle.com", "google.com.evil.net"):
        assert not addon._page_only_host(h)


def test_mitmproxy_can_inspect_addon_before_running():
    # mitmproxy's command collection getattr()s every attribute at script load.
    a = addon.AIFilter.__new__(addon.AIFilter)
    a._store = None
    assert not a.store
    import pytest
    with pytest.raises(RuntimeError):
        a.store.verdict("x")
