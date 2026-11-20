from aifilter import safesearch


def test_search_engines_and_youtube_map_to_safe_endpoints():
    for h in ("www.google.com", "google.com", "www.google.co.il", "google.de", "www.google.com.br", "WWW.GOOGLE.COM."):
        assert safesearch.target(h) == "forcesafesearch.google.com"
    assert safesearch.target("www.bing.com") == "strict.bing.com"
    assert safesearch.target("duckduckgo.com") == "safe.duckduckgo.com"
    assert safesearch.target("www.youtube.com") == "restrict.youtube.com"


def test_other_names_untouched_and_youtube_can_be_exempt():
    for h in ("www.googleapis.com", "mail.google.com", "accounts.google.com", "google.com.evil.net",
              "notgoogle.com", "www.google.com.evil.co", "example.com", ""):
        assert safesearch.target(h) is None
    assert safesearch.target("www.youtube.com", youtube=False) is None
    assert safesearch.target("www.google.com", youtube=False) == "forcesafesearch.google.com"
