"""Search engines and YouTube forced to their safe endpoints.

The provider's own documented method: connect to the safe endpoint's address while
keeping the original name. Used by the home DNS filter (CNAME) and by the proxy
(upstream address), so it also holds for the iPhone and for tunnelled apps.
"""
import re

# Broader than the country table: also covers official non-ccTLDs such as .cat.
# Only search frontends, never accounts/mail/API hosts or lookalike suffixes.
_GOOGLE = re.compile(r"^(?:(?:www|images|search|encrypted|news|video|videos|ipv4|ipv6)\.)?google\.(?:[a-z]{2,63}|(?:co|com)\.[a-z]{2})$")
_FIXED = {
    "www.bing.com": "strict.bing.com", "bing.com": "strict.bing.com",
    "duckduckgo.com": "safe.duckduckgo.com", "www.duckduckgo.com": "safe.duckduckgo.com",
}
_YOUTUBE = {"www.youtube.com", "m.youtube.com", "youtube.com", "youtubei.googleapis.com",
            "youtube.googleapis.com", "www.youtube-nocookie.com"}


def google_search(name: str) -> bool:
    return bool(_GOOGLE.fullmatch((name or "").lower().rstrip(".")))


def target(name: str, youtube: bool = True) -> str | None:
    """The safe endpoint to resolve instead of `name`, or None."""
    name = (name or "").rstrip(".").lower()
    if google_search(name):
        return "forcesafesearch.google.com"
    if youtube and name in _YOUTUBE:
        return "restrict.youtube.com"
    return _FIXED.get(name)
