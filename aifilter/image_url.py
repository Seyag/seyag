"""Conservative identities for known Google image variants."""
import re
from urllib.parse import urlsplit


def image_url_key(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = parts.path
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https"):
        return ""
    if host in {"yt3.googleusercontent.com", "lh3.googleusercontent.com", "yt3.ggpht.com", "lh3.ggpht.com"}:
        parent, sep, last = path.rpartition("/")
        base = last.split("=", 1)[0]
        return host + parent + sep + base if sep and base else ""
    if host in {"i.ytimg.com", "i9.ytimg.com"}:
        match = re.fullmatch(r"/(?:vi|vi_webp)/([A-Za-z0-9_-]{11})/[^/]+", path)
        return "ytimg:" + match.group(1) if match else ""
    return ""
