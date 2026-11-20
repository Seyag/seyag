"""Emergency backup proxy (cloud VM). No TLS inspection and no CA on the server:
every connection is tunnelled, except hosts on the block lists, which are refused.
Lists: community lists fetched on boot + the Mac's own decisions (blocked.txt, synced via GCS)."""
from pathlib import Path
import ipaddress
import re

from mitmproxy import http, tls
try:
    from aifilter.safesearch import target as safe_target
except ModuleNotFoundError:
    # setup.sh delivers only this file via VM metadata. Keep that standalone
    # path dependency-free; parity with the shared table is regression-tested.
    def safe_target(name):
        name = name.lower().rstrip(".")
        if re.fullmatch(r"(?:(?:www|images|search|encrypted|news|video|videos)\.)?google\.(?:[a-z]{2,63}|(?:co|com)\.[a-z]{2})", name):
            return "forcesafesearch.google.com"
        if name in {"www.bing.com", "bing.com"}:
            return "strict.bing.com"
        if name in {"duckduckgo.com", "www.duckduckgo.com"}:
            return "safe.duckduckgo.com"
        if name in {"www.youtube.com", "m.youtube.com", "youtube.com", "youtubei.googleapis.com",
                    "youtube.googleapis.com", "www.youtube-nocookie.com"}:
            return "restrict.youtube.com"
        return None

LISTS = Path(__file__).with_name("lists")


def _load() -> set[str]:
    out: set[str] = set()
    for f in LISTS.glob("*.txt"):
        for line in f.read_text(errors="ignore").splitlines():
            line = line.strip().lower().lstrip("*.").rstrip(".")
            if line and not line.startswith("#"):
                out.add(line)
    return out


BLOCKED = _load()
ALLOW = {"apple.com", "icloud.com", "whatsapp.net", "whatsapp.com", "telegram.org", "anthropic.com", "claude.ai"}


def blocked(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]").rstrip("."))
        return True  # no domain policy can be applied to a literal destination
    except ValueError:
        pass
    parts = host.lower().rstrip(".").split(".")
    names = {".".join(parts[i:]) for i in range(len(parts) - 1)}
    if names & ALLOW:
        return False
    return bool(names & BLOCKED)


class Backup:
    def server_connect(self, data):
        host, port = data.server.address
        if blocked(str(host)):
            data.server.error = "blocked by home filter (backup)"
            return
        target = safe_target(str(host))
        if target:
            data.server.address = (target, port)
            if not data.server.sni:
                data.server.sni = str(host)

    def http_connect(self, flow: http.HTTPFlow):
        if blocked(flow.request.host):
            flow.response = http.Response.make(403, b"blocked by home filter (backup)")

    def tls_clienthello(self, data: tls.ClientHelloData):
        data.ignore_connection = True  # never decrypt on the backup

    def request(self, flow: http.HTTPFlow):
        if blocked(flow.request.pretty_host):
            flow.response = http.Response.make(403, "האתר חסום (סינון גיבוי)".encode(),
                                               {"content-type": "text/plain; charset=utf-8"})


addons = [Backup()]
