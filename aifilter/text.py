"""Text review of pages from unknown sites.

A weighted term list (Hebrew and English) scores visible page text. This is the
first layer; a local language model can be added behind the same interface.
"""

import re
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path

TERMS_FILE = Path(__file__).resolve().parent.parent / "data" / "terms.txt"
CODE_TAGS = {"script", "style", "noscript", "template"}
MAX_SCAN_BYTES = 262_144       # bytes passed to the HTML/text scanner
SAMPLE_WINDOWS = 8
SAMPLE_BYTES = 32_768
MAX_DECODE_BYTES = 32 * 1024 * 1024  # bounded compressed text expansion
MAX_PAGE_CHARS = 262_144   # raw HTML read per page
MAX_TEXT_CHARS = MAX_PAGE_CHARS  # do not leave an unscanned gap within a head window
SAFETY_CONTEXT = re.compile(
    r"(?<![\w-])(?:prevention|addiction|help|safety|education|treatment|recovery|"
    r"מניעה|התמכרות|עזרה|חינוך|טיפול)(?![\w-])")


def load_terms(path: Path = TERMS_FILE) -> dict[str, int]:
    terms = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        term, _, weight = line.rpartition(" ")
        terms[term.strip().lower()] = int(weight)
    return terms


class _Visible(HTMLParser):
    """Collects what a reader sees. Stateful: code inside <script>/<style> stays hidden
    even when the page is cut in the middle of it (a regex on a truncated page used to
    expose that code as text)."""

    def __init__(self, limit: int):
        super().__init__(convert_charrefs=True)
        self.limit, self.size, self.parts, self._code = limit, 0, [], 0

    def handle_starttag(self, tag, attrs):
        self.parts.append(" ")  # a tag separates words; text split across reads does not
        if tag in CODE_TAGS:
            self._code += 1

    def handle_endtag(self, tag):
        self.parts.append(" ")
        if tag in CODE_TAGS and self._code:
            self._code -= 1

    def handle_data(self, data):
        if self._code or self.size >= self.limit:
            return
        self.parts.append(data)
        self.size += len(data)


def visible_text(page: str, limit: int = MAX_TEXT_CHARS) -> str:
    parser = _Visible(limit)
    page = page[:MAX_PAGE_CHARS]
    try:
        for i in range(0, len(page), 65_536):  # stop reading once enough text was seen
            parser.feed(page[i:i + 65_536])
            if parser.size >= limit:
                break
        else:
            parser.close()
    except Exception:  # noqa: BLE001 - broken markup: score what was read so far
        pass
    return "".join(parser.parts)[:limit * 2].lower()


def score(page: str, terms: dict[str, int]) -> tuple[int, list[str]]:
    total, hits, _ = assess(page, terms)
    return total, hits


@lru_cache(maxsize=16)
def _patterns(terms):
    return tuple((term, weight, re.compile(rf"(?<![\w-]){re.escape(term)}(?![\w-])"))
                 for term, weight in terms)


def sample_windows(data):
    """Head plus boundary, evenly spaced and tail samples; <=512 KiB scored."""
    if len(data) <= MAX_SCAN_BYTES:
        return [data]
    last = max(MAX_SCAN_BYTES, len(data) - SAMPLE_BYTES)
    starts = sorted({MAX_SCAN_BYTES + (last - MAX_SCAN_BYTES) * i // (SAMPLE_WINDOWS - 1)
                     for i in range(SAMPLE_WINDOWS)})
    # Merge overlaps so near-cap bodies are not scored repeatedly.
    windows, end = [data[:MAX_SCAN_BYTES]], MAX_SCAN_BYTES
    for start in starts:
        start = max(start, end)
        stop = min(len(data), start + SAMPLE_BYTES)
        if stop > start:
            windows.append(data[start:stop])
            end = stop
    return windows


def assess(page: str, terms: dict[str, int], plain: bool = False) -> tuple[int, list[str], bool]:
    text = page[:MAX_PAGE_CHARS].lower() if plain else visible_text(page)
    total, hits = 0, []
    for term, weight, pattern in _patterns(tuple(terms.items())):
        # Whole words only: "xxx" in "xxx-xxx-xxxx" placeholders or "nude" in "denuded" must not count.
        n = sum(1 for _ in pattern.finditer(text))
        if n:
            total += weight * min(n, 3)
            hits.append(term)
    return total, hits, bool(SAFETY_CONTEXT.search(text))
