"""Hebrew (RTL) pages shown to the filtered device."""

import html
import struct
import zlib

APPEAL_HOST = "ai-filter.local"
# Same-origin path: posting over the blocked page's own HTTPS avoids Safari's "form is not secure" warning.
APPEAL_PATH = "/__ai-filter/appeal"

_STYLE = """
body{margin:0;font-family:-apple-system,"SF Hebrew","Segoe UI",Arial,sans-serif;
background:#f4f1ea;color:#1f2a37;display:flex;min-height:100vh;align-items:center;justify-content:center}
.card{background:#fff;border-radius:20px;padding:32px 24px;max-width:420px;margin:16px;
box-shadow:0 8px 30px rgba(31,42,55,.12);text-align:center}
.icon{width:64px;height:64px;margin:0 auto 12px;border-radius:50%;background:#1f4e79;
display:flex;align-items:center;justify-content:center}
h1{font-size:22px;margin:8px 0}
p{line-height:1.6;color:#4b5563}
.host{direction:ltr;unicode-bidi:embed;font-weight:600;color:#1f2a37}
button{background:#1f4e79;color:#fff;border:0;border-radius:12px;padding:14px 22px;font-size:17px;width:100%}
textarea{width:100%;box-sizing:border-box;border:1px solid #d1d5db;border-radius:12px;padding:10px;
font-size:16px;margin:8px 0 12px;font-family:inherit}
"""

_SHIELD = ('<svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2">'
           '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/></svg>')


def _page(title: str, body: str) -> bytes:
    return (f'<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)}</title><style>{_STYLE}</style></head>'
            f'<body><div class="card"><div class="icon">{_SHIELD}</div>{body}</div></body></html>').encode()


def blocked(host: str, url: str, reason: str) -> bytes:
    h, u = html.escape(host), html.escape(url, quote=True)
    return _page("האתר חסום", f"""
<h1>האתר חסום</h1>
<p>האתר <span class="host">{h}</span> נחסם על ידי מערכת הסינון.</p>
<p>{html.escape(reason)}</p>
<form method="post" action="{APPEAL_PATH}">
<input type="hidden" name="url" value="{u}">
<textarea name="note" rows="2" placeholder="למה צריך את האתר? (לא חובה)"></textarea>
<button type="submit">בקשה לפתיחת האתר</button>
</form>""")


def appeal_sent() -> bytes:
    return _page("הבקשה נשלחה", "<h1>הבקשה נשלחה לוועדה</h1><p>כדי שהבקשה תיבדק, כתוב ל-Claude באיזה אתר מדובר ולמה אתה צריך אותו. "
                         "אתר נפתח רק לצורך ברור, ולרוב לזמן מוגבל.</p>")


APPEAL_TOO_MANY = "נשלחו הרבה בקשות בזמן קצר. אפשר לנסות שוב בעוד שעה."


def appeal_error(message: str = "הבקשה לא תקינה. אפשר לחזור לדף הקודם ולנסות שוב.") -> bytes:
    return _page("הבקשה לא נשלחה", f"<h1>הבקשה לא נשלחה</h1><p>{html.escape(message)}</p>")


PLACEHOLDER_GREY = 0xE6  # light neutral grey


def solid_png(width: int, height: int, grey: int) -> bytes:
    """A valid opaque single-colour greyscale PNG built from first principles (no image library)."""
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    rows = (b"\x00" + bytes([grey]) * width) * height  # filter type 0 per scanline
    header = struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0)  # 8-bit greyscale, no interlace
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b""))


# Shown in place of a removed image. It is made here, never from the removed bytes, so it reveals
# nothing of them. The earlier hand-written constant had a corrupt IDAT chunk: apps could not decode
# it and drew a broken tile on every hidden YouTube thumbnail and avatar (2026-11-19).
PLACEHOLDER_PNG = solid_png(16, 9, PLACEHOLDER_GREY)
