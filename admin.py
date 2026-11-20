"""Admin page ("the higher committee"): approve appeals, decide sites, see blocks.

Binds only to the configured Tailscale address so the owner can use it from the
phone, while the filtered device cannot reach it.
"""

import html
import json
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aifilter import config  # noqa: E402
from aifilter.store import ALLOW, BLOCK, MAX_OVERRIDE_DAYS, TEXT_ONLY, TRUSTED, Store  # noqa: E402

APPROVALS = (ALLOW, TRUSTED)  # opening decisions are always temporary (1-30 days)
DEFAULT_DAYS = 7


def _days(form: dict) -> int | None:
    value = form.get("days", "")
    return int(value) if value.isdigit() and 1 <= int(value) <= MAX_OVERRIDE_DAYS else None

VERDICT_HE = {ALLOW: "פתוח", TRUSTED: "מהימן", BLOCK: "חסום", TEXT_ONLY: "טקסט בלבד"}
SOURCE_HE = {"ai": "AI", "admin": "מנהל", "policy": "מדיניות"}
KIND_HE = {"image-blocked": "תמונה הוסתרה", "page-blocked": "אתר נחסם", "video-blocked": "וידאו נחסם",
           "appeal": "בקשת פתיחה", "verdict": "החלטה", "passthrough": "אפליקציה הותרה"}

STYLE = """
body{margin:0;font-family:-apple-system,"SF Hebrew",Arial,sans-serif;background:#f4f1ea;color:#1f2a37}
header{background:#1f4e79;color:#fff;padding:18px 16px}
header h1{margin:0;font-size:20px}
main{padding:12px 16px;max-width:720px;margin:auto}
section{background:#fff;border-radius:16px;padding:14px;margin:12px 0;box-shadow:0 4px 16px rgba(0,0,0,.06)}
h2{font-size:17px;margin:0 0 10px}
.row{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:10px 0;border-top:1px solid #eee}
.row:first-of-type{border-top:0}
.ltr{direction:ltr;unicode-bidi:embed;font-weight:600;word-break:break-all}
.muted{color:#6b7280;font-size:13px}
form{display:inline}
button{border:0;border-radius:10px;padding:9px 14px;font-size:15px;color:#fff;background:#1f4e79}
button.no{background:#9b2c2c}
button.ok{background:#2f6f3e}
input,select{font-size:16px;padding:8px;border:1px solid #d1d5db;border-radius:10px}
.add{display:flex;gap:8px;flex-wrap:wrap}
.add input{flex:1;min-width:160px;direction:ltr}
.empty{color:#6b7280}
"""


def _ago(ts: float) -> str:
    m = int((time.time() - ts) // 60)
    return "עכשיו" if m < 1 else f"לפני {m} דק׳" if m < 60 else f"לפני {m // 60} שע׳" if m < 1440 else f"לפני {m // 1440} ימים"


def _btn(action: str, fields: dict, label: str, cls: str = "") -> str:
    hidden = "".join(f'<input type="hidden" name="{k}" value="{html.escape(str(v), quote=True)}">' for k, v in fields.items())
    return f'<form method="post" action="/{action}">{hidden}<button class="{cls}">{label}</button></form>'


def render(store: Store) -> bytes:
    e = html.escape
    appeals = store.appeals()
    rows = "".join(
        f'<div class="row"><div><div class="ltr">{e(h)}</div><div class="muted">{e(n or "")} · {_ago(c)}</div></div>'
        f'<div>{_btn("appeal", {"id": i, "approve": 1, "days": DEFAULT_DAYS}, "לפתוח", "ok")} {_btn("appeal", {"id": i, "approve": 0}, "לדחות", "no")}</div></div>'
        for i, h, _u, n, c in appeals
    ) or '<p class="empty">אין בקשות ממתינות.</p>'

    tls = store.tls_failures()
    tls_rows = "".join(
        f'<div class="row"><div><div class="ltr">{e(h)}</div><div class="muted">{n} ניסיונות · {_ago(t)}</div></div>'
        f'{_btn("passthrough", {"host": h}, "להתיר בלי סינון")}</div>'
        for h, n, t in tls
    ) or '<p class="empty">אין.</p>'

    ev = "".join(
        f'<div class="row"><div><div class="ltr">{e(h or "")}</div><div class="muted">{KIND_HE.get(k, k)} · {_ago(t)}</div></div></div>'
        for t, k, h, _d in store.events(40) if k in KIND_HE
    ) or '<p class="empty">אין עדיין.</p>'

    doms = "".join(
        f'<div class="row"><div><div class="ltr">{e(h)}</div><div class="muted">{VERDICT_HE.get(v, v)} · {SOURCE_HE.get(s, s)} · {e(r or "")}</div></div>'
        f'<div>{_btn("domain", {"host": h, "verdict": ALLOW, "days": DEFAULT_DAYS}, "לפתוח", "ok") if v == BLOCK else _btn("domain", {"host": h, "verdict": BLOCK}, "לחסום", "no")}</div></div>'
        for h, v, s, r, _t in store.domains(60)
    ) or '<p class="empty">אין עדיין.</p>'

    temp = "".join(
        f'<div class="row"><div><div class="ltr">{e(h)}</div><div class="muted">{VERDICT_HE.get(v, v)} · '
        f'עד {time.strftime("%d.%m %H:%M", time.localtime(x))} · {e(r or "")}</div></div></div>'
        for h, v, r, x in store.overrides()
    ) or '<p class="empty">אין.</p>'

    page = f"""<!doctype html><html lang="he" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ניהול סינון</title><style>{STYLE}</style></head>
<body><header><h1>ניהול הסינון</h1></header><main>
<section><h2>בקשות לפתיחת אתר ({len(appeals)})</h2><p class="muted">פתיחה היא לשבוע. לתקופה אחרת: הטופס למטה.</p>{rows}</section>
<section><h2>להוסיף החלטה לאתר</h2><form class="add" method="post" action="/domain">
<input name="host" placeholder="example.com" required autocapitalize="off">
<select name="verdict"><option value="{BLOCK}">חסום</option><option value="{ALLOW}">פתוח</option>
<option value="{TRUSTED}">מהימן (בלי בדיקת תמונות)</option></select>
<select name="days"><option value="1">ליום אחד</option><option value="{DEFAULT_DAYS}" selected>לשבוע</option>
<option value="{MAX_OVERRIDE_DAYS}">ל-30 יום</option></select><button>שמירה</button></form>
<p class="muted">חסימה היא קבועה. פתיחה היא תמיד זמנית.</p></section>
<section><h2>אישורים זמניים</h2>{temp}</section>
<section><h2>אפליקציות שלא עובדות דרך הסינון</h2><p class="muted">אפליקציות כמו בנק או וואטסאפ לא מקבלות סינון. התרה פירושה שהן עוברות בלי בדיקה.</p>{tls_rows}</section>
<section><h2>פעילות אחרונה</h2>{ev}</section>
<section><h2>החלטות על אתרים</h2>{doms}</section>
</main></body></html>"""
    return page.encode()


_whois_cache: dict[str, tuple[float, str]] = {}


def device_name(ip: str) -> str:
    """Tailscale device name of a peer (first DNS label), cached for 5 minutes."""
    hit = _whois_cache.get(ip)
    if hit and time.time() - hit[0] < 300:
        return hit[1]
    try:
        out = subprocess.run(["tailscale", "whois", "--json", ip], capture_output=True, text=True, timeout=5)
        name = json.loads(out.stdout)["Node"]["Name"].split(".")[0].lower()
    except Exception:  # noqa: BLE001 - unknown peer means no access
        name = ""
    _whois_cache[ip] = (time.time(), name)
    return name


def make_handler(store: Store, allowed_devices: set[str], resolve=device_name):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b"", ctype="text/html; charset=utf-8", location=None):
            self.send_response(code)
            self.send_header("content-type", ctype)
            self.send_header("cache-control", "no-store")
            if location:
                self.send_header("location", location)
            self.end_headers()
            self.wfile.write(body)

        def _allowed(self) -> bool:
            # Only the owner's admin devices; the filtered device must not decide for itself.
            return resolve(self.client_address[0]) in allowed_devices

        def do_GET(self):
            if not self._allowed():
                return self._send(403, "אין הרשאה".encode())
            if self.path != "/":
                return self._send(404)
            self._send(200, render(store))

        def do_POST(self):
            if not self._allowed():
                return self._send(403)
            origin = self.headers.get("origin", "")
            if origin.split("://", 1)[-1] != self.headers.get("host"):
                return self._send(403)  # cross-site form post
            try:
                size = min(int(self.headers.get("content-length") or 0), 10_000)
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(size).decode("utf-8")).items()}
            except (ValueError, UnicodeDecodeError):
                return self._send(400)
            days = _days(form)
            if self.path == "/appeal" and form.get("id", "").isdigit():
                approve = form.get("approve") == "1"
                if approve and days is None:
                    return self._send(400)
                store.resolve_appeal(int(form["id"]), approve, days if approve else None)
            elif self.path == "/domain" and form.get("verdict") in VERDICT_HE and form.get("host"):
                verdict = form["verdict"]
                host = form["host"].strip().lower()
                # Text-only skips page review: a loosening (same gate, temporary only) unless it only
                # replaces a standing open rule.
                opening = verdict in APPROVALS or (verdict == TEXT_ONLY and not store.text_only_tightens(host))
                if opening and days is None:
                    return self._send(400)  # an opening decision is never permanent
                if opening:
                    try:
                        store.loosen(host, verdict, "admin", "manual", days=days)
                    except ValueError:
                        return self._send(400)
                else:
                    try:
                        store.set_verdict(host, verdict, "admin", "manual")
                    except ValueError:
                        return self._send(400)
            elif self.path == "/passthrough" and form.get("host"):
                try:
                    store.loosen(form["host"], TRUSTED, "admin", "manual passthrough",
                                 passthrough=True, request_id=form.get("request_id"))
                except ValueError:
                    return self._send(400)
            else:
                return self._send(400)
            self._send(303, location="/")

    return Handler


def main():
    cfg = config.load()
    store = Store(config.db_path())
    addr = (cfg.get("admin", "bind", "127.0.0.1"), cfg.get("admin", "port", 8090))
    allowed = {d.lower() for d in cfg.get("admin", "allowed_devices", [])}
    print(f"admin on http://{addr[0]}:{addr[1]}/ for {sorted(allowed)}", flush=True)
    ThreadingHTTPServer(addr, make_handler(store, allowed)).serve_forever()


if __name__ == "__main__":
    main()
