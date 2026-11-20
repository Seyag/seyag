"""Usage: .venv/bin/python scripts/browse_probe.py  # measure browsing through the local filter"""
from __future__ import annotations

import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scripts import tls_watch

PAGES = tuple('https://' + host + '/' for host in (
    'www.google.com', 'he.wikipedia.org', 'www.ynet.co.il', 'www.walla.co.il',
    'www.mako.co.il', 'www.apple.com', 'www.gov.il', 'www.waze.com',
    'www.hebcal.com', 'github.com', 'claude.ai', 'web.whatsapp.com',
))
# Candidate Apple software distribution object; verify availability before deployment.
DOWNLOAD_URL = 'https://mesu.apple.com/assets/com_apple_MobileAsset_SoftwareUpdate/com_apple_MobileAsset_SoftwareUpdate.xml'  # Apple-hosted, answers ranged GETs (verified 2026-11-13)
SAMPLE_BYTES = 5 * 1024 * 1024
CA = Path.home() / '.mitmproxy/mitmproxy-ca-cert.pem'


def fetch(url: str, download: bool = False) -> dict:
    """Use the actual proxy and CA, without the filter's special probe marker."""
    cmd = ['curl', '--disable', '--silent', '--show-error', '--location',
           '--proxy', 'http://127.0.0.1:8118', '--noproxy', '',
           '--cacert', str(CA), '--max-time', '10', '--output', '/dev/null',
           '--write-out', '%{http_code} %{time_starttransfer} %{time_total} %{size_download}']
    if download:
        cmd += ['--range', f'0-{SAMPLE_BYTES - 1}', '--max-filesize', str(SAMPLE_BYTES)]
    try:
        result = subprocess.run(cmd + [url], capture_output=True, text=True, timeout=10)
        status, ttfb, total, size = result.stdout.split()
        status, ttfb, total, size = int(status), float(ttfb), float(total), int(float(size))
        # A page counts as reachable when the site answers at all below 500: some sites (gov.il, claude.ai)
        # refuse automated clients with 403, which says nothing about the filter.
        ok = (result.returncode == 0 and (100 <= status < 500 if not download else True) and
              (not download or (status in (200, 206) and size == SAMPLE_BYTES)))
        return {'url': url, 'ok': ok, 'ttfb_s': ttfb or None, 'total_s': total,
                'mbit_s': size * 8 / total / 1_000_000 if download and total > 0 and ok else None,
                'status': status, 'error': result.stderr.strip() or None}
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return {'url': url, 'ok': False, 'ttfb_s': None, 'total_s': None,
                'mbit_s': None, 'status': None, 'error': str(exc)}


def run(data_dir: Path, fetcher=fetch, report=None, now=None) -> dict:
    data_dir.mkdir(parents=True, exist_ok=True)
    state_path = data_dir / 'browse-probe.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    day = (now or dt.datetime.now().astimezone()).date().isoformat()
    results = [fetcher(url, False) for url in PAGES]
    results.append(fetcher(DOWNLOAD_URL, True))
    problems = {}
    for item in results:
        url = item['url']
        if not item['ok']:
            problems[f'broken:{url}'] = 'request failed'
        elif url == DOWNLOAD_URL:
            if item['mbit_s'] < 20:
                problems[f'slow:{url}'] = f"download {item['mbit_s']:.1f} Mbit/s"
        elif item['total_s'] > 4:
            problems[f'slow:{url}'] = f"page took {item['total_s']:.1f} seconds"

    entry = {'timestamp': (now or dt.datetime.now().astimezone()).isoformat(), 'results': results}
    with (data_dir / 'browse-probe.log').open('a') as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + '\n')
    previous = set(state.get('previous', []))
    reported = {k: v for k, v in state.get('reported', {}).items() if v == day}
    for key, detail in problems.items():
        if key in previous and key not in reported:
            kind, url = key.split(':', 1)
            (report or tls_watch._ledger)(url, 2, f'browse check {kind}: {detail}')
            reported[key] = day
    state_path.write_text(json.dumps({'previous': list(problems), 'reported': reported}))
    return entry


if __name__ == '__main__':
    print(json.dumps(run(ROOT / 'data'), ensure_ascii=False))
