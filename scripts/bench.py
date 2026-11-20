#!/usr/bin/env python3
"""Offline hook benchmark against a frozen Git ref; temporary DB/logs only.

Run with the existing test interpreter: python scripts/bench.py --baseline-ref 2fa3742
No listening proxy, sockets, external requests, model inference or live data.
"""
import argparse
import asyncio
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def source_at(ref, path):
    return subprocess.run(['git', 'show', f'{ref}:{path}'], cwd=ROOT, text=True,
                          capture_output=True, check=True, timeout=10).stdout


def module_from_source(name, source):
    module = types.ModuleType(name)
    module.__file__ = str(ROOT / ('addon.py' if name.endswith('addon') else 'aifilter/text.py'))
    exec(compile(source, module.__file__, 'exec'), module.__dict__)
    return module


def percentiles(values):
    values = sorted(values)
    return {p: round(values[math.ceil(len(values) * q) - 1] * 1000, 4)
            for p, q in (('p50_ms', .5), ('p95_ms', .95))}


async def measure(module, store, count):
    from mitmproxy import http
    from mitmproxy.test import tflow
    from aifilter import config

    flt = module.AIFilter(config.load(), store)
    # Avoid model inference: these cases exercise only the hook overhead.
    cases = {}
    for name, host, ctype, body in (
            ('request', 'unknown.example', 'text/html', b'<p>hello</p>'),
            ('blocked_request', 'blocked.example', 'text/html', b''),
            ('tls_passthrough', 'apple.com', '', b''),
            ('static_response', 'unknown.example', 'text/css', b'body{}'),
            ('cached_html', 'unknown.example', 'text/html', b'<p>hello world</p>' * 300),
            ('trusted_image', 'trusted.example', 'image/png', b'x' * 4096)):
        flow = tflow.tflow(resp=True)
        flow.request.url = f'https://{host}/asset'
        flow.request.headers["accept"] = "text/html"
        flow.client_conn.sni = host
        flow.server_conn.address = host, 443
        flow.response = http.Response.make(200, body, {'content-type': ctype})
        tls_data = types.SimpleNamespace(context=types.SimpleNamespace(client=flow.client_conn, server=flow.server_conn), ignore_connection=False)
        samples = []
        for i in range(count + 30):
            start = time.perf_counter()
            if name.endswith('request'):
                flt.request(flow)
            elif name == 'tls_passthrough':
                flt.tls_clienthello(tls_data)
            else:
                flt.responseheaders(flow)
                await flt.response(flow)
            elapsed = time.perf_counter() - start
            if i >= 30:
                samples.append(elapsed)
        cases[name] = percentiles(samples)
    if hasattr(store, "flush"):
        if not store.flush():
            raise RuntimeError("benchmark writer did not drain")
    flt.done()
    return cases


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-ref', default='2fa3742')
    parser.add_argument('--iterations', type=int, default=500)
    args = parser.parse_args(argv)
    if not 10 <= args.iterations <= 100_000:
        parser.error('iterations must be between 10 and 100000')
    import addon
    from aifilter.store import Store, TRUSTED, BLOCK
    from aifilter.hotstore import ProxyStore

    baseline = module_from_source('bench_baseline_addon', source_at(args.baseline_ref, 'addon.py'))
    baseline.text = module_from_source('bench_baseline_text', source_at(args.baseline_ref, 'aifilter/text.py'))
    with tempfile.TemporaryDirectory(prefix='aifilter-bench-') as folder:
        folder = Path(folder)
        baseline.RECENT_HOSTS = folder / 'recent.log'
        results = {}
        for name, module in (('before', baseline), ('after', addon)):
            db = folder / f'{name}.sqlite'
            raw = Store(db)
            raw.set_verdict('trusted.example', TRUSTED, 'admin')
            raw.set_verdict('blocked.example', BLOCK, 'admin')
            raw._db.close()
            store = Store(db) if name == 'before' else ProxyStore(db)
            try:
                results[name] = asyncio.run(measure(module, store, args.iterations))
            finally:
                if isinstance(store, Store):
                    store._db.close()
                else:
                    store.close()
        print(json.dumps({'baseline_ref': args.baseline_ref, 'iterations': args.iterations,
                          'scope': 'local warm hooks; no transport/model inference', **results}, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
