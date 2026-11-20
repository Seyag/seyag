import json

from mitmproxy import http
from mitmproxy.test import tflow

import addon


def test_youtube_capture_redacts_sensitive_query_values():
    flow = tflow.tflow(resp=True)
    flow.request.url = ("https://rr1.googlevideo.com/initplayback?"
                        "sig=SECRET&n=NONCE&ip=192.0.2.1&c=5&itag=140&sabr=1&z=PRIVATE")
    flow.request.method = "POST"
    flow.request.headers["cookie"] = "SID=SECRET"
    flow.request.headers["authorization"] = "Bearer SECRET"
    flow.request.headers["x-youtube-client-name"] = "5"
    flow.request.headers["x-youtube-client-version"] = "20.45"
    flow.response = http.Response.make(200, b"private response body", {
        "content-type": "application/vnd.yt-ump", "content-length": "21"
    })

    raw = addon._youtube_capture_detail(flow, "response")
    record = json.loads(raw)

    assert record["path"] == "/initplayback"
    assert record["query_keys"] == ["c", "ip", "itag", "n", "sabr", "sig", "z"]
    assert record["query_values"] == {"c": ["5"], "itag": ["140"], "sabr": ["1"]}
    assert record["client"] == {"name": "5", "version": "20.45"}
    for secret in ("SECRET", "NONCE", "192.0.2.1", "PRIVATE", "private response body"):
        assert secret not in raw
