"""Guard the published PAC: MDM goes direct, and on the home LAN the Mac's LAN proxy comes first."""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

PAC = Path(__file__).resolve().parent.parent / "pac" / "proxy.pac"
PUBLIC_EXPORT = (PAC.parent.parent / ".public-export").exists()
HARNESS = """
const src = require('fs').readFileSync(process.argv[1], 'utf8'); eval(src);
global.dnsDomainIs = (h, d) => h.endsWith(d);
global.isPlainHostName = h => !h.includes('.');
const ip = s => s.split('.').map(Number);
global.isInNet = (h, n, m) => ip(h).every((v, i) => (v & ip(m)[i]) == (ip(n)[i] & ip(m)[i]));
const out = {};
for (const [me, host] of JSON.parse(process.argv[2])) { global.myIpAddress = () => me; out[me + ' ' + host] = FindProxyForURL('https://' + host + '/', host); }
console.log(JSON.stringify(out));
"""


def _run(cases):
    if PUBLIC_EXPORT and not shutil.which("node"):
        pytest.skip("node not installed")
    res = subprocess.run(["node", "-e", HARNESS, str(PAC), json.dumps(cases)], capture_output=True, text=True, check=True)
    return json.loads(res.stdout)


def test_mdm_direct_and_lan_first():
    if PUBLIC_EXPORT:
        local, away = "192.0.2.35", "203.0.113.35"
        lan_proxy, tailnet_proxy = "192.0.2.10", "198.51.100.10"
    else:
        local, away = "203.0.113.10", "203.0.113.10"
        lan_proxy, tailnet_proxy = "203.0.113.10", "203.0.113.10"
    host = "www.ynet.co.il"
    out = _run([[local, "mdm.manageengine.com"], [local, host], [away, host]])
    assert out[f"{local} mdm.manageengine.com"] == "DIRECT"
    assert out[f"{local} {host}"].startswith(f"PROXY {lan_proxy}:8118;")
    assert out[f"{away} {host}"].startswith(f"PROXY {tailnet_proxy}:8118;")
    assert all("DIRECT" not in out[f"{client} {host}"] for client in (local, away))


def test_tailscale_login_goes_direct_but_lookalikes_do_not():
    # Logged out on cellular, every proxy is a tailnet address; login must not depend on the proxy (2026-11-19).
    out = _run([["203.0.113.10", "controlplane.tailscale.com"], ["203.0.113.10", "login.tailscale.com"],
                ["203.0.113.10", "derp4.tailscale.com"], ["203.0.113.10", "log.tailscale.io"],
                ["203.0.113.10", "eviltailscale.com"], ["203.0.113.10", "tailscale.com.evil.net"]])
    for h in ("controlplane.tailscale.com", "login.tailscale.com", "derp4.tailscale.com", "log.tailscale.io"):
        assert out["203.0.113.10 " + h] == "DIRECT"
    for h in ("eviltailscale.com", "tailscale.com.evil.net"):
        assert "DIRECT" not in out["203.0.113.10 " + h]
