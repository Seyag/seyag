import pytest

from conftest import PUBLIC_EXPORT

if PUBLIC_EXPORT:
    pytest.importorskip("mcp.server.fastmcp")


def test_create_app_builds_with_real_sdk(tmp_path):
    from aifilter import mcp_server
    from aifilter.store import Store
    assert mcp_server.create_app(Store(tmp_path / "f.db"), enabled=lambda: True) is not None


def test_only_configured_host_is_accepted(tmp_path):
    from aifilter import mcp_server
    from aifilter.store import Store
    app = mcp_server.create_app(Store(tmp_path / "f.db"), enabled=lambda: True, hosts=("203.0.113.10:8130",))
    assert app is not None


def test_skip_install_window_check_uses_existing_mcp_authorization(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from starlette.testclient import TestClient

    from aifilter import mcp_server
    from aifilter.store import Store
    from scripts import app_request

    import ipaddress
    tailnet = ipaddress.ip_network("100.64.0.0/10")  # computed, so no literal tailnet address appears
    host_ip, peer_ip = str(tailnet[1]), str(tailnet[2])
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "f.db"))
    store = Store(tmp_path / "f.db")
    backend = SimpleNamespace(device_id=7)
    calls = []

    def skip(state_file, target, clock, audit):
        calls.append((state_file, target))
        return {"applied": True, "extra_app_check_skipped": True}

    monkeypatch.setattr(app_request, "_skip_closing_check", skip)
    enabled = False
    source = "192.0.2.1"
    app = mcp_server.create_app(store, backend=backend, enabled=lambda: enabled, hosts=(f"{host_ip}:8130",))

    async def with_source(scope, receive, send):
        if scope["type"] == "http":
            scope["client"] = (source, 50000)
        await app(scope, receive, send)

    read = mcp_server.issue_token(store, "reader", "read")
    tighten = mcp_server.issue_token(store, "committee", "tighten")
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "skip_install_window_check", "arguments": {"device": "7"}}}
    headers = {"Accept": "application/json, text/event-stream", "Authorization": "Bearer " + tighten}
    with TestClient(with_source, base_url=f"http://{host_ip}:8130") as client:
        assert client.post("/mcp", json=payload, headers=headers).status_code == 503
        enabled = True
        assert client.post("/mcp", json=payload, headers=headers).status_code == 403
        source = peer_ip
        assert client.post("/mcp", json=payload, headers={"Accept": headers["Accept"]}).status_code == 401
        headers["Authorization"] = "Bearer " + read
        refused = client.post("/mcp", json=payload, headers=headers)
        assert refused.json()["result"]["isError"] and not calls
        headers["Authorization"] = "Bearer " + tighten
        allowed = client.post("/mcp", json=payload, headers=headers)
        assert not allowed.json()["result"].get("isError", False)
        assert calls == [(tmp_path / "app-requests.json", backend)]
