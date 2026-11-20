import json
import socket
import threading
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts import healthcheck


class OneShotSocketPair:
    def __init__(self, response: bytes):
        self.response = response
        self.client, self.server = socket.socketpair()
        self.request = b""
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        with self.server:
            self.server.settimeout(2)
            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) < 4096:
                part = self.server.recv(1024)
                if not part:
                    break
                data.extend(part)
            self.request = bytes(data)
            self.server.sendall(self.response)

    def close(self):
        self.client.close()
        self.thread.join(timeout=2)


def test_proxy_check_sends_connect_and_accepts_http_200():
    server = OneShotSocketPair(b"HTTP/1.1 200 Connection established\r\n\r\n")
    try:
        ok, reason = healthcheck.check_proxy_connect(
            proxy_port=8118, target="17.0.0.1:443", timeout=2,
            connect=lambda _address, timeout: server.client,
            tls_probe=lambda sock, host, timeout: None,
        )
        assert ok, reason
        server.thread.join(timeout=2)
        assert server.request.startswith(b"CONNECT 17.0.0.1:443 HTTP/1.1\r\n")
    finally:
        server.close()


def test_proxy_check_rejects_non_200_and_bad_target():
    server = OneShotSocketPair(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
    try:
        ok, _ = healthcheck.check_proxy_connect(
            proxy_port=8118, target="17.0.0.1:443", timeout=2,
            connect=lambda _address, timeout: server.client,
            tls_probe=lambda sock, host, timeout: None,
        )
        assert not ok
    finally:
        server.close()
    ok, reason = healthcheck.check_proxy_connect(target="bad\r\nInjected: yes:443")
    assert not ok
    assert "CONNECT failed" in reason


def test_pac_check_requires_exact_expected_contents():
    body = b"function FindProxyForURL(url, host) { return 'PROXY 127.0.0.1:8118'; }\n"

    class Response:
        status = 200

        def __init__(self, content):
            self.content = content

        def read(self, _limit):
            return self.content

    class Connection:
        def __init__(self, _host, _port, timeout, content=body):
            assert timeout == 2
            self.content = content
            self.path = None

        def request(self, method, path, headers):
            assert method == "GET"
            assert headers["Connection"] == "close"
            self.path = path

        def getresponse(self):
            assert self.path == "/proxy.pac"
            return Response(self.content)

        def close(self):
            pass

    ok, reason = healthcheck.check_pac(body, pac_port=8119, timeout=2, connection_factory=Connection)
    assert ok, reason
    ok, _ = healthcheck.check_pac(
        body + b"different", pac_port=8119, timeout=2,
        connection_factory=lambda host, port, timeout: Connection(host, port, timeout, body),
    )
    assert not ok


def test_outage_alert_threshold_restart_dedup_and_recovery(tmp_path):
    path = tmp_path / "health.json"
    state = healthcheck.load_state(path)
    notify = Mock(return_value=True)
    initial = healthcheck.update_service(state, "proxy", False, "socket refused", 1000, notify=True, state_path=path, notifier=notify)
    assert "down for 0s" in initial
    assert notify.call_count == 0

    state = healthcheck.load_state(path)  # simulate process restart
    healthcheck.update_service(state, "proxy", False, "socket refused", 1299, notify=True, state_path=path, notifier=notify)
    assert notify.call_count == 0
    result = healthcheck.update_service(state, "proxy", False, "socket refused", 1300, notify=True, state_path=path, notifier=notify)
    assert "down alert sent" in result
    assert notify.call_count == 1

    state = healthcheck.load_state(path)
    healthcheck.update_service(state, "proxy", False, "still refused", 1500, notify=True, state_path=path, notifier=notify)
    assert notify.call_count == 1
    result = healthcheck.update_service(state, "proxy", True, "ok", 1501, notify=True, state_path=path, notifier=notify)
    assert "recovery alert sent" in result
    assert notify.call_count == 2

    state = healthcheck.load_state(path)
    healthcheck.update_service(state, "proxy", True, "ok", 1502, notify=True, state_path=path, notifier=notify)
    assert notify.call_count == 2


def test_notifications_are_opt_in_and_command_failures_do_not_raise(tmp_path):
    path = tmp_path / "health.json"
    state = healthcheck.load_state(path)
    notify = Mock(side_effect=RuntimeError("not available"))
    healthcheck.update_service(state, "pac", False, "offline", 10, notify=False, state_path=path, notifier=notify)
    healthcheck.update_service(state, "pac", False, "offline", 400, notify=False, state_path=path, notifier=notify)
    assert notify.call_count == 0

    result = healthcheck.update_service(state, "pac", False, "offline", 500, notify=True, state_path=path, notifier=notify)
    assert "down alert failed" in result
    assert notify.call_count == 1
    state = healthcheck.load_state(path)
    healthcheck.update_service(state, "pac", False, "offline", 800, notify=True, state_path=path, notifier=notify)
    assert notify.call_count == 1


def test_notification_uses_the_existing_session_hook_without_running_it(monkeypatch):
    monkeypatch.setenv("AIFILTER_NOTIFICATION_COMMAND", "test-notifier")
    completed = SimpleNamespace(returncode=0)
    with patch.object(healthcheck.shutil, "which", return_value="/test/test-notifier") as which:
        with patch.object(healthcheck.subprocess, "run", return_value=completed) as run:
            assert healthcheck.send_alert("proxy unavailable", timeout=3)
    which.assert_called_once_with("test-notifier")
    args, kwargs = run.call_args
    assert args[0][:3] == ["/test/test-notifier", "mirror", "--title"]
    assert args[0][args[0].index("--session") + 1] == "ai-filter-appeals"
    assert kwargs["input"] == "proxy unavailable"
    assert kwargs["timeout"] == 3


def test_state_is_persistent_and_owner_only(tmp_path):
    path = tmp_path / "nested" / "state.json"
    state = healthcheck.fresh_state()
    state["services"]["pac"]["failure_since"] = 42
    assert healthcheck.save_state(path, state)
    assert healthcheck.load_state(path)["services"]["pac"]["failure_since"] == 42
    assert path.stat().st_mode & 0o777 == 0o600
    # Default persistent state must never become a source artifact.
    ignore_patterns = (healthcheck.ROOT / '.gitignore').read_text().splitlines()
    assert {'data/healthcheck.json', 'data/healthcheck.lock'} <= set(ignore_patterns)


def test_once_is_default_and_watch_interval_is_bounded():
    parser = healthcheck.make_parser()
    args = parser.parse_args([])
    assert not args.watch
    assert args.interval == 120
    try:
        parser.parse_args(["--interval", "0"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("zero interval should be rejected")


def test_lazy_connect_success_without_upstream_tls_is_down():
    server = OneShotSocketPair(b"HTTP/1.1 200 Connection established\r\n\r\n")
    try:
        def failed_tls(*args):
            raise OSError('upstream unavailable')
        ok, _ = healthcheck.check_proxy_connect(connect=lambda *a, **kw: server.client, tls_probe=failed_tls)
        assert not ok
    finally:
        server.close()


def test_one_aggregate_alert_and_recovery_even_when_both_services_fail(tmp_path, monkeypatch):
    args = healthcheck.make_parser().parse_args(['--notify', '--state-file', str(tmp_path / 'state.json')])
    args.pac_file = tmp_path / 'proxy.pac'
    args.pac_file.write_text('function FindProxyForURL() {}')
    notify = Mock(return_value=True)
    statuses = [False, False]
    monkeypatch.setattr(healthcheck, 'check_proxy_connect', lambda *a: (statuses[0], 'proxy test'))
    monkeypatch.setattr(healthcheck, 'check_pac', lambda *a: (statuses[1], 'pac test'))
    for now in (0, 120, 240, 360, 480):
        healthcheck.run_once(args, now=lambda: now, notifier=notify)
    assert notify.call_count == 1
    statuses[0] = True
    healthcheck.run_once(args, now=lambda: 600, notifier=notify)
    assert notify.call_count == 1
    statuses[1] = True
    healthcheck.run_once(args, now=lambda: 720, notifier=notify)
    healthcheck.run_once(args, now=lambda: 840, notifier=notify)
    assert notify.call_count == 2


def test_concurrent_watchdog_cannot_duplicate_alert(tmp_path):
    import fcntl
    args = healthcheck.make_parser().parse_args(['--state-file', str(tmp_path / 'state.json')])
    with open(args.state_file.with_suffix('.lock'), 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert healthcheck.run_once(args) == ['healthcheck already running']


def test_dns_check_reports_dead_port_and_missing_dhcp_is_skipped(tmp_path, monkeypatch):
    import importlib.util, socket
    spec = importlib.util.spec_from_file_location("hc_extra", "scripts/healthcheck.py")
    hc = importlib.util.module_from_spec(spec); spec.loader.exec_module(hc)
    # No live bind: exercise the same OS failure without host network permissions.
    def unavailable(*args):
        raise OSError("DNS socket unavailable")
    monkeypatch.setattr(hc.socket, "socket", unavailable)
    ok, message = hc.check_dns("127.0.0.1", 53, 0.3)
    assert not ok and "DNS" in message
    assert hc.check_home_dhcp(tmp_path / "absent.plist") is None


def test_home_v6_absent_is_skipped(tmp_path):
    assert healthcheck.check_home_v6(tmp_path / "absent.plist") is None


def test_home_v6_probes_each_taken_over_address(tmp_path, monkeypatch):
    plist = tmp_path / "p.plist"; plist.write_text("x")
    state = tmp_path / "s.json"; state.write_text('{"addrs": ["2001:db8::1", "2001:db8::2"], "ts": 1}')
    monkeypatch.setattr(healthcheck.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0})())
    seen = []
    ok, _ = healthcheck.check_home_v6(plist, state, probe=lambda a, p, t: (seen.append(a), (True, "ok"))[1])
    assert ok and seen == ["2001:db8::1", "2001:db8::2"]
    ok, msg = healthcheck.check_home_v6(plist, state, probe=lambda a, p, t: (False, "DNS query failed: timeout"))
    assert not ok and "not filtering" in msg


def test_home_v6_guard_down_or_bad_state(tmp_path, monkeypatch):
    plist = tmp_path / "p.plist"; plist.write_text("x")
    state = tmp_path / "s.json"; state.write_text("not json")
    monkeypatch.setattr(healthcheck.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0})())
    assert healthcheck.check_home_v6(plist, state)[0] is False
    monkeypatch.setattr(healthcheck.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 1})())
    assert healthcheck.check_home_v6(plist, state) == (False, "IPv6 guard is not running")


def test_home_v6_empty_takeover_is_down_when_router_announces_dns(tmp_path, monkeypatch):
    plist = tmp_path / "p.plist"; plist.write_text("x")
    state = tmp_path / "s.json"; state.write_text('{"addrs": [], "ts": 1}')
    monkeypatch.setattr(healthcheck.subprocess, "run", lambda *a, **k: type("R", (), {"returncode": 0})())
    monkeypatch.setattr(healthcheck, "announced_v6_dns", lambda: ["2001:db8::2"])
    ok, msg = healthcheck.check_home_v6(plist, state)
    assert not ok and "holds no address" in msg
    monkeypatch.setattr(healthcheck, "announced_v6_dns", lambda: [])
    assert healthcheck.check_home_v6(plist, state)[0] is True
