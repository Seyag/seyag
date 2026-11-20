"""heartbeat.sh reconnects Tailscale after it stays offline (2026-11-19 reboot cut the iPhone off for 27 min)."""
import os
import shutil
import stat
import subprocess
from pathlib import Path


def _fake(path: Path, body: str) -> str:
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


def _run(tmp_path, ts):
    env = dict(os.environ, HEARTBEAT_TAILSCALE=ts,
               HEARTBEAT_OPEN=_fake(tmp_path / "open", f'echo open "$@" >> {tmp_path}/calls\n'))
    return subprocess.run(["bash", str(tmp_path / "root/backup/failover/heartbeat.sh")],
                          env=env, capture_output=True, text=True, timeout=60)


def test_reconnect_from_second_offline_run_then_reset(tmp_path):
    (tmp_path / "root/backup/failover").mkdir(parents=True)
    (tmp_path / "root/data").mkdir()
    shutil.copy("backup/failover/heartbeat.sh", tmp_path / "root/backup/failover/heartbeat.sh")
    calls = tmp_path / "calls"
    offline = _fake(tmp_path / "ts", f'''if [ "$1" = status ]; then echo '{{"BackendState":"Stopped","Self":{{"Online":false}}}}';
else echo ts "$@" >> {calls}; fi\n''')
    first = _run(tmp_path, offline)
    assert "1 in a row" in first.stdout and not calls.exists()
    second = _run(tmp_path, offline)
    assert "2 in a row" in second.stdout and "reconnect attempted" in second.stdout
    log = calls.read_text()
    assert "open -g -a Tailscale" in log and "ts up\n" in log
    assert "--reset" not in log
    # Back online: the counter clears (the run then stops at the proxy check, which is fine here).
    online = _fake(tmp_path / "ts2", '''echo '{"BackendState":"Running","Self":{"Online":true}}'\n''')
    _run(tmp_path, online)
    assert not (tmp_path / "root/data/tailscale-offline").exists()
