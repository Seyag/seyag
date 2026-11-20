import os, sys, types
os.environ.update(PROJECT="p", BUCKET="b", ZONE="test-zone", VM="test-vm",
                  FAILOVER_PAUSE_TIMEZONE="UTC", FAILOVER_PAUSE_START="15:00", FAILOVER_PAUSE_END="20:00")
for m in ("functions_framework", "google", "google.cloud"):
    sys.modules.setdefault(m, types.ModuleType(m))
sys.modules["functions_framework"].http = lambda f: f
sys.modules["google.cloud"].compute_v1 = types.SimpleNamespace(); sys.modules["google.cloud"].storage = types.SimpleNamespace()
sys.path.insert(0, os.path.dirname(__file__))
from main import decide

def test_start_when_stale_and_stopped():
    assert decide(11, "TERMINATED", False) == "start"
def test_missing_heartbeat_counts_as_stale():
    assert decide(None, "TERMINATED", False) == "start"
    assert decide(None, "RUNNING", True) is None
def test_stop_only_auto_started():
    assert decide(1, "RUNNING", True) == "stop"
    assert decide(1, "RUNNING", False) is None
def test_hysteresis():
    assert decide(9, "RUNNING", True) is None
    assert decide(7, "RUNNING", True) == "stop"  # a 3-minute heartbeat always lands inside the window
    assert decide(6, "TERMINATED", False) is None


def test_failed_stop_keeps_ownership_for_retry():
    import main
    calls = []
    class Op:
        def __init__(self, fail=False): self.fail = fail
        def result(self):
            if self.fail: raise RuntimeError("stop failed")
    class IC:
        def stop(self, **k): calls.append("stop"); return Op(fail=True)
        def set_labels(self, **k): calls.append("label"); return Op()
        def get(self, **k): return None
    import pytest
    with pytest.raises(RuntimeError):
        main.act(IC(), types.SimpleNamespace(labels={"auto": "1"}, label_fingerprint="f"), "stop")
    assert calls == ["stop"]  # label untouched: the next tick still owns the VM and retries


def test_shabbat_keeps_the_server_off():
    import datetime as dt, main
    assert decide(60, "TERMINATED", False, shabbat=True) is None
    assert decide(60, "RUNNING", True, shabbat=True) == "stop"
    assert decide(60, "RUNNING", False, shabbat=True) is None  # a manual start is left alone
    utc = dt.timezone.utc
    assert not main.is_shabbat(dt.datetime(2030, 1, 4, 14, 59, tzinfo=utc))
    assert main.is_shabbat(dt.datetime(2030, 1, 4, 15, 0, tzinfo=utc))
    assert main.is_shabbat(dt.datetime(2030, 1, 5, 19, 59, tzinfo=utc))
    assert not main.is_shabbat(dt.datetime(2030, 1, 5, 20, 0, tzinfo=utc))
