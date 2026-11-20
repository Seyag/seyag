import os
import sys
import tempfile
from importlib.util import find_spec
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_EXPORT = (ROOT / ".public-export").exists()

if PUBLIC_EXPORT:
    os.environ["AIFILTER_CONFIG"] = str(ROOT / "tests/fixtures/config.toml")


@pytest.fixture
def policy_config_path():
    """Configuration used by policy integration tests."""
    return Path(os.environ["AIFILTER_CONFIG"]) if PUBLIC_EXPORT else ROOT / "config.toml"


def pytest_collection_modifyitems(items):
    if not PUBLIC_EXPORT:
        return
    omitted = {
        "test_heartbeat_reconnect.py": "requires the omitted household failover script",
        "test_heartbeat_requires_own_block_page_before_upload": "requires the omitted household failover script",
        "test_public_export_passes_gate": "requires the private source tree and Git index to create an export",
        "test_known_private_literals_are_removed": "requires the private source configuration for comparison",
    }
    for item in items:
        reason = omitted.get(item.path.name) or omitted.get(getattr(item, "originalname", None))
        if reason:
            item.add_marker(pytest.mark.skip(reason=reason))


def pytest_ignore_collect(collection_path, config):
    """Skip dependency-specific modules in a minimal public-export environment."""
    if collection_path.suffix != ".py" or not collection_path.name.startswith("test_"):
        return False
    if not PUBLIC_EXPORT:
        return False  # the private repo never skips a test: a missing dependency must fail loudly
    source = collection_path.read_text(errors="ignore")
    dependencies = {
        "mitmproxy": ("mitmproxy", "import addon", "from test_filter import"),
        "dnslib": ("dnslib", "from aifilter import dns"),
        "PIL": ("from PIL",),
    }
    if find_spec("dnslib") is None and collection_path.name in {
        "test_healthcheck.py", "test_selftest.py", "test_v6guard.py"
    }:
        return True
    return any(find_spec(module) is None and any(marker in source for marker in markers)
               for module, markers in dependencies.items())

sys.path.insert(0, str(ROOT))

# Never let a test (or an import) open the live database: any default Store goes to a temp file.
os.environ["AIFILTER_DB"] = str(Path(tempfile.mkdtemp(prefix="aifilter-test-")) / "filter.db")


@pytest.fixture(autouse=True)
def _no_telegram(monkeypatch):
    if PUBLIC_EXPORT and find_spec("mitmproxy") is None:
        return
    import addon
    monkeypatch.setattr(addon, "NOTIFY", False)


@pytest.fixture(autouse=True)
def _no_live_prefetch_budget(monkeypatch, tmp_path):
    """The prefetch spend counter must never touch the live data/yt-prefetch-budget.json."""
    from aifilter import ytprefetch
    monkeypatch.setattr(ytprefetch, "BUDGET_FILE", tmp_path / "yt-prefetch-budget.json")


@pytest.fixture(autouse=True)
def _no_live_schedules(request, monkeypatch, tmp_path):
    """Wall-clock schedules and the bridge's real focus file must not leak into unrelated tests."""
    from aifilter import schedules
    monkeypatch.setattr(schedules, "DEFAULT_FOCUS_FILE", tmp_path / "focus-blocks.json")
    if request.node.fspath.basename not in ("test_schedules.py", "test_music_carplay.py", "test_youtube_smooth.py"):
        monkeypatch.setattr(schedules.SchedulePolicy, "reason",
                            lambda self, host, now=None, *, allow_work_music=False, client=None: None)


@pytest.fixture(autouse=True)
def _loosening_clock_is_daytime(monkeypatch):
    """The night rule must not make tests depend on when they run: default to noon, Israel time.
    Night behaviour is tested with an explicit `now=`."""
    from datetime import datetime
    from zoneinfo import ZoneInfo
    from aifilter import store
    import time

    def noon():
        local = datetime.fromtimestamp(time.time(), ZoneInfo("Asia/Jerusalem"))
        return local.replace(hour=12, minute=0, second=0, microsecond=0).timestamp()
    monkeypatch.setattr(store, "_loosen_clock", noon)
