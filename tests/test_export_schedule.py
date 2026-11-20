"""Public export: runtime schedule files live beside the configured database."""
from pathlib import Path


def test_schedule_keeps_runtime_files_beside_the_configured_database(tmp_path, monkeypatch):
    from aifilter import config, schedules

    assert isinstance(schedules.DEFAULT_FOCUS_FILE, Path)
    monkeypatch.setenv("AIFILTER_DB", str(tmp_path / "filter.db"))
    monkeypatch.setattr(schedules, "DEFAULT_FOCUS_FILE", None)
    policy = schedules.SchedulePolicy(config.Config({}))
    assert policy.focus_file.parent == tmp_path
    assert policy.state_file.parent == tmp_path
