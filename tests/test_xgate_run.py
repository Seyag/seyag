import shutil
import subprocess

import pytest

from aifilter import xgate
from conftest import PUBLIC_EXPORT


@pytest.mark.skipif(PUBLIC_EXPORT and not shutil.which("ffmpeg"), reason="ffmpeg not installed")
def test_real_video_check_runs_ffprobe_and_ffmpeg(tmp_path):
    """Guard: the real check (not a mocked _run) must complete on a valid clip (2026-11-18 TypeError)."""
    clip = tmp_path / "t.mp4"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "lavfi", "-i", "testsrc=duration=2:size=160x120:rate=10",
                    "-pix_fmt", "yuv420p", str(clip)], check=True)
    data = clip.read_bytes()

    class Clean:
        def review(self, frame):
            return False, []

    checker = xgate.VideoChecker(reviewer=Clean(), fetch=lambda *a, **k: data)
    ok, reasons, identities = checker.check("https://video.twimg.com/ext_tw_video/1/pu/vid/avc1/160x120/a.mp4")
    assert ok and reasons == [] and identities


def test_run_accepts_capture_output():
    checker = xgate.VideoChecker(reviewer=object(), fetch=lambda *a, **k: b"")
    out = checker._run(["echo", "hi"], capture_output=True, text=True, timeout=5)
    assert out.stdout.strip() == "hi"
