import plistlib
from pathlib import Path

PROFILE = Path(__file__).resolve().parent.parent / "deploy/iphone-filter.mobileconfig"


def _blocked():
    prof = plistlib.loads(PROFILE.read_bytes())
    return {b for x in prof["PayloadContent"] if x["PayloadType"] == "com.apple.applicationaccess"
            for b in x.get("blockedAppBundleIDs", [])}


def test_regular_telegram_blocked_and_companion_allowed():
    blocked = _blocked()
    assert {"ph.telegra.Telegraph", "app.nicegram", "app.swiftgram.ios"} <= blocked
    assert not any(b.startswith("com.example.companion") for b in blocked)
