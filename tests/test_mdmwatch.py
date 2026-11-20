import json

from aifilter import mdmwatch as w

NOW = 1_800_000_000.0


def dev(status="2", ago=60, did="7"):
    return [{"device_id": did, "managed_status": status, "last_contact_time": str(int((NOW - ago) * 1000))}]


def test_managed_and_recent_is_quiet():
    s = {}
    assert w.check(s, dev(), 7, NOW) == (None, False)
    assert "alerted" not in s


def test_removed_or_unmanaged_alerts_once_then_recovers():
    s = {}
    msg, _ = w.check(s, [], 7, NOW)
    assert msg == w.GONE
    assert w.check(s, dev(status="4"), 7, NOW)[0] is None  # same incident: no repeat
    assert w.check(s, dev(), 7, NOW)[0] == w.BACK
    assert "alerted" not in s


def test_unreadable_manageengine_changes_nothing():
    s = {"alerted": "gone"}
    assert w.check(s, None, 7, NOW) == (None, False)
    assert s == {"alerted": "gone"}


def test_quiet_phone_is_asked_to_report_then_alerted_after_a_day():
    s = {}
    assert w.check(s, dev(ago=3600), 7, NOW) == (None, True)
    assert w.check(s, dev(ago=3600), 7, NOW + 60) == (None, False)  # one scan per hour
    assert w.check(s, dev(ago=3600), 7, NOW + 3600) == (None, True)
    assert w.check(s, dev(ago=25 * 3600), 7, NOW)[0] == w.SILENT


def test_silent_after_gone_does_not_downgrade():
    s = {"alerted": "gone"}
    assert w.check(s, dev(ago=25 * 3600), 7, NOW)[0] is None
    assert s["alerted"] == "gone"


class Backend:
    available = True
    device_id = 7

    def __init__(self, devices):
        self._d, self.scans = devices, 0

    def devices(self):
        if isinstance(self._d, Exception):
            raise self._d
        return self._d

    def scan(self):
        self.scans += 1


def test_watch_throttles_and_retries_undelivered(tmp_path):
    f, sent = tmp_path / "w.json", []
    assert w.watch(f, Backend([]), NOW, notify=lambda m: False) == "mdm: managed"  # undelivered: flag rolled back
    assert "alerted" not in json.loads(f.read_text())["devices"]["7"]
    assert w.watch(f, Backend([]), NOW + 60, notify=sent.append) is None  # not due yet
    assert w.watch(f, Backend([]), NOW + w.CHECK_SECONDS, notify=lambda m: sent.append(m) or True) == "mdm: gone"
    assert sent == [w.GONE]


def test_watch_outage_is_not_an_alarm(tmp_path):
    f = tmp_path / "w.json"
    assert w.watch(f, Backend(RuntimeError("zoho down")), NOW, notify=lambda m: 1 / 0) == "mdm: unreadable"


def test_watch_skips_without_mdm(tmp_path):
    class NoMDM:
        available = False
    assert w.watch(tmp_path / "w.json", NoMDM(), NOW) is None


def test_watch_migrates_history_and_reports_and_scans_each_device(tmp_path):
    from aifilter import mdm

    class Fleet:
        available = True
        device_ids = (mdm.IPHONE, mdm.IPAD)
        scans = []

        def devices(self):
            return dev(ago=7200, did=mdm.IPHONE)  # iPad missing, iPhone should be scanned

        def for_device(self, did):
            class Device:
                def scan(self):
                    Fleet.scans.append(did)
            return Device()

    path, messages = tmp_path / "s.json", []
    old = {"checked_at": NOW - 3600, "alerted": "gone", "metadata": "preserved"}
    path.write_text(json.dumps(old))
    note = w.watch(path, Fleet(), NOW, notify=lambda m: messages.append(m) or True)
    assert mdm.IPHONE in note and mdm.IPAD in note
    assert Fleet.scans == [mdm.IPHONE]
    assert len(messages) == 2
    assert "האייפון" in messages[0] and "שוב מנוהל" in messages[0]
    assert "האייפד" in messages[1] and "מהאייפד" in messages[1] and "האייפון" not in messages[1]
    saved = json.loads(path.read_text())["devices"]
    assert saved[mdm.IPHONE]["metadata"] == "preserved" and "alerted" not in saved[mdm.IPHONE]
    assert saved[mdm.IPAD]["alerted"] == "gone"
    assert w.watch(path, Fleet(), NOW + 60, notify=messages.append) is None
