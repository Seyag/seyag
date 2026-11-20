import tomllib
from pathlib import Path

import pytest

from test_filter import FakeReviewer, flow_for, make_filter, store  # noqa: F401


@pytest.mark.parametrize("url", ["https://t.me/s/anychannel", "https://telegram.me/s/x", "https://t.me/s",
                                 "https://t.me/S/ch", "https://t.me/%73/ch", "https://t.me//s/ch", "https://t.me/./s/ch",
                                 "https://www.t.me/s/ch", "https://telegram.dog/s/ch"])
def test_public_channel_pages_are_blocked(store, url):
    flt = make_filter(store, FakeReviewer())
    flow = flow_for(url)
    flt.request(flow)
    assert flow.response is not None and flow.response.status_code == 403


def test_chat_links_are_not_blocked_by_the_feed_rule(store):
    flt = make_filter(store, FakeReviewer())
    flow = flow_for("https://t.me/somebody")
    flt.request(flow)
    assert flow.response is None or flow.response.status_code != 403 or "ערוצי" not in flow.response.get_text()


def test_telegram_web_hosts_are_neither_passthrough_nor_night_allowed(policy_config_path):
    cfg = tomllib.loads(policy_config_path.read_text())
    for host in ("t.me", "telegram.me", "telesco.pe"):
        assert host not in cfg["passthrough"]["hosts"]
        assert host not in cfg["schedule"]["night_allow"]
    assert "telegram.org" in cfg["passthrough"]["hosts"]  # the app itself keeps working
