"""ManageEngine MDM backend (aifilter/mdm.py) against a fake HTTP layer: no network, no Keychain."""
import json
import fcntl
import re
import urllib.parse
from pathlib import Path

import pytest

from aifilter import mdm

DEV = "101"
PID, ITEM = "900000002", "900000007"
SECRET = {"client_id": "cid-XYZ", "client_secret": "csecret-XYZ", "refresh_token": "rtoken-XYZ",
          "accounts": "https://accounts.zoho.com"}
TOKEN_URL = "https://accounts.zoho.com/oauth/v2/token"


class FakeAPI:
    """Routes (method, path) to handlers; records every call. Unknown routes fail the test."""

    def __init__(self, routes=None, tokens=("tok-1", "tok-2", "tok-3")):
        self.routes, self.calls, self.tokens = dict(routes or {}), [], list(tokens)

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if url == TOKEN_URL:
            return 200, json.dumps({"access_token": self.tokens.pop(0), "expires_in": 3600}).encode()
        u = urllib.parse.urlsplit(url)
        assert u.scheme == "https" and u.netloc == "mdm.manageengine.com", url
        path = u.path.removeprefix("/api/v1/mdm")
        handler = self.routes.get((method, path))
        if handler is None:
            pytest.fail(f"unexpected call {method} {path}")
        got = handler(json.loads(body) if body else None, urllib.parse.parse_qs(u.query)) \
            if callable(handler) else handler
        status, payload = got if isinstance(got, tuple) else (200, got)
        return status, (b"" if payload is None else json.dumps(payload).encode())

    def api_calls(self):
        return [(m, urllib.parse.urlsplit(u).path.removeprefix("/api/v1/mdm"), json.loads(b) if b else None)
                for m, u, _, b in self.calls if u != TOKEN_URL]


def make(tmp_path, api, clock=lambda: 1000.0):
    return mdm.ManageEngineMDM(device_id=DEV, state_file=tmp_path / "mdm-state.json", transport=api,
                               read_secret=lambda: json.dumps(SECRET).encode(), clock=clock)


def profile(status_id="110", **kw):
    return {"profile_id": PID, "profile_name": mdm.PROFILE_NAME, "profile_description": mdm.PROFILE_MARK,
            "platform_type": "1", "profile_status_id": status_id, "is_moved_to_trash": False, **kw}


# ---- OAuth ----
def test_token_refresh_once_cached_and_header_shape(tmp_path):
    api = FakeAPI({("GET", f"/devices/{DEV}/apps"): {"installed_apps": [{"identifier": "com.example.a"}]}})
    me = make(tmp_path, api)
    me.installed_apps()
    me.installed_apps()
    token_calls = [c for c in api.calls if c[1] == TOKEN_URL]
    assert len(token_calls) == 1
    form = urllib.parse.parse_qs(token_calls[0][3].decode())
    assert form == {"grant_type": ["refresh_token"], "refresh_token": ["rtoken-XYZ"], "client_id": ["cid-XYZ"],
                    "client_secret": ["csecret-XYZ"]}
    assert token_calls[0][0] == "POST"
    api_hdrs = [h for m, u, h, b in api.calls if u != TOKEN_URL]
    assert all(h["Authorization"] == "Zoho-oauthtoken tok-1" for h in api_hdrs)
    # the secret never travels in a URL
    assert not any("XYZ" in u for _, u, _, _ in api.calls)


def test_token_expiry_and_401_force_refresh(tmp_path):
    now = [1000.0]
    seen = []

    def apps(body, q):
        seen.append(api.calls[-1][2]["Authorization"])
        return (401, {"error_code": "INVALID_TOKEN"}) if len(seen) == 1 else \
            {"installed_apps": [{"identifier": "com.example.a"}]}
    api = FakeAPI({("GET", f"/devices/{DEV}/apps"): apps})
    me = make(tmp_path, api, clock=lambda: now[0])
    assert me.installed_apps() == {"com.example.a"}
    assert seen == ["Zoho-oauthtoken tok-1", "Zoho-oauthtoken tok-2"]
    now[0] += 3600  # expired: the next call refreshes first
    me.installed_apps()
    assert seen[-1] == "Zoho-oauthtoken tok-3"


def test_token_failure_message_has_no_secret(tmp_path):
    def transport(method, url, headers, body):
        return 400, json.dumps({"error": "invalid_client", "echo": "rtoken-XYZ csecret-XYZ"}).encode()
    me = make(tmp_path, transport)
    with pytest.raises(mdm.MDMError) as exc:
        me.installed_apps()
    assert "invalid_client" in str(exc.value) and "XYZ" not in str(exc.value) and "XYZ" not in repr(me)


@pytest.mark.parametrize("item", [b"not json", b'{"client_id": "x"}',
                                  json.dumps({**SECRET, "accounts": "https://evil.example"}).encode()])
def test_bad_keychain_item_is_unavailable(tmp_path, item):
    me = mdm.ManageEngineMDM(device_id=DEV, state_file=tmp_path / "s.json", transport=FakeAPI(),
                             read_secret=lambda: item)
    with pytest.raises(mdm.MDMUnavailable):
        me.installed_apps()


def test_http_error_message_has_no_body_or_token(tmp_path):
    api = FakeAPI({("GET", f"/devices/{DEV}/apps"): (500, {"error_code": "COM0004", "message": "tok-1 leaked"})})
    with pytest.raises(mdm.MDMError) as exc:
        make(tmp_path, api).installed_apps()
    assert "HTTP 500 COM0004" in str(exc.value) and "tok-" not in str(exc.value)


# ---- installed apps ----
def test_installed_apps_parsing_and_paging(tmp_path):
    def apps(body, q):
        if q.get("offset") == ["200"]:
            return {"installed_apps": [{"identifier": "io.tailscale.ipn.ios"}]}
        return {"installed_apps": [{"identifier": "com.example.a"}, {"identifier": "bad id;rm"}, {"app_name": "x"}],
                "paging": {"next": f"https://mdm.manageengine.com/api/v1/mdm/devices/{DEV}/apps?limit=200&offset=200"}}
    me = make(tmp_path, FakeAPI({("GET", f"/devices/{DEV}/apps"): apps}))
    assert me.installed_apps() == {"com.example.a", "io.tailscale.ipn.ios"}


def test_paging_link_to_other_host_refused(tmp_path):
    api = FakeAPI({("GET", f"/devices/{DEV}/apps"): {"installed_apps": [{"identifier": "a.b"}],
                                                       "paging": {"next": "https://evil.example/x?offset=1"}}})
    with pytest.raises(mdm.MDMError, match="paging"):
        make(tmp_path, api).installed_apps()


def test_empty_inventory_is_an_error_not_an_empty_set(tmp_path):
    # Live 2026-11-14: installed_apps came back empty before any app scan. An empty snapshot would make the
    # tick block every app a later scan finds, so it must fail closed.
    api = FakeAPI({("GET", f"/devices/{DEV}/apps"): {"installed_apps": [], "apps": [{"identifier": "x.y"}]}})
    with pytest.raises(mdm.MDMError, match="inventory is empty"):
        make(tmp_path, api).installed_apps()


# ---- lock / unlock ----
def lock_routes(item_value, status_id="110", items=(ITEM,), removal="false"):
    put_bodies = []
    item = {"payload_id": ITEM, mdm.INSTALL_KEY: item_value, "allow_vpn_creation": True,
            **{key: str(value).lower() for key, value in mdm.CONTENT_RESTRICTIONS.items()}}
    if removal is not None:
        item[mdm.REMOVAL_KEY] = removal

    def put(body, q):
        put_bodies.append(body)
        item.update(body)
        return item
    routes = {
        ("GET", "/profiles"): {"profiles": [profile(status_id)]},
        ("GET", f"/profiles/{PID}"): profile(status_id),
        ("GET", f"/profiles/{PID}/payloads/restrictionspolicy"): {"payload_name": "restrictionspolicy",
                                                                   "payloaditems": list(items)},
        ("GET", f"/profiles/{PID}/payloads/restrictionspolicy/payloaditems/{ITEM}"): lambda b, q: dict(item),
        ("PUT", f"/profiles/{PID}/payloads/restrictionspolicy/payloaditems/{ITEM}"): put,
        ("POST", f"/profiles/{PID}/publish"): (204, None),
        ("POST", f"/devices/{DEV}/profiles"): (204, None),
    }
    return routes, put_bodies


def test_lock_modifies_publishes_and_associates_own_profile(tmp_path):
    routes, puts = lock_routes(True)
    api = FakeAPI(routes)
    me = make(tmp_path, api)
    me.lock()
    calls = api.api_calls()
    assert puts == [{mdm.INSTALL_KEY: False, "allow_vpn_creation": True,
                     **mdm.CONTENT_RESTRICTIONS,
                     mdm.REMOVAL_KEY: False}]  # no payload_id
    assert ("POST", f"/profiles/{PID}/publish", None) in calls
    assert calls[-1] == ("POST", f"/devices/{DEV}/profiles", {"profile_ids": [int(PID)]})
    state = json.loads((tmp_path / "mdm-state.json").read_text())["devices"][DEV]
    assert state["profile_id"] == PID and state["payload_id"] == ITEM and state["allow_installs"] is False
    assert all(m != "DELETE" for m, _, _ in calls)


@pytest.mark.parametrize("operation", ["lock", "unlock", "block_app", "draft"])
def test_mdm_transaction_lock_covers_read_api_and_nested_saves(tmp_path, monkeypatch, operation):
    routes, _ = lock_routes(True)
    routes.update({
        ("GET", "/blacklist/apps"): {"apps": [{"identifier": "com.extra.app", "platform": "1", "appgroupid": "99"}]},
        ("POST", "/blacklist/devices"): (204, None),
    })
    api, phases = FakeAPI(routes), []
    me = make(tmp_path, api)

    def assert_locked(phase):
        with me.state_file.with_suffix(".json.lock").open("a") as probe:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        phases.append(phase)

    real_load, real_save = me._load, me._save

    def load():
        assert_locked("read")
        return real_load()

    def save(state):
        assert_locked("save")
        real_save(state)  # must not deadlock when the transaction already owns the file lock

    def transport(*args):
        assert_locked("api")
        return api(*args)

    monkeypatch.setattr(me, "_load", load)
    monkeypatch.setattr(me, "_save", save)
    monkeypatch.setattr(me, "_transport", transport)
    if operation == "unlock":
        me.unlock(minutes=15)
    elif operation == "block_app":
        me.block_app("com.extra.app")
    else:
        getattr(me, operation)()
    assert phases[0] == "read" and {"read", "api", "save"} <= set(phases)
    with me.state_file.with_suffix(".json.lock").open("a") as probe:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released after the complete operation


def test_unlock_sets_allowed_and_lock_is_idempotent(tmp_path):
    routes, puts = lock_routes(False)
    api = FakeAPI(routes)
    me = make(tmp_path, api)
    me.unlock(minutes=15)
    assert puts[-1][mdm.INSTALL_KEY] is True
    n = len(puts)
    me.unlock(minutes=15)  # already allowed and published: no PUT, no publish, association re-sent
    assert len(puts) == n
    last = api.api_calls()[-3:]
    assert ("POST", f"/profiles/{PID}/publish", None) not in last
    assert last[-1] == ("POST", f"/devices/{DEV}/profiles", {"profile_ids": [int(PID)]})


def test_unpublished_profile_is_published_even_without_change(tmp_path):
    routes, puts = lock_routes(False, status_id="1")
    api = FakeAPI(routes)
    make(tmp_path, api).lock()
    assert puts == [] and ("POST", f"/profiles/{PID}/publish", None) in api.api_calls()


def test_first_lock_creates_profile_and_payload(tmp_path):
    created = {}

    def create(body, q):
        created["profile"] = body
        return {**profile("1"), "profile_id": PID}

    def payload_list(body, q):
        return {"payloaditems": [ITEM]} if "payload" in created else (404, {"error_code": "COM0008"})

    def add_payload(body, q):
        created["payload"] = body
        return {**body, "payload_id": ITEM}
    api = FakeAPI({
        ("GET", "/profiles"): {"profiles": [{"profile_id": "99", "profile_name": mdm.PROFILE_NAME,
                                             "profile_description": "someone else's", "platform_type": "1"}]},
        ("POST", "/profiles"): create,
        ("GET", f"/profiles/{PID}/payloads/restrictionspolicy"): payload_list,
        ("POST", f"/profiles/{PID}/payloads/restrictionspolicy"): add_payload,
        ("POST", f"/profiles/{PID}/publish"): (204, None),
        ("POST", f"/devices/{DEV}/profiles"): (204, None),
    })
    make(tmp_path, api).lock()
    assert created["profile"] == {"profile_name": mdm.PROFILE_NAME, "profile_description": mdm.PROFILE_MARK,
                                  "platform_type": 1, "scope": 0}
    assert created["payload"] == {mdm.INSTALL_KEY: False, mdm.REMOVAL_KEY: False,
                                  **mdm.CONTENT_RESTRICTIONS}
    assert not any("/profiles/99" in p for _, p, _ in api.api_calls())  # same name, not ours: untouched


def test_adopts_own_profile_from_list_with_string_booleans(tmp_path):
    # Live 2026-11-14: the list returns is_moved_to_trash as "false" (a string), the detail as false.
    routes, puts = lock_routes(True)
    routes[("GET", "/profiles")] = {"profiles": [profile(is_moved_to_trash="false")]}
    api = FakeAPI(routes)
    make(tmp_path, api).lock()
    assert json.loads((tmp_path / "mdm-state.json").read_text())["devices"][DEV]["profile_id"] == PID and puts


def test_string_install_value_is_compared_as_boolean(tmp_path):
    routes, puts = lock_routes("false")
    make(tmp_path, FakeAPI(routes)).lock()
    assert puts == []  # already "false": nothing to change


def test_content_restriction_drift_puts_every_required_key(tmp_path):
    routes, puts = lock_routes("false")
    original = routes[("GET", f"/profiles/{PID}/payloads/restrictionspolicy/payloaditems/{ITEM}")]

    def drift(body, query):
        item = original(body, query)
        item["allow_news"] = "true"
        return item

    routes[("GET", f"/profiles/{PID}/payloads/restrictionspolicy/payloaditems/{ITEM}")] = drift
    make(tmp_path, FakeAPI(routes)).lock()
    assert len(puts) == 1
    assert all(puts[0][key] == value for key, value in mdm.CONTENT_RESTRICTIONS.items())


def test_install_window_keeps_content_restrictions_tight(tmp_path):
    routes, puts = lock_routes("false")
    routes[("GET", f"/profiles/{PID}/payloads/restrictionspolicy/payloaditems/{ITEM}")] = {
        "payload_id": ITEM, mdm.INSTALL_KEY: "false", mdm.REMOVAL_KEY: "false",
        **{key: str(value).lower() for key, value in mdm.CONTENT_RESTRICTIONS.items()},
        "allow_itunes": "true",
    }
    make(tmp_path, FakeAPI(routes)).unlock(15)
    assert puts[0][mdm.INSTALL_KEY] is True
    assert all(puts[0][key] == value for key, value in mdm.CONTENT_RESTRICTIONS.items())


@pytest.mark.parametrize("trash", [True, "true", "TRUE"])
def test_trashed_own_profile_in_list_is_not_adopted(tmp_path, trash):
    api = FakeAPI({("GET", "/profiles"): {"profiles": [profile(is_moved_to_trash=trash)]}})
    assert make(tmp_path, api)._owned_profile({"blocked": {}}, create=False) is None


def test_trashed_or_renamed_own_profile_stops(tmp_path):
    (tmp_path / "mdm-state.json").write_text(json.dumps({"profile_id": PID}))
    api = FakeAPI({("GET", f"/profiles/{PID}"): profile(is_moved_to_trash=True)})
    with pytest.raises(mdm.MDMError, match="trashed or renamed"):
        make(tmp_path, api).lock()
    assert [m for m, _, _ in api.api_calls()] == ["GET"]


@pytest.mark.parametrize("minutes", [0, 121, "15", None])
def test_unlock_minutes_validated(tmp_path, minutes):
    with pytest.raises(ValueError):
        make(tmp_path, FakeAPI()).unlock(minutes)


def test_draft_never_publishes_or_associates(tmp_path):
    routes, puts = lock_routes(True, status_id="1")
    api = FakeAPI(routes)
    out = make(tmp_path, api).draft()
    assert out[mdm.INSTALL_KEY] is True and puts == []
    assert not any(p.endswith("/publish") or p.startswith("/devices") for _, p, _ in api.api_calls())


# ---- block_app ----
def block_routes(available, created_gid="555"):
    posted = {"apps": [], "devices": []}

    def add(body, q):
        posted["apps"].append(body)
        return {"apps": [{**body["apps"][0], "appgroupid": created_gid}]}

    def to_devices(body, q):
        posted["devices"].append(body)
        return {"resource_ids": body["resource_ids"]}
    return {("GET", "/blacklist/apps"): {"apps": available}, ("POST", "/blacklist/apps"): add,
            ("POST", "/blacklist/devices"): to_devices}, posted


def test_block_app_new_bundle_creates_group_then_blocks_on_device(tmp_path):
    routes, posted = block_routes([{"identifier": "com.apple.camera", "appgroupid": "1", "platform": "1"}])
    me = make(tmp_path, FakeAPI(routes))
    assert me.block_app("com.example.game") is True
    assert posted["apps"] == [{"apps": [{"identifier": "com.example.game", "platform": 1,
                                         "appname": "com.example.game"}]}]
    assert posted["devices"] == [{"resource_ids": [int(DEV)], "app_group_ids": [555]}]


def test_block_app_reuses_inventory_group_and_merges_state(tmp_path):
    (tmp_path / "mdm-state.json").write_text(json.dumps({"profile_id": PID, "blocked": {"com.old.app": "7"}}))
    routes, posted = block_routes([{"identifier": "com.Example.Game", "appgroupid": "42", "platform": "1"},
                                   {"identifier": "com.example.game", "appgroupid": "43", "platform": "3"}])
    me = make(tmp_path, FakeAPI(routes))
    me.block_app("com.example.game")
    me.block_app("com.example.game")  # second time: from state, no lookup, same group
    assert posted["apps"] == []
    assert posted["devices"] == [{"resource_ids": [int(DEV)], "app_group_ids": [42]}] * 2
    state = json.loads((tmp_path / "mdm-state.json").read_text())["devices"][DEV]
    assert state["blocked"] == {"com.old.app": "7", "com.example.game": "42"} and state["profile_id"] == PID


@pytest.mark.parametrize("bundle", ["com.apple.mobilesafari", "io.tailscale.ipn.ios", "com.example.companion",
                                    "com.manageengine.mdm.iosagent"])
def test_block_app_never_blocks_filter_or_system_apps(tmp_path, bundle):
    api = FakeAPI()
    assert make(tmp_path, api).block_app(bundle) is False
    assert api.calls == []


@pytest.mark.parametrize("bundle", ["", "a b", "x;rm -rf", "../x", "a" * 300, None])
def test_block_app_bad_bundle(tmp_path, bundle):
    with pytest.raises(ValueError):
        make(tmp_path, FakeAPI()).block_app(bundle)


# ---- safety guards ----
@pytest.mark.parametrize("method,path", [
    ("POST", f"/devices/{DEV}/actions/lock"), ("POST", f"/devices/{DEV}/actions/erase"),
    ("POST", f"/devices/{DEV}/actions/corporate_wipe"), ("POST", "/actions/shutdown"),
    ("DELETE", f"/devices/{DEV}/profiles"), ("DELETE", "/profiles"), ("DELETE", "/blacklist/devices"),
    ("PUT", f"/devices/{DEV}"), ("PUT", f"/profiles/{PID}/update_all"),
    ("POST", f"/profiles/{PID}/payloads/passcodepolicy"), ("GET", "/devices/1/../../actions"),
])
def test_disallowed_calls_never_leave_the_process(tmp_path, method, path):
    api = FakeAPI()
    with pytest.raises(mdm.MDMError, match="refused"):
        make(tmp_path, api)._call(method, path)
    assert api.calls == []


def test_allowlist_has_no_destructive_routes():
    assert all(m in ("GET", "POST", "PUT") for m, _ in mdm._ALLOWED)
    for _, p in mdm._ALLOWED:
        assert ("action" not in p or p == r"/devices/{id}/actions/scan") and "update_all" not in p and "users" not in p


def test_module_source_never_names_destructive_endpoints():
    src = Path(mdm.__file__).read_text().lower()
    for word in ("wipe", "erase", "shutdown", "restart", "deprovision", "lost_mode", "lostmode",
                 "lock_device", "remove_device", "disassociate", "clear_passcode", "\"delete\"", "'delete'"):
        assert word not in src, word
    assert re.findall(r"/actions/[a-z_]+", src) == ["/actions/scan"] * len(re.findall(r"/actions/[a-z_]+", src))
    urls = re.findall(r"https?://[^\s\"')]+", src)
    hosts = ("https://mdm.manageengine.com/", "https://accounts\\.zoho\\.")
    assert urls and all(u.startswith(hosts) for u in urls), urls


def test_redirects_are_not_followed():
    assert mdm._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil.example") is None


def test_cli_rejects_unknown_command(capsys):
    assert mdm.main(["wipe"]) == 2 and mdm.main([]) == 2


@pytest.mark.parametrize("removal", [None, "true", True])
def test_lock_also_locks_app_deleting_when_installs_already_closed(tmp_path, removal):
    routes, puts = lock_routes(False, removal=removal)
    api = FakeAPI(routes)
    make(tmp_path, api).lock()
    assert puts and puts[-1][mdm.REMOVAL_KEY] is False and puts[-1][mdm.INSTALL_KEY] is False


def test_install_window_keeps_app_deleting_locked(tmp_path):
    routes, puts = lock_routes(False)
    api = FakeAPI(routes)
    make(tmp_path, api).unlock(15)
    assert puts[-1][mdm.INSTALL_KEY] is True and puts[-1][mdm.REMOVAL_KEY] is False



class MemCache:
    def __init__(self, value=None):
        self.value, self.saved = value, []

    def load(self):
        return self.value

    def save(self, token, until):
        self.saved.append((token, until))
        self.value = (token, until)


def test_token_cache_shared_between_processes(tmp_path):
    route = {("GET", f"/devices/{DEV}/apps"): {"installed_apps": [{"identifier": "com.example.a"}]}}
    cache, api = MemCache(), FakeAPI(route)
    kw = dict(device_id=DEV, state_file=tmp_path / "s.json", read_secret=lambda: json.dumps(SECRET).encode(),
              clock=lambda: 1000.0, token_cache=cache)
    mdm.ManageEngineMDM(transport=api, **kw).installed_apps()
    mdm.ManageEngineMDM(transport=api, **kw).installed_apps()  # a second process reuses the cached token
    assert len([c for c in api.calls if c[1] == TOKEN_URL]) == 1
    assert cache.saved == [("tok-1", 1000.0 + 3600 - 60)]


def test_expired_cached_token_is_refreshed(tmp_path):
    api = FakeAPI({("GET", f"/devices/{DEV}/apps"): {"installed_apps": [{"identifier": "com.example.a"}]}})
    me = mdm.ManageEngineMDM(device_id=DEV, state_file=tmp_path / "s.json", transport=api,
                             read_secret=lambda: json.dumps(SECRET).encode(), clock=lambda: 5000.0,
                             token_cache=MemCache(("old", 4000.0)))
    me.installed_apps()
    assert [h["Authorization"] for m, u, h, b in api.calls if u != TOKEN_URL] == ["Zoho-oauthtoken tok-1"]


def test_tests_never_touch_the_real_keychain(tmp_path):
    assert make(tmp_path, FakeAPI())._token_cache is None


class FleetAPI(FakeAPI):
    """Model the important provider behavior: publishing a payload affects every associated device."""
    def __init__(self):
        self.items = {PID: {mdm.INSTALL_KEY: True, mdm.REMOVAL_KEY: False}}
        self.names = {PID: mdm.PROFILE_NAME}
        self.associations = {}
        routes, self.puts = lock_routes(True)
        routes[("GET", "/profiles")] = lambda b, q: {
            "profiles": [profile(profile_id=pid, profile_name=name) for pid, name in self.names.items()]}

        def create(body, query):
            pid = "222"
            self.names[pid] = body["profile_name"]
            return {"profile_id": pid}
        routes[("POST", "/profiles")] = create
        for pid, item_id in ((PID, ITEM), ("222", "333")):
            routes[("GET", f"/profiles/{pid}")] = lambda b, q, pid=pid: profile(
                profile_id=pid, profile_name=self.names[pid])
            path = f"/profiles/{pid}/payloads/restrictionspolicy"
            routes[("GET", path)] = lambda b, q, pid=pid, item_id=item_id: {
                "payloaditems": [item_id] if pid in self.items else []}
            routes[("POST", path)] = lambda b, q, pid=pid: self.items.setdefault(pid, dict(b))
            routes[("GET", f"{path}/payloaditems/{item_id}")] = lambda b, q, pid=pid: dict(self.items[pid])

            def put(body, query, pid=pid):
                self.items[pid].update(body)
                return dict(body)
            routes[("PUT", f"{path}/payloaditems/{item_id}")] = put
            routes[("POST", f"/profiles/{pid}/publish")] = (204, None)
        for did in (mdm.IPHONE, mdm.IPAD):
            def associate(body, query, did=did):
                self.associations[did] = str(body["profile_ids"][0])
                return {}
            routes[("POST", f"/devices/{did}/profiles")] = associate
        super().__init__(routes)

    def allows(self, did):
        return self.items[self.associations[did]][mdm.INSTALL_KEY]


def test_two_device_profiles_lock_independently_and_unlock_is_isolated(tmp_path):
    api = FleetAPI()
    me = mdm.ManageEngineMDM(device_ids=[mdm.IPHONE, mdm.IPAD], state_file=tmp_path / "s.json",
                             transport=api, read_secret=lambda: json.dumps(SECRET).encode())
    phone, pad = me.for_device("iphone"), me.for_device("ipad")
    phone.lock()
    pad.lock()
    assert api.associations == {mdm.IPHONE: PID, mdm.IPAD: "222"}
    assert api.allows(mdm.IPHONE) is False and api.allows(mdm.IPAD) is False
    pad.unlock(15)
    assert api.allows(mdm.IPAD) is True and api.allows(mdm.IPHONE) is False
    pad.lock()
    phone.unlock(15)
    assert api.allows(mdm.IPHONE) is True and api.allows(mdm.IPAD) is False
    assert all(item[mdm.REMOVAL_KEY] is False for item in api.items.values())
    saved = json.loads((tmp_path / "s.json").read_text())["devices"]
    assert saved[mdm.IPHONE]["profile_id"] != saved[mdm.IPAD]["profile_id"]


def test_legacy_mdm_state_is_owned_by_phone_even_when_ipad_runs_first(tmp_path):
    path = tmp_path / "s.json"
    old = {"profile_id": PID, "payload_id": ITEM, "blocked": {"com.old.app": "55"}, "changed_at": 123}
    path.write_text(json.dumps(old))
    api = FleetAPI()
    # Even the explicit one-device CLI override must not reuse the iPhone's profile.
    pad = mdm.ManageEngineMDM(device_id=mdm.IPAD, state_file=path, transport=api,
                              read_secret=lambda: json.dumps(SECRET).encode())
    pad.lock()
    saved = json.loads(path.read_text())["devices"]
    assert saved[mdm.IPHONE] == old
    assert saved[mdm.IPAD]["profile_id"] == "222"
    assert saved[mdm.IPAD]["blocked"] == {}
    assert api.items[PID][mdm.INSTALL_KEY] is True  # no edit of the original profile


def test_scan_inventory_and_blacklist_target_only_selected_device(tmp_path):
    routes, posted = block_routes([{"identifier": "com.example.game", "appgroupid": "42", "platform": "1"}])
    for did in (mdm.IPHONE, mdm.IPAD):
        routes[("POST", f"/devices/{did}/actions/scan")] = {}
        routes[("GET", f"/devices/{did}/apps")] = {"installed_apps": [{"identifier": f"com.app.{did}"}]}
    api = FakeAPI(routes)
    me = mdm.ManageEngineMDM(device_ids=[mdm.IPHONE, mdm.IPAD], state_file=tmp_path / "s.json",
                             transport=api, read_secret=lambda: json.dumps(SECRET).encode())
    for did in me.device_ids:
        target = me.for_device(did)
        target.scan()
        assert target.installed_apps() == {f"com.app.{did}"}
        target.block_app("com.example.game")
    assert posted["devices"] == [{"resource_ids": [int(did)], "app_group_ids": [42]}
                                  for did in (mdm.IPHONE, mdm.IPAD)]
    saved = json.loads((tmp_path / "s.json").read_text())["devices"]
    assert all(saved[did]["blocked"] == {"com.example.game": "42"} for did in me.device_ids)


def test_device_config_legacy_compatibility_and_aliases(monkeypatch):
    from aifilter.config import Config
    monkeypatch.setattr("aifilter.config.load", lambda: Config({"mdm": {"device_id": mdm.IPHONE}}))
    assert mdm.configured_device_ids() == (mdm.IPHONE,)
    monkeypatch.setattr("aifilter.config.load", lambda: Config({"mdm": {
        "device_id": mdm.IPHONE, "device_ids": [mdm.IPAD, mdm.IPHONE]}}))
    me = mdm.ManageEngineMDM()
    assert me.device_id == int(mdm.IPHONE)  # ordering must not change the request default
    assert mdm.resolve_device(me, "ipad") == mdm.IPAD
    assert mdm.resolve_device(me, "iphone") == mdm.IPHONE
    assert mdm.resolve_device(me, mdm.IPAD) == mdm.IPAD
    with pytest.raises(ValueError, match="not configured"):
        mdm.resolve_device(me, "999")


def test_cli_lock_continues_after_one_device_fails(monkeypatch, capsys):
    class Fleet:
        device_ids = (mdm.IPHONE, mdm.IPAD)
        calls = []

        def for_device(self, did):
            class Device:
                def lock(self):
                    Fleet.calls.append(did)
                    if did == mdm.IPHONE:
                        raise mdm.MDMError("API unreadable")
            return Device()
    monkeypatch.setattr(mdm, "ManageEngineMDM", lambda **kw: Fleet())
    assert mdm.main(["lock"]) == 1
    assert Fleet.calls == [mdm.IPHONE, mdm.IPAD]
    result = json.loads(capsys.readouterr().out)
    assert "error" in result[mdm.IPHONE] and result[mdm.IPAD] == {"lock": "pushed"}


def test_concurrent_device_state_writes_preserve_both_histories(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    path, start = tmp_path / "s.json", Barrier(2)
    old = {"history": [{"bundle": "com.old.app", "status": "approved"}], "window": None}
    path.write_text(json.dumps(old))

    def write(did):
        start.wait(timeout=5)
        record = dict(old) if did == mdm.IPHONE else {"history": [], "window": None}
        record["history"] = record["history"] + [{"bundle": f"com.new.{did}"}]
        mdm.save_device_state(path, did, record, mdm.IPHONE)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(write, (mdm.IPHONE, mdm.IPAD)))
    saved = json.loads(path.read_text())["devices"]
    assert saved[mdm.IPHONE]["history"] == old["history"] + [{"bundle": f"com.new.{mdm.IPHONE}"}]
    assert saved[mdm.IPAD]["history"] == [{"bundle": f"com.new.{mdm.IPAD}"}]
