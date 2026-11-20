import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aifilter import policysign as ps

DAY = 1_800_000_000.0 - (1_800_000_000.0 % 86400) + 9 * 3600  # 11:00 UTC, 13:00-14:00 in Israel (not night)


class MemKey:
    def __init__(self):
        self.seed = None

    def load(self):
        return self.seed

    def create(self, seed):
        self.seed = seed


def doc_ok(doc, payload):
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(doc["publicKey"]))
    body = base64.b64decode(doc["payload"])
    pub.verify(base64.b64decode(doc["signature"]), body)  # raises if bad
    assert json.loads(body) == payload


def test_public_key_created_once_and_signing_verifies(tmp_path):
    k = MemKey()
    pk = ps.public_key(k)
    assert len(base64.b64decode(pk)) == 32 and ps.public_key(k) == pk
    p = {"version": 1, "locked": True, "rules": {}}
    doc = ps.sign(tmp_path / "s.json", p, k, now=DAY)
    doc_ok(doc, p)
    assert doc["publicKey"] == pk


def test_no_key_never_signs(tmp_path):
    with pytest.raises(ps.PolicyError):
        ps.sign(tmp_path / "s.json", {"version": 1, "locked": True, "rules": {}}, MemKey(), now=DAY)


def test_tightening_signs_at_once_even_at_night(tmp_path):
    k, f = MemKey(), tmp_path / "s.json"
    ps.public_key(k)
    night = DAY + 12 * 3600  # 01:00 Israel
    ps.sign(f, {"version": 1, "locked": True, "rules": {}}, k, now=night)
    ps.sign(f, {"version": 2, "locked": True, "rules": {"search": True}}, k, now=night)


def tap(rid, asked, answered, choice="yes", did="d1", routine=False):
    return {"id": did, "state": "answered", "choice": choice, "routine": routine,
            "title": f"Loosen the companion filter (request {rid})?", "created": asked, "closed": answered}


def test_loosening_needs_the_owners_tap_24h_later_and_not_at_night(tmp_path):
    k, f = MemKey(), tmp_path / "s.json"
    ps.public_key(k)
    ps.sign(f, {"version": 1, "locked": True, "rules": {}}, k, now=DAY)
    loose = {"version": 2, "locked": True, "rules": {"stories": False}}
    with pytest.raises(ps.PolicyError, match="rule 7"):
        ps.sign(f, loose, k, now=DAY)
    r = ps.request(f, "turn stories off", ["stories"], now=DAY)
    later = DAY + 86400 + 60
    with pytest.raises(ps.PolicyError, match="24 hours"):
        ps.confirm(f, r["id"], tap(r["id"], DAY + 3600, DAY + 3700))
    with pytest.raises(ps.PolicyError, match="night"):
        ps.confirm(f, r["id"], tap(r["id"], later, DAY + 86400 + 12 * 3600))
    for bad in (tap(r["id"], later, later + 5, choice="no"), tap(r["id"], later, later + 5, routine=True),
                tap("zzzz", later, later + 5)):
        with pytest.raises(ps.PolicyError):
            ps.confirm(f, r["id"], bad)
    ps.confirm(f, r["id"], tap(r["id"], later, later + 5))
    with pytest.raises(ps.PolicyError, match="night"):
        ps.sign(f, loose, k, request_id=r["id"], now=DAY + 86400 + 12 * 3600)
    ps.sign(f, loose, k, request_id=r["id"], now=later + 10)
    with pytest.raises(ps.PolicyError):  # a confirmation is used once
        ps.sign(f, {"version": 3, "locked": True, "rules": {"stories": False, "search": False}}, k,
                request_id=r["id"], now=later + 20)


def test_confirmed_request_cannot_loosen_anything_else(tmp_path):
    k, f = MemKey(), tmp_path / "s.json"
    ps.public_key(k)
    ps.sign(f, {"version": 1, "locked": True, "rules": {}}, k, now=DAY)
    r = ps.request(f, "stories off", ["stories"], now=DAY)
    ps.confirm(f, r["id"], tap(r["id"], DAY + 86400, DAY + 86400 + 5))
    with pytest.raises(ps.PolicyError, match="rule 7"):  # an unlock is outside the request's scope
        ps.sign(f, {"version": 2, "locked": False, "rules": {}}, k, request_id=r["id"], now=DAY + 86400 + 10)


def test_one_decision_confirms_one_request(tmp_path):
    f = tmp_path / "s.json"
    r1 = ps.request(f, "a", ["stories"], now=DAY)
    r2 = ps.request(f, "b", ["search"], now=DAY)
    t = tap(r1["id"], DAY + 86400, DAY + 86400 + 5)
    ps.confirm(f, r1["id"], t)
    with pytest.raises(ps.PolicyError):
        ps.confirm(f, r2["id"], dict(t, title=f"{r1['id']} {r2['id']}"))


def test_fresh_state_is_strictest_and_unreadable_state_refuses(tmp_path):
    k, f = MemKey(), tmp_path / "s.json"
    ps.public_key(k)
    with pytest.raises(ps.PolicyError, match="rule 7"):  # no history: an unlocked first document is a loosening
        ps.sign(f, {"version": 1, "locked": False, "rules": {}}, k, now=DAY)
    f.write_text("{broken")
    with pytest.raises(ps.PolicyError, match="unreadable"):
        ps.sign(f, {"version": 1, "locked": True, "rules": {}}, k, now=DAY)


def test_version_must_increase_and_payload_is_strict(tmp_path):
    k, f = MemKey(), tmp_path / "s.json"
    ps.public_key(k)
    ps.sign(f, {"version": 5, "locked": True, "rules": {}}, k, now=DAY)
    for bad in ({"version": 5, "locked": True, "rules": {}}, {"version": 6, "locked": True, "rules": {"nope": True}},
                {"version": 6, "locked": "yes", "rules": {}}, {"version": 6, "locked": True, "rules": {}, "x": 1}):
        with pytest.raises(ps.PolicyError):
            ps.sign(f, bad, k, now=DAY)


def test_unlock_is_a_loosening(tmp_path):
    assert ps.loosenings({"version": 1, "locked": True, "rules": {}}, {"version": 2, "locked": False, "rules": {}}) \
        == ["locked"]
    assert ps.loosenings(None, {"version": 1, "locked": False, "rules": {"search": True}}) == ["locked"]
    assert ps.loosenings(None, {"version": 1, "locked": True, "rules": {"search": False}}) == ["search"]


def signed_record(key, obj):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    body = json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode()
    pub = base64.b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
    return {"answer_sig": {"payload": base64.b64encode(body).decode(),
                           "signature": base64.b64encode(key.sign(body)).decode(), "key": pub}}, pub


def answer(**kw):
    obj = {"v": 1, "kind": "companion-decision-answer", "id": "d9", "title": "loosen abc", "detail": "",
           "choice": "yes", "note": "", "created": 100.0, "closed": 200.0, "routine": False, "by": 42, "via": "panel"}
    obj.update(kw)
    return obj


def test_signed_answer_verifies_and_uses_only_signed_fields():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    rec, pub = signed_record(k, answer())
    rec.update(choice="no", title="forged")  # unsigned fields are ignored
    a = ps.verified_answer(rec, pub, 42)
    assert a["choice"] == "yes" and a["title"] == "loosen abc" and a["id"] == "d9"


def test_signed_answer_refusals():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    rec, pub = signed_record(k, answer())
    bad = [({}, pub, 42), (rec, "", 42), (rec, pub, 0), (rec, pub, 43),
           (signed_record(other, answer())[0], pub, 42),
           (signed_record(k, answer(via="widget"))[0], pub, 42),
           (signed_record(k, answer(routine=True))[0], pub, 42),
           (signed_record(k, answer(kind="x"))[0], pub, 42)]
    tampered = json.loads(json.dumps(rec))
    tampered["answer_sig"]["payload"] = base64.b64encode(b'{"v":1}').decode()
    bad.append((tampered, pub, 42))
    for r, key, owner in bad:
        with pytest.raises(ps.PolicyError):
            ps.verified_answer(r, key, owner)
