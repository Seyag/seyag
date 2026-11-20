import json

from scripts import selftest


def good_dns(name, port):
    if name in selftest.DNS_BLOCKED:
        return {"0.0.0.0"}, set()
    if name in selftest.DNS_SAFE:
        return {"216.239.38.120"}, {selftest.DNS_SAFE[name]}
    return {"17.0.0.1"}, set()


def good_get(url, port, cacert, timeout=20):
    if url in selftest.PAGE_BLOCKED:
        return "403", "<a href='/__ai-filter/appeal'>"
    return "200", "ok"


def test_all_cases_pass_on_a_working_filter():
    assert selftest.run_cases(8118, 53, "ca", dns=good_dns, get=good_get, connect=lambda u, p: "403") == []


def test_each_broken_mechanism_is_named():
    failed = selftest.run_cases(8118, 53, "ca", dns=lambda n, p: ({"1.2.3.4"}, set()), get=lambda *a: ("200", "page"), connect=lambda u, p: "000")
    assert any(f.startswith("dns-block") for f in failed)
    assert any(f.startswith("dns-safe") for f in failed)
    assert any(f.startswith("page-block") for f in failed)
    assert "ip-literal refused" in failed
    assert not any(f.startswith("page-open") or f.startswith("dns-open") for f in failed)


def test_a_block_page_from_someone_else_does_not_count():
    failed = selftest.run_cases(8118, 53, "ca", dns=good_dns,
                                get=lambda url, *a: ("403", "forbidden") if url in selftest.PAGE_BLOCKED else good_get(url, *a), connect=lambda u, p: "403")
    assert [f for f in failed if f.startswith("page-block")] and len(failed) == len(selftest.PAGE_BLOCKED)


def test_crashing_probe_is_a_failed_case():
    def boom(*a):
        raise OSError("down")
    failed = selftest.run_cases(8118, 53, "ca", dns=boom, get=good_get, connect=lambda u, p: "403")
    assert failed and all("OSError" in f for f in failed)


def test_alert_only_when_the_failing_set_changes(tmp_path):
    state, sent = tmp_path / "s.json", []
    selftest.report(["a"], state, sent.append, retried=True)
    selftest.report(["a"], state, sent.append, retried=True)
    assert len(sent) == 1 and "\na" in sent[0]
    selftest.report([], state, sent.append, retried=False)
    selftest.report([], state, sent.append, retried=False)
    assert len(sent) == 2 and json.loads(state.read_text())["failed"] == []
