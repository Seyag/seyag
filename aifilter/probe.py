"""Marker that proves a blocked request is one of the filter's own health probes.

The watchdog and the daily self-test ask for blocked sites on purpose. Those requests carry a
random per-install token (a private DNS option, or an HTTP header), so only they stay out of the
family report. Anything without the token, real browsing from this Mac included, is reported.
"""
from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path

from dnslib import DNSRecord, EDNS0, EDNSOption, QTYPE

from .config import db_path

EDNS_CODE = 65001  # RFC 6891 local/experimental range
HEADER = "x-aifilter-probe"


def token_file() -> Path:
    return db_path().parent / "probe.token"


def token(create: bool = False) -> bytes:
    """The install's probe token; empty when missing (then nothing counts as a probe)."""
    path = token_file()
    for _ in range(2):
        try:
            value = path.read_bytes().strip()
        except OSError:
            value = b""
        if value or not create:
            return value
        # Publish a complete file atomically; a concurrent creator simply wins.
        tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(secrets.token_hex(16).encode())
            try:
                os.link(tmp, path)
            except FileExistsError:
                pass
        except OSError:
            return b""
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return b""


def matches(value) -> bool:
    if isinstance(value, str):
        value = value.encode("ascii", "ignore")
    expected = token()
    return bool(expected) and bool(value) and hmac.compare_digest(bytes(value), expected)


def dns_query(name: str) -> DNSRecord:
    """A question for `name` that carries the probe marker."""
    query = DNSRecord.question(name)
    value = token(create=True)
    if value:
        query.add_ar(EDNS0(opts=[EDNSOption(EDNS_CODE, value)]))
    return query


def dns_marked(req: DNSRecord) -> bool:
    try:
        for rr in req.ar:
            if rr.rtype == QTYPE.OPT:
                for opt in rr.rdata:
                    if opt.code == EDNS_CODE and matches(bytes(opt.data)):
                        return True
    except Exception:  # an odd OPT record is simply not a probe
        return False
    return False
