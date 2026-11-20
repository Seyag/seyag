"""Startup check: the CA mitmproxy signs with must be the one the iPhone trusts.

The iPhone profile embeds a fixed root certificate (payload com.apple.security.root).
If mitmproxy's CA was regenerated, or the service runs with another home folder,
every inspected HTTPS site would fail on the phone. run.sh refuses to start the
proxy when the fingerprints differ.

Run:  .venv/bin/python -m aifilter.cacheck   (exit 0 = match; prints fingerprints only)
Only CERTIFICATE blocks are read; the private key in the same file is never parsed.
"""

import base64
import hashlib
import os
import plistlib
import re
import sys
from pathlib import Path

from aifilter.config import ROOT

PROFILE = ROOT / "deploy" / "iphone-filter.mobileconfig"
CONFDIR = Path(os.environ.get("AIFILTER_MITM_CONFDIR", Path.home() / ".mitmproxy"))
_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def _der_certs(blob: bytes) -> list[bytes]:
    if b"-----BEGIN" in blob:
        return [base64.b64decode(b"".join(m.split())) for m in _PEM_CERT.findall(blob)]
    return [blob]


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def profile_roots(path: Path = PROFILE) -> set[str]:
    with open(path, "rb") as f:
        profile = plistlib.load(f)
    found = set()
    for payload in profile.get("PayloadContent", []):
        if isinstance(payload, dict) and payload.get("PayloadType") == "com.apple.security.root":
            found.update(fingerprint(d) for d in _der_certs(payload.get("PayloadContent", b"")))
    return found


def signing_cert(confdir: Path = CONFDIR) -> str | None:
    """Fingerprint of the certificate in mitmproxy-ca.pem (the file mitmproxy signs with)."""
    path = confdir / "mitmproxy-ca.pem"
    if not path.exists():
        return None
    certs = _der_certs(path.read_bytes())
    return fingerprint(certs[0]) if certs else None


def check(profile: Path = PROFILE, confdir: Path = CONFDIR) -> tuple[bool, str]:
    try:
        roots = profile_roots(profile)
    except (OSError, plistlib.InvalidFileException, ValueError) as e:
        return False, f"cannot read the iPhone profile {profile}: {e}"
    if not roots:
        return False, f"no com.apple.security.root payload in {profile}"
    ca = signing_cert(confdir)
    if ca is None:
        return False, f"no mitmproxy CA at {confdir}/mitmproxy-ca.pem (mitmproxy would create a new, untrusted one)"
    if ca not in roots:
        return False, f"CA MISMATCH: mitmproxy CA {ca[:16]}... is not the profile root {sorted(roots)[0][:16]}..."
    return True, f"CA ok: {ca[:16]}... matches the iPhone profile"


def main() -> int:
    ok, message = check()
    print(("" if ok else "!!! ai-filter: ") + message, file=sys.stdout if ok else sys.stderr, flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
