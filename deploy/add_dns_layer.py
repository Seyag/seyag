"""Usage: python3 deploy/add_dns_layer.py  -- adds/updates the locked encrypted-DNS payload (Cloudflare Families) in deploy/iphone-filter.mobileconfig so filtering also works on cellular."""
import plistlib, sys
from pathlib import Path
from uuid import uuid4
p = Path(__file__).with_name("iphone-filter.mobileconfig")
prof = plistlib.loads(p.read_bytes())
dns = {
    "PayloadType": "com.apple.dnsSettings.managed",
    "PayloadIdentifier": "home.example.filter.dns",
    "PayloadDisplayName": "Filter DNS (all networks)",
    "PayloadUUID": str(uuid4()),
    "PayloadVersion": 1,
    "DNSSettings": {
        "DNSProtocol": "HTTPS",
        "ServerURL": "https://family.cloudflare-dns.com/dns-query",
        "ServerAddresses": ["1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003"],
    },
    "ProhibitDisablement": True,
}
prof["PayloadContent"] = [x for x in prof["PayloadContent"] if x["PayloadType"] != dns["PayloadType"]] + [dns]  # the lock always stays (maintainer decision); there is no remove option
prof["PayloadVersion"] = 1  # must stay 1: iOS rejects other values as invalid
p.write_bytes(plistlib.dumps(prof))
print("ok", [x["PayloadType"] for x in prof["PayloadContent"]])
