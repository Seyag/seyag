# AI Filter

AI Filter is a **pilot** strict home content-filtering stack designed for a Haredi household. It combines a mitmproxy add-on, local DNS policy, PAC configuration, Apple MDM helpers, and an optional AI judge for media and YouTube. Its default-deny approach makes uncertain requests explicit decisions rather than silent exceptions.

This is engineering material, not a certified safety product. It can fail open because of operating-system changes, encrypted DNS, VPNs, certificate pinning, bugs, unavailable AI services, or incorrect deployment. **Do not use it as the only safeguard for children or vulnerable users.** Retain human supervision and consult qualified local authorities.

## Architecture

1. A PAC file sends eligible HTTP(S) traffic to the mitmproxy add-on.
2. DNS blocks known categories and bypass routes. Generic private CIDRs such as `192.168.0.0/16` are policy constants, not deployment addresses.
3. The proxy applies static rules, SafeSearch, text/image checks, and the YouTube verdict pipeline.
4. MDM helpers reduce easy bypasses on managed Apple devices.
5. Committee tooling records deliberate exceptions. Unknown or unavailable verdicts remain denied wherever a component supports fail-closed behavior.

## Fresh macOS setup

1. Install Python 3.11+, `mitmproxy`, and `requirements.txt` in a virtual environment. Install Node.js and FFmpeg to run their integration tests.
2. Copy `config.example.toml` to `config.toml` and keep that file private. The example starts with no configured exceptions or enrolled devices. The test suite uses a separate synthetic policy.
3. Run `OPENBLAS_NUM_THREADS=1 python -m pytest -q tests`.
4. Start with `mitmdump --listen-host 127.0.0.1 -s addon.py` on an isolated network. Replace the documentation addresses in `pac/proxy.pac` for the test device and use a new local CA. The public MDM profile ships without a root certificate. Install your new CA if you use that profile.
5. Build DNS and MDM settings for your network. Review the paths, identifiers, interfaces, and profiles in `deploy/` and `home-dhcp/` before installing anything.
6. Test outages, certificate errors, pinned apps, IPv6, encrypted DNS, VPN behavior, and recovery before adding devices.

The launcher binds the proxy, PAC, and DNS to loopback by default. For a separate test device, set each required `listen_host` to a specific private LAN address and firewall access to trusted clients. For IPv6 DNS, `listen_host_ipv6` accepts loopback or a private IPv6 address, and an empty value disables IPv6. **An open proxy or DNS resolver can be abused.** Never port-forward these services or expose admin, committee, MCP, or media endpoints to an untrusted network. Keep logs and learned data out of source control.

The example sets image review to `modest`, hides images during reviewer overload, and blocks images flagged by the detector for female faces. DNS tries the next configured upstream when an upstream times out or fails to communicate. If the local resolver raises an internal error, it can answer via the upstream without applying the local rules. If all upstream attempts fail, clients receive `SERVFAIL`. Client and router fallback resolvers can also bypass local policy, so test outages from the client.

### Optional integrations

The private companion app, notification bridge and CLI, local review ledger, machine-specific Keychain and credential helpers, and WhatsApp self-send integration are outside this distribution. Reports remain available locally. An optional `AIFILTER_NOTIFICATION_COMMAND` can point to your own compatible adapter. Remote committee confirmation requires an operator-supplied `AIFILTER_DECISIONS_FILE` and a configured verification key. MDM authentication and Keychain signing require your own helpers via `AIFILTER_KEYCHAIN_HELPERS`. Optional Claude review uses `ANTHROPIC_API_KEY` when enabled. The focus schedule can read a locally maintained `data/focus-blocks.json`. App approvals start empty.

The optional backup VM failover requires `PROJECT`, `ZONE`, `VM`, and `BUCKET`. To pause automatic failover each weekend, also set `FAILOVER_PAUSE_TIMEZONE`, `FAILOVER_PAUSE_START` (Friday), and `FAILOVER_PAUSE_END` (Saturday). Times use local 24-hour clock notation.

## Committee and default deny

Automated classification is advisory. A small trusted committee can approve narrow, audited, preferably expiring requests. Absence of approval is not approval. See [COMMITTEE.md](COMMITTEE.md). Local religious and safeguarding guidance takes precedence over software defaults.

## תקציר בעברית

זהו פיילוט לסינון ביתי מחמיר: פרוקסי, DNS, כלי MDM ובדיקה אופציונלית באמצעות בינה מלאכותית. ברירת המחדל היא חסימה כאשר אין החלטה בטוחה, וחריגים נבדקים בידי ועדה אמינה. המערכת אינה תחליף לפיקוח אנושי או להנחיה הלכתית ומקצועית, ועלולה להיכשל או להיעקף. יש לבדוק במכשיר ניסוי ולא לפרסם הגדרות, סודות, לוגים או את היסטוריית המאגר הפרטי.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
