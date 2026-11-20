"""Usage: python3 deploy/set_restrictions.py -- sets the supervised restrictions in deploy/iphone-filter.mobileconfig (no new VPNs, block apps of platforms the policy blocks)."""
import plistlib
from pathlib import Path

# Apps of platforms whose sites the policy already blocks (config/policy "block"). Reddit/X stay: their sites are text-only, not blocked.
BLOCKED_APPS = [
    "com.zhiliaoapp.musically",   # TikTok
    "com.burbn.instagram",        # Instagram
    "com.facebook.Facebook",      # Facebook
    "com.toyopagroup.picaboo",    # Snapchat
    "com.burbn.barcelona",        # Threads
    "com.hammerandchisel.discord",  # Discord
    "com.tumblr.tumblr",          # Tumblr
    "pinterest",                  # Pinterest
    "tv.twitch",                  # Twitch
    "xyz.blueskyweb.app",         # Bluesky
    # Browsers that carry their own tunnel (Tor, built-in proxy/VPN, cloud rendering):
    # they would skip both the proxy and the DNS lock. Bundle IDs from the App Store API.
    "com.miketigas.OnionBrowser", "ch.b-eng.tor", "com.techlogix.private.browser", "org.torproject.orbot",
    "com.opera.OperaTouch", "com.opera.gx", "com.alohabrowser.alohabrowser",
    "com.cloudmosa.PuffinFree", "com.cloudmosa.puffin", "com.psiphon3.browser", "ca.psiphon.Psiphon",
    "com.xprivate.video",
    # Telegram clients (maintainer decision).
    # Bundle IDs from the App Store search API (country il).
    "ph.telegra.Telegraph", "app.nicegram", "app.swiftgram.ios", "com.olcorporation.olai", "com.seastar.turrit",
    "click.vpgram.messenger", "com.gusu.telexmsg", "com.tg-connect.app",
]
"""Usage: python3 deploy/set_restrictions.py -- sets the supervised restrictions in deploy/iphone-filter.mobileconfig (no new VPNs, block apps of platforms the policy blocks)."""
import plistlib
from pathlib import Path

# Apps of platforms whose sites the policy already blocks (config/policy "block"). Reddit/X stay: their sites are text-only, not blocked.
BLOCKED_APPS = [
    "com.zhiliaoapp.musically",   # TikTok
    "com.burbn.instagram",        # Instagram
    "com.facebook.Facebook",      # Facebook
    "com.toyopagroup.picaboo",    # Snapchat
    "com.burbn.barcelona",        # Threads
    "com.hammerandchisel.discord",  # Discord
    "com.tumblr.tumblr",          # Tumblr
    "pinterest",                  # Pinterest
    "tv.twitch",                  # Twitch
    "xyz.blueskyweb.app",         # Bluesky
    # Browsers that carry their own tunnel (Tor, built-in proxy/VPN, cloud rendering):
    # they would skip both the proxy and the DNS lock. Bundle IDs from the App Store API.
    "com.miketigas.OnionBrowser", "ch.b-eng.tor", "com.techlogix.private.browser", "org.torproject.orbot",
    "com.opera.OperaTouch", "com.opera.gx", "com.alohabrowser.alohabrowser",
    "com.cloudmosa.PuffinFree", "com.cloudmosa.puffin", "com.psiphon3.browser", "ca.psiphon.Psiphon",
    "com.xprivate.video",
    # Telegram clients (maintainer decision).
    # Bundle IDs from the App Store search API (country il).
    "ph.telegra.Telegraph", "app.nicegram", "app.swiftgram.ios", "com.olcorporation.olai", "com.seastar.turrit",
    "click.vpgram.messenger", "com.gusu.telexmsg", "com.tg-connect.app",
]


def main():
    p = Path(__file__).with_name("iphone-filter.mobileconfig")
    prof = plistlib.loads(p.read_bytes())
    for x in prof["PayloadContent"]:
        if x["PayloadType"] == "com.apple.applicationaccess":
            x["allowCloudPrivateRelay"] = False
            x["allowVPNCreation"] = False          # no other VPN app can route around the filter
            x["allowEraseContentAndSettings"] = False  # a factory reset would remove the whole filter
            x["allowAppRemoval"] = False           # Tailscale (the filter route) cannot be deleted
            x["blockedAppBundleIDs"] = BLOCKED_APPS
    assert prof["PayloadVersion"] == 1
    p.write_bytes(plistlib.dumps(prof))
    print("ok", len(BLOCKED_APPS), "apps blocked")


if __name__ == "__main__":
    main()
