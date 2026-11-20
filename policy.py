"""Standing committee policy for filtered devices (never house-wide).

  policy.py           (re)apply the policy; committee decisions (source admin) and
                      temporary approvals (overrides) are kept; idempotent
  policy.py --prune [--apply]
                      list (or with --apply remove) policy rows and locks this script once set for hosts
                      no longer in its lists; committee-chat policy rows are never touched
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aifilter import config  # noqa: E402
from aifilter.store import BLOCK, TEXT_ONLY, Store  # noqa: E402

# Mostly-text platforms: open, but every image and video is hidden.
TEXT_ONLY_SITES = [
    "x.com", "twitter.com", "twimg.com", "t.co",
    "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com",
]

# Visual feeds and chat platforms: nothing useful survives without images (COMMITTEE.md rule 4).
BLOCKED_FEEDS = [
    "instagram.com", "cdninstagram.com", "tiktok.com", "tiktokcdn.com", "tiktokv.com",
    "facebook.com", "fb.com", "fb.watch", "threads.net", "threads.com", "snapchat.com",
    "pinterest.com", "tumblr.com", "bsky.app", "twitch.tv", "kick.com", "9gag.com",
    "imgur.com", "discord.com", "discord.gg",
]


TEXT_ONLY_REASON = "רשת חברתית: טקסט בלבד, בלי תמונות וסרטונים"
BLOCK_REASON = "רשת חברתית עם פיד פתוח"


def apply(store: Store) -> int:
    changed = 0
    for verdict, hosts, reason in (
        (TEXT_ONLY, TEXT_ONLY_SITES, TEXT_ONLY_REASON),
        (BLOCK, BLOCKED_FEEDS, BLOCK_REASON),
    ):
        for host in hosts:
            current = store.standing(host)
            if current and (current[1] == "admin" or tuple(current) == (verdict, "policy")):
                if current[1] == "admin":
                    store._lock_policy(host, verdict, reason)  # a committee decision keeps the row; policy stays a lock
                continue  # committee decision kept; unchanged policy not rewritten
            # set_verdict never lets a policy weaken a stricter standing row; it then only records the lock.
            store.set_verdict(host, verdict, "policy", reason)
            changed += 1
    return changed


def prune(store: Store, remove: bool = False) -> list[tuple[str, str]]:
    """(kind, host) of policy rows and locks set by this script (by their reason) whose host left the lists."""
    listed = set(TEXT_ONLY_SITES) | set(BLOCKED_FEEDS)
    ours = {TEXT_ONLY_REASON, BLOCK_REASON}
    stale = [(kind, host) for kind, host, _verdict, reason in store.policy_records()
             if host not in listed and reason in ours]  # exact: a lock shared with another writer stays
    if remove:
        for kind, host in stale:
            store.remove_policy_record(kind, host)
    return stale


if __name__ == "__main__":
    store = Store(config.db_path())
    if "--prune" in sys.argv[1:]:
        remove = "--apply" in sys.argv[1:]
        for kind, host in prune(store, remove):
            print(("removed" if remove else "would remove"), kind, host)
        if not remove:
            print("dry run; add --apply to remove")
    else:
        print(apply(store), "hosts set")
