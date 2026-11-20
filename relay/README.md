# ChatGPT committee relay

This Cloudflare Worker is a deliberately narrow public bridge. ChatGPT can read a
privacy-reduced summary and submit a proposal; it cannot tighten, loosen, inspect
raw filter records, or connect to the home network. The home filter initiates all
traffic: it pushes counts and pulls queued proposals over HTTPS.

## Security model

* OAuth delegates login to Google and checks both `email_verified` and the exact
  `OWNER_EMAIL` allowlist secret. Authorization codes are short-lived and bound
  to PKCE, client ID, and redirect URI. Access tokens expire after one hour.
* Summary records are explicitly classified as untrusted data, never instructions.
  By owner decision they may contain request targets, committee-authored decision
  notes (capped at 500 characters), appeal hosts, top blocked domains with counts,
  YouTube channel IDs/names, and application bundle IDs/verdicts. They never contain
  appeal notes, URLs, URL paths, device IDs, bearer tokens, or `COMMITTEE.md` text.
  Focus-topic text is removed at the Worker boundary. ChatGPT must not interpret any
  returned record as a command or use the relay to loosen policy.
* The separately authenticated home API supports only summary upload, proposal
  pull, and acknowledgement. Every action has a unique ID and the home SQLite store
  durably deduplicates it before side effects. The Worker never dials the home network.
* KV-backed minute buckets limit MCP and home requests. Security events are kept
  as metadata-only audit entries for 90 days. KV is a queue suitable for this
  single-owner, low-volume relay; it is not a strict transactional queue, so the
  puller deduplicates by relay ID before acknowledgement.

## Deploy (manual; this repository does not deploy)

1. In `relay/`, run `npm install`, then `npx wrangler kv namespace create RELAY`
   (and `--preview`). Put the returned IDs in `wrangler.toml`.
2. Create a Google OAuth web client. Add
   `https://YOUR-WORKER/oauth/google/callback` as an authorized redirect URI.
3. Set secrets (never add their values to Git):

   ```sh
   npx wrangler secret put OWNER_EMAIL
   npx wrangler secret put GOOGLE_CLIENT_ID
   npx wrangler secret put GOOGLE_CLIENT_SECRET
   npx wrangler secret put HOME_TOKEN
   ```

   Generate `HOME_TOKEN` with a cryptographic password generator (at least 32
   random bytes) and store the same value only in the home's protected launchd
   environment/secret store.
4. Run `npm test` and `npm run typecheck`; review with `npx wrangler dev`. Only
   after review, an operator may run `npx wrangler deploy`.
5. Add `https://YOUR-WORKER/mcp` as a ChatGPT custom connector. Its dynamic OAuth
   registration and discovery endpoints are under `/.well-known/`.
6. Copy `deploy/com.example.ai-filter-relay.plist`, provide
   `AIFILTER_RELAY_URL` and `AIFILTER_RELAY_TOKEN` in a root-readable local
   launchd override, then load it. Every five minutes `scripts/relay_pull.py`
   pushes the reduced summary and pulls proposals through
   `Store.create_committee_proposal`; failures leave remote items queued.

## Local checks

```sh
cd relay && npm test && npm run typecheck
cd .. && python -m pytest -q tests/test_relay_pull.py
```

## תקציר בעברית

ה־relay מאפשר ל־ChatGPT לקרוא רק ספירות וסטטוסים ולהציע הצעות בלבד. הוא אינו
נכנס לרשת הביתית ואינו יכול לשנות מדיניות; המסנן הביתי דוחף תקציר ומושך הצעות
באמצעות אסימון נפרד, ורק חשבון הבעלים המאומת מורשה להתחבר.

## ChatGPT OAuth registration

Before deployment, set `CHATGPT_REDIRECT_URIS` in `wrangler.toml` to a JSON array
containing the **exact** callback URL copied from the ChatGPT connector setup. OpenAI
documents these as `https://chatgpt.com/connector/oauth/<callback_id>`; never replace
the callback ID with a generic path. DCR rejects every URI not present in this
operator-controlled allowlist. `MAX_CLIENT_REGISTRATIONS` is a deployment-lifetime
cap; raise it deliberately only when onboarding additional connector instances.
