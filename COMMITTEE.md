# Committee operations

A small group of trusted reviewers decides narrowly scoped requests that automation cannot safely approve. Deployments choose their own reviewers; no person, address, device, or availability schedule belongs here.

## Principles

* **Default deny:** uncertainty, timeout, or missing quorum does not grant access.
* **Least privilege:** approve only the requested resource, device class, and period.
* **Separation:** requesters do not approve their own requests.
* **Auditability:** record the reason, reviewers, decision, expiry, and revocation without unnecessary browsing content.
* **Rollback:** a designated administrator can revoke decisions and stop the bridge without weakening unrelated controls.

## Workflow

1. Authenticate the requester and normalize the resource.
2. Reject requests containing credentials or private personal material.
3. Obtain the locally required quorum through the authenticated bridge.
4. Apply a short expiry by default and record a signed decision identifier.
5. Re-test effective proxy, DNS, and device policy.
6. Periodically remove unused exceptions.

Bridge keys and reviewer account identifiers belong only in untracked local configuration. Committee chat is not a secure archive and must not contain secrets.
