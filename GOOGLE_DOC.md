# Oriel — T3N Agent Build Challenge

Repository: https://github.com/Takumixbt/oriel
Demo video: `[ADD VIDEO URL]`
Challenge: https://superteam.fun/earn/listing/t3n-agent-build-challenge

## The product

Oriel is private qualification infrastructure for autonomous agents. It makes an enterprise agent's exact deployed identity and target-attested version label earn short-lived, narrowly scoped access by surviving adversarial tests that run against tenant-private policy and data on T3N.

The problem is the gap between permission and behavior. A DID proves who is calling and an ACL says what that identity may attempt, but neither proves that the running build will respect a private-data boundary under attack. Oriel turns a deterministic qualification into a runtime access condition at the protected T3N function.

## The demo

The example is a fulfillment/support agent allowed to call `support.lookup` on `support-api.oriel.test`. It must not disclose hidden customer context, issue refunds, or contact arbitrary hosts.

The vulnerable build fails because it leaks a fresh private canary, attempts `support.issue-refund`, and contacts `collector.invalid`. The hardened build refuses the canary disclosure and stays inside the approved function/host scope. Only the qualified target DID and exact requested version label can read the protected synthetic order. Version drift, wrong caller, expiry, untested capability/host, and revocation all deny with no protected record.

The protected support read checks the fixed `support-api.oriel.test` route internally; the caller cannot substitute a host label at access time.

## The trust model

The T3N contract derives the per-run canary from tenant-private state, calls the probe gateway, verifies the target's signature over the exact response evidence, verifies a separate gateway observer receipt, and only then stores the qualification. The protected action uses the authenticated T3N caller DID, requested version label, capability, order, fixed support host, expiry, and revocation state; the caller cannot substitute a host label.

The target key and observer key are separate. The local combined fixture exists only for deterministic testing; the deployable configuration defaults to a target-agent service behind a distinct observer gateway. The current gateway receipt proves integrity and separation of the returned HTTP evidence, not independent measurement of hidden in-process actions. A production observer should additionally instrument the agent's real tool and egress boundary.

## Build evidence

- Rust `wasm32-wasip2` component, source version `0.2.0`;
- release WASM SHA-256: `eb39d5fabf27474644e969ff5bc76c238768b2898454c9b49d587bfb4ab17a6b`;
- 14 Rust unit tests + 1 doc test;
- 11 TypeScript lifecycle/security tests + strict typecheck;
- deterministic local demo;
- pinned toolchain, lockfile, CI, Docker/Render deployment;
- agent card with schema preflight;
- architecture, threat model, probe protocol, methodology, bug report, demo script, and handover runbook.

The repo records historical testnet registration/grant evidence for `oriel@0.1.2`, contract ID `824`. The current `0.2.0` protocol must be registered separately because its WIT package and signed-attestation flow changed. A live qualification/access transcript is the final operator-run artifact once funded execution identities and a stable HTTPS gateway are available.

## Bugs found and maintainership

The repository documents four actionable SDK/platform issues: an unresolved transitive archive-extraction advisory, weak `MapVisibility` typing, a heavyweight clean install, and stale map ACLs after a new contract ID. Oriel mitigates the ACL issue automatically and records exact reproduction/impact boundaries in `docs/BUGS.md`.

The pure policy engine is data-driven and separate from the T3N adapter. Redeployment, ACL rewrite, key rotation, versioned test packs, monitoring, rollback, and acceptance checks are documented in the handover runbook. I prefer Terminal 3 to host and maintain Oriel after a 30-day transition.

## Attachments

1. Architecture/role split
2. Vulnerable run with three findings
3. Hardened qualification with both attestations
4. Protected action allowed
5. Version drift denied
6. Revocation denied
7. Node and Rust test output
8. Live T3N transcript when funded execution is available

Full technical details and the challenge-ready submission copy are in [`docs/SUBMISSION.md`](https://github.com/Takumixbt/oriel/blob/main/docs/SUBMISSION.md).
