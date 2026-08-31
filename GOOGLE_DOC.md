# Oriel — T3N Agent Build Challenge submission

**Private qualification infrastructure for autonomous agents**

- Repository: https://github.com/Takumixbt/oriel
- Demo video: `[ADD VIDEO URL]`
- Live evidence: testnet registration and scoped grants verified for `oriel@0.1.2`, contract ID `824`; the final qualification/access transcript is added after funded agent keys and a stable HTTPS target are supplied.

## What Oriel does

Oriel makes an enterprise agent's exact deployed identity and software version earn narrowly scoped, short-lived access by surviving tenant-private adversarial tests on T3N.

Identity and permission systems answer who an agent is and what it was configured to call. They do not prove that the running build respects a private-data boundary under attack. Audits also tend to produce reports disconnected from runtime authorization. Oriel closes that gap: a deterministic test result becomes a condition of access at the protected T3N function.

## Enterprise scenario

The demo tests a fulfillment/support agent. Its legitimate job is to look up order state. It must not reveal hidden customer context, issue refunds, or send information to arbitrary hosts.

The vulnerable build receives a fresh private canary and adversarial request. It leaks the canary, attempts an unauthorized refund, and tries `collector.invalid`, so Oriel stores a failed result. The hardened build refuses disclosure and stays within `support.lookup` and its approved host, so it receives a five-minute qualification.

Only that target DID and version can read the protected synthetic order. A different identity, new unqualified version, untested function, expired pass, or revoked pass receives a denial with no order data.

## Why this needs T3N

Oriel uses T3N authenticated caller identity instead of caller-provided identity, cluster time for expiry, private tenant KV for policies/seeds/qualifications/data, contract-ID map ACLs, outbound host grants, WASI isolation, and a claims digest over stored qualification evidence. The T3N contract is the enforcement point.

## What is complete

- Rust/WASI T3N component with `run-qualification`, `get-qualification`, `protected-support-action`, and `revoke-qualification`;
- separate tenant-owner, certifier-agent, and target-agent identities;
- fresh per-run canary derived from a private master seed inside T3N;
- deterministic checks for secret leakage, version mismatch, unauthorized functions, and unauthorized hosts;
- DID/version/scope/host/time/revocation-bound admission;
- vulnerable and hardened real HTTP fixtures;
- end-to-end demo and independent TypeScript/Rust test suites;
- strict typecheck, pinned SDK/lockfile, GitHub Actions, Docker/Render deployment;
- agent card, architecture, threat model, probe protocol, test methodology, bugs, and handover runbook;
- live scripts that preserve existing grants and never print key material.

## Verification

- Rust: 10 unit tests plus 1 doc test passing
- TypeScript: strict typecheck passing
- HTTP lifecycle/security suite: 5 tests passing
- WASM release component: builds and exposes the expected T3N interfaces
- Live testnet: contract registration and scoped grants verified; qualification/access needs funded certifier and target identities plus a public HTTPS target

The corrected component is registered on T3N testnet as
`z:51cfebef5279596508dae8355cb2c86a3ae08efc:oriel@0.1.2`, contract ID
`824`, with WASM SHA-256
`a2c8c62a3bd7d528bb329fbc9fc489814624a9654e45ac34e55ed188684d0e38`.
The registration output confirmed all four private maps were seeded and ACL'd
to the current contract. The remaining qualification/access transcript is
operator-run evidence because it requires funded execution identities and a
stable HTTPS target.

## Maintainability and handover

The pure policy engine is separated from T3N adapters. Test packs are versioned JSON. Dependencies are pinned. CI rebuilds both stacks. Docker runs the target fixture. The redeploy script rewrites all map ACLs to the new contract ID, avoiding a known operational footgun.

I prefer to hand Oriel to Terminal 3 to host and maintain, with a 30-day transition. The repository is MIT licensed and the deterministic verdict has no proprietary model dependency. The runbook covers deployment, grants, key rotation, policy versioning, monitoring, rollback, and acceptance tests.

## Bugs found

1. `@terminal3/t3n-sdk@4.36.0` currently resolves a vulnerable archive-extraction chain; `npm audit` reports one critical and three moderate advisories. Oriel does not execute that path, and `npm audit fix --dry-run` does not resolve it.
2. SDK `MapVisibility` is typed as unrestricted `string` despite exact `Private`/`Public` wire values, so casing mistakes survive compilation.
3. Clean SDK installation is heavy (268 dependencies in this environment), largely due to bundled componentization/platform tooling; splitting runtime and authoring packages would improve CI and maintenance.
4. New contract registrations produce new numeric IDs, so private-map ACLs can go stale. Oriel automatically rewrites all four ACLs after registration.

Full reproduction steps, impact boundaries, mitigations, and maintainer actions are documented in [`docs/BUGS.md`](https://github.com/Takumixbt/oriel/blob/main/docs/BUGS.md).

During the first live registration attempt, Oriel also caught and fixed its own descriptor omission: T3N rejected the agent card because each function was missing the required boolean `mutates` field. Follow-up validation exposed the required `auth`, `params_schema`, `returns`, `errors`, and `examples` shapes; the card and registration preflight now cover all of them. The corrected card is registered as `oriel@0.1.2` with contract ID `824`, and scoped grants have been verified.

## Honest limits and roadmap

A qualification proves one DID/version passed one test-pack version for one finite scope and interval; it is not universal safety. Production priorities are signed deployment manifests or remote attestation, independently observed tool traces, transformed-leak detectors, multiple policy packs, scheduled requalification, and portable receipts.

## Screenshots

- `[INSERT: architecture]`
- `[INSERT: vulnerable build, three findings]`
- `[INSERT: hardened build qualified]`
- `[INSERT: protected record allowed]`
- `[INSERT: version drift denied with null order]`
- `[INSERT: revocation denied with null order]`
- `[INSERT: green Node and Rust tests]`
- `[INSERT: live T3N run]`

Challenge: https://superteam.fun/earn/listing/t3n-agent-build-challenge
