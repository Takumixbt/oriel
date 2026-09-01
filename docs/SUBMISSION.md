# Oriel — T3N Agent Build Challenge submission

## Private qualification infrastructure for autonomous agents

- Repository: https://github.com/Takumixbt/oriel
- Demo video: `[ADD VIDEO URL]`
- Challenge: https://superteam.fun/earn/listing/t3n-agent-build-challenge

## What Oriel does

Oriel makes an enterprise agent's exact deployed identity and target-attested version label earn narrowly scoped, short-lived access by surviving tenant-private adversarial tests on T3N.

An identity system can prove which key is calling. A permission grant can describe what that key may attempt. Neither proves that the running build respects a private-data boundary under attack. Oriel closes that gap: the qualification result is stored privately and the protected T3N function checks it before returning sensitive data.

## Enterprise scenario

The demo models a fulfillment/support agent whose legitimate job is `support.lookup`. The private policy says it must not reveal hidden customer context, issue refunds, or contact an arbitrary host.

The vulnerable build fails three deterministic checks: it leaks a fresh private canary, attempts `support.issue-refund`, and contacts `collector.invalid`. The hardened build refuses the disclosure and stays within the approved function and host. Only the hardened target DID and exact requested version label can read the protected synthetic order.

The protected path also denies a different caller, an unqualified version, an untested function, an expired qualification, and a revoked qualification. Every denial returns no order data.

The protected support read does not accept a caller-supplied destination host; it checks the fixed `support-api.oriel.test` route against the qualification internally. Host scope remains part of the private probe policy and evidence.

## Why this needs T3N

Oriel uses T3N authenticated caller identity rather than caller-provided identity, cluster time for expiry, tenant-private KV for policies/secrets/qualifications/data, contract-ID map ACLs, outbound-host grants, a WASI component boundary, and a claims digest over the stored evidence.

The probe is intentionally split into roles:

1. The target agent signs the exact response evidence with its target key.
2. A separate probe gateway signs an observer receipt over the exact response returned through the gateway.
3. The T3N contract verifies both attestations before persisting a qualification.

This prevents a certifier from manufacturing a pass for an arbitrary DID and keeps the observer credential separate from the target credential. The current release documents the remaining boundary honestly: a gateway receipt authenticates the observed HTTP evidence; production deployment should instrument the real tool/egress boundary for stronger independent trace observation.

## What is complete

- Rust `wasm32-wasip2` T3N component with `run-qualification`, `get-qualification`, `protected-support-action`, and `revoke-qualification`;
- tenant-owner, certifier, target-agent, and separate observer/gateway trust roles;
- fresh per-run canary derived from a private master seed inside T3N;
- deterministic checks for secret leakage, version mismatch, unauthorized functions, and unauthorized hosts;
- DID/version-label/scope/fixed-host/time/revocation-bound admission;
- target signatures and separate gateway receipts bound to the exact response evidence;
- vulnerable and hardened HTTP fixtures plus a production-safe target/gateway deployment split;
- one-command end-to-end demo and independent TypeScript/Rust test suites;
- strict agent-card/preflight validation, pinned Rust toolchain, lockfile, GitHub Actions, Docker, and Render deployment;
- architecture, threat model, probe protocol, test methodology, bug report, demo script, and handover runbook.

## Verification snapshot

- Rust: 14 unit tests plus 1 doc test passing;
- TypeScript: strict typecheck passing;
- TypeScript lifecycle/security suite: 11 tests passing;
- WASM: release component validates and exports the expected T3N interfaces;
- contract source version: `0.2.0`;
- release WASM SHA-256: `eb39d5fabf27474644e969ff5bc76c238768b2898454c9b49d587bfb4ab17a6b`;
- local demo: vulnerable target fails, hardened target qualifies, protected access succeeds, version drift and revocation deny.

The repository contains a historical T3N testnet transcript for the earlier `oriel@0.1.2` registration (contract ID `824`). That registration and its scoped grants were verified, but it is not represented as the current release: `0.2.0` changes the WIT package and attestation protocol and must be registered as a new version. The remaining live qualification transcript requires funded certifier/target execution identities and a stable public HTTPS gateway.

## Maintainability and handover

The pure policy engine is separated from T3N adapters. Test packs are versioned JSON. Dependencies and the Rust toolchain are pinned. CI rebuilds both stacks and checks the contract hash. Docker runs the target fixture; Render supports separate target-agent and observer-gateway roles. The redeploy runbook rewrites all private-map ACLs to the new contract ID, avoiding a known operational footgun.

I prefer to hand Oriel to Terminal 3 to host and maintain, with a 30-day transition. The repository is MIT licensed and the deterministic verdict has no proprietary model dependency. The runbook covers deployment, grants, key rotation, policy versioning, monitoring, rollback, and acceptance tests.

## Bugs found

1. `@terminal3/t3n-sdk@4.36.0` currently resolves a vulnerable archive-extraction chain; `npm audit` reports one critical and three moderate advisories. Oriel does not execute that path, and `npm audit fix --dry-run` does not resolve it.
2. SDK `MapVisibility` is typed as unrestricted `string` despite exact `Private`/`Public` wire values, so casing mistakes survive compilation.
3. Clean SDK installation is heavy (268 dependencies in the captured environment), largely due to bundled componentization/platform tooling; splitting runtime and authoring packages would improve CI and maintenance.
4. New contract registrations produce new numeric IDs, so private-map ACLs can go stale. Oriel automatically rewrites all four ACLs after registration.

Full reproduction steps, impact boundaries, mitigations, and maintainer actions are in [`docs/BUGS.md`](https://github.com/Takumixbt/oriel/blob/main/docs/BUGS.md).

During the first live registration attempt, Oriel also caught and fixed its own descriptor omission: T3N rejected the card because each function was missing the required boolean `mutates` field. Follow-up validation now covers `auth`, `params_schema`, `returns`, `errors`, and `examples` as well.

## Honest limits and roadmap

A qualification proves that one DID and target-attested version label passed one test-pack version for one finite scope and interval; it is not universal safety or measured artifact provenance. The next production milestones are signed deployment manifests or remote attestation, an observer that instruments actual tool/egress traces, transformed-leak detectors, multiple policy packs, scheduled requalification, and portable receipts.

## Screenshots to attach

- architecture and role split;
- vulnerable run with three findings;
- hardened run with target signature and observer receipt;
- protected record allowed;
- version drift denied with null order;
- revocation denied with null order;
- green Node and Rust tests;
- live T3N registration/qualification transcript after funded execution is available.
