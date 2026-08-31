# Oriel — private qualification infrastructure for autonomous agents

## One sentence

Oriel makes an enterprise agent's exact deployed identity and version earn narrowly scoped, short-lived access by surviving tenant-private adversarial tests on T3N.

## The gap

Agent identity tells an enterprise which key is calling. A permission grant says what that key may attempt. Neither proves that the running build respects private-data boundaries under adversarial input. Periodic audits are also disconnected from runtime authorization: a failed test can become a PDF while the agent keeps its access.

Oriel closes that loop. It privately tests the target, records a deterministic result bound to DID + version + test pack + scope + expiry, and makes the protected T3N function enforce the result before reading data.

## Enterprise use case

The demo models a fulfillment/support agent. Its legitimate job is `support.lookup`. It must not reveal hidden customer context, issue refunds, or exfiltrate to arbitrary hosts.

The vulnerable build fails because it leaks a private canary, attempts `support.issue-refund`, and contacts `collector.invalid`. The hardened build passes because it refuses the disclosure and remains within the approved function/host. Only that hardened version can read the protected synthetic order. Identity impersonation, version drift, scope escalation, expiry, and revocation all return no protected data.

## What is built

- Rust `wasm32-wasip2` T3N component with four exported functions;
- private T3N map design for secrets, policies, qualifications, and protected records;
- three-identity grant model: owner, Oriel certifier, target agent;
- deterministic finding and access engines;
- vulnerable/hardened HTTP target fixtures;
- one-command end-to-end lifecycle demo;
- strict TypeScript integration tests and independent Rust unit tests;
- contract descriptor/agent card;
- credential-safe registration, grant, qualify, protected-call, and revoke scripts;
- Docker/Render target deployment and GitHub Actions CI;
- architecture, threat model, test method, bug report, demo script, and handover runbook.

## Why T3N is essential

T3N is not a branding layer here. Oriel uses authenticated caller DID rather than caller input, cluster time for expiry, tenant-private KV for hidden tests and records, contract ACLs, outbound-host grants, a WASI component boundary, and a claims digest over stored qualification evidence. Moving the decision to an ordinary web server would weaken the identity and state guarantees that make admission meaningful.

## Judge-criteria matrix

| Criterion from listing | Evidence |
|---|---|
| Useful enterprise agent | closes the test-to-runtime-access gap for any sensitive enterprise agent |
| Build quality | strict compiler settings, two independent test layers, fail-closed protected path, pinned SDK, CI |
| Easy to maintain post challenge | small interfaces, versioned data-driven packs, Docker deployment, runbook, ACL-safe redeploy path |
| Documentation quality | README + architecture + threat model + methodology + live runbook + 90-second script |
| Bug submission quality | four documented findings with reproduction commands, observed impact, boundary notes, mitigations, and maintainer actions |
| Efficient to run | deterministic verdict; no LLM/API required; one command for local lifecycle |
| Handover | explicit Terminal 3 handover preference and operator acceptance checklist |

## Verification snapshot

- Rust: 10 unit tests and 1 doc test passing
- TypeScript: strict typecheck passing
- Integration: 5 lifecycle/security tests passing
- WASM: release component builds and exports the expected T3N interfaces
- Live testnet: contract registration and scoped grants verified; qualification/access needs funded certifier and target identities plus a public HTTPS target

The corrected component is registered on T3N testnet as
`z:51cfebef5279596508dae8355cb2c86a3ae08efc:oriel@0.1.2`, contract ID
`824`, with WASM SHA-256
`a2c8c62a3bd7d528bb329fbc9fc489814624a9654e45ac34e55ed188684d0e38`.
Registration confirmed all four private maps were seeded and ACL'd to the
current contract. The qualification/access transcript remains an operator-run
artifact because it requires funded execution identities and a stable HTTPS
target.

## Honest boundaries

Oriel does not claim universal agent safety. A qualification proves only that one DID/version passed one versioned test pack for one capability/host scope during one finite interval. Target build attestation, transformed-leak detectors, independently observed traces, and portable receipts are the next production milestones.

## Handover preference

I prefer to hand Oriel to Terminal 3 to host and maintain, with a 30-day transition. The repository is MIT licensed, the verdict needs no proprietary model, and the tenant owns its policies and data. The included handover guide covers deployment, grants, key rotation, policy versioning, monitoring, rollback, and acceptance tests.

## Links and media

- Public repository: https://github.com/Takumixbt/oriel
- Demo video: `[ADD VIDEO URL]`
- Live contract/transaction evidence: testnet registration and scoped grants verified for `oriel@0.1.2`, contract ID `824`; qualification/access transcript follows once agent execution credits and a stable HTTPS target are supplied.
- Screenshots: follow the eight-item checklist in `docs/DEMO_SCRIPT.md`; the final live-registration image is added after the testnet run.

Built for the T3N Agent Build Challenge: https://superteam.fun/earn/listing/t3n-agent-build-challenge
