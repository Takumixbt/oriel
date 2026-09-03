# Oriel — T3N Agent Build Challenge

**Repository:** https://github.com/Takumixbt/oriel  
**Challenge:** https://superteam.fun/earn/listing/t3n-agent-build-challenge  
**Handover preference:** Pass to Terminal 3 to host and maintain (30-day transition)

---

## What Oriel is

Oriel is private qualification infrastructure for autonomous agents on Terminal 3 Network (T3N).

Enterprises already know *which* agent identity is calling and *what* it was granted. They rarely know whether the **exact deployed version** survived their private tests — and they rarely bind that result to runtime access.

Oriel closes that gap:

1. A tenant stores a secret canary, test policy, qualification ledger, and protected data in private T3N maps.
2. An Oriel certifier invokes a T3N WASM contract, which probes the target through a separate observer gateway.
3. The target signs the response with its Ethereum/T3N identity; the gateway receipts the exact returned evidence with a separate key.
4. A deterministic evaluator checks secret leakage, version mismatch, unauthorized functions, and unauthorized hosts.
5. Only the exact target DID + version label earns a short-lived, scope-bound, revocable qualification.
6. The protected function returns enterprise data only when identity, version, scope, fixed host, expiry, and revocation all pass.

This is useful for enterprises because failure is enforced as denial at the T3N boundary, not filed as a dashboard warning. It is maintainable because the policy engine is pure/data-driven, packs are versioned JSON, dependencies are pinned, CI rebuilds both stacks, and the handover runbook covers redeploy, ACL rotation, and key rotation.

---

## Demo scenario

A fulfillment/support agent may call `support.lookup` on `support-api.oriel.test`. It must not disclose hidden customer context, issue refunds, or contact arbitrary hosts.

- **Vulnerable build** → fails with `CANARY_LEAK`, `UNAUTHORIZED_FUNCTION`, `UNAUTHORIZED_HOST`
- **Hardened build** → qualifies (target signature + separate observer receipt)
- **Qualified access** → returns synthetic order `order-1042`
- **Version drift** → denied, `order: null`
- **Owner revocation** → denied, `order: null`

Reproduce locally:

```bash
npm ci
npm run demo
npm test
npm run contract:test
npm run contract:build
npm run contract:hash
```

---

## Screenshots

Insert the PNGs from the repo folder `submission/screenshots/` (same files also live at `docs/assets/screenshots/`).

### 1. Architecture / role split
Insert: `01-architecture.png`

### 2. Verified lifecycle overview
Insert: `02-lifecycle.png`

### 3. Vulnerable run — three findings (failed)
Insert: `03-vulnerable-failed.png`

### 4. Hardened run — qualified
Insert: `04-hardened-qualified.png`

### 5. Protected action — allowed
Insert: `05-protected-allowed.png`

### 6. Version drift — denied, null order
Insert: `06-version-drift-denied.png`

### 7. Revocation — denied, null order
Insert: `07-revocation-denied.png`

### 8. TypeScript tests — 11 passing
Insert: `08-npm-test.png`

### 9. Rust contract tests — 14 unit + 1 doc
Insert: `09-cargo-test.png`

### 10. Release contract hash (0.2.0)
Insert: `10-contract-hash.png`

Optional full dump: `00-full-demo.png`

---

## Build evidence

| Check | Result |
|---|---|
| Contract source version | `0.2.0` |
| Release WASM size | 304,736 bytes |
| Release WASM SHA-256 | `295820dfb875f051d64238f4bc7cf936040de9fbd869f8a9b586b23798d894a7` |
| Rust tests | 14 unit + 1 doc test passing |
| TypeScript tests | 11 passing + strict typecheck |
| Local demo | vulnerable fails → hardened qualifies → access allowed → drift/revoke deny |
| CI | GitHub Actions rebuilds Node + Rust WASM and checks contract hash |
| Deploy shape | Docker + Render (`agent` / `gateway` roles) |

Historical note: testnet registration/grants for earlier `oriel@0.1.2` (contract ID `824`) succeeded. Current `0.2.0` changes WIT and the attestation protocol, so it must be registered as a new version. A live `0.2.0` qualification/access transcript is the remaining operator artifact once funded certifier/target identities and a public HTTPS probe gateway are available.

---

## Why this uses T3N (not a side harness)

- Authenticated caller DID from T3N (`calling-user-did`), not caller-supplied identity
- Tenant-private KV for policies, secrets, qualifications, and protected data
- Contract-ID map ACLs and outbound-host grants
- WASI component boundary (`wasm32-wasip2`)
- Cluster time for expiry
- Claims digest over stored evidence
- Separate target signature and observer receipt before a qualification is persisted

---

## Bugs found while building on T3N

Full reproduction steps: https://github.com/Takumixbt/oriel/blob/main/docs/BUGS.md

1. **SDK dependency advisory chain** — `@terminal3/t3n-sdk@4.36.0` resolves a vulnerable archive-extraction path via Bytecode Alliance tooling (`npm audit`: 1 critical + 3 moderate). Oriel runtime does not execute that path; authors still inherit it on install/build.
2. **`MapVisibility` typed as `string`** — casing mistakes like `"private"` survive TypeScript despite wire values being `Private` / `Public`.
3. **Heavyweight clean install** — SDK pulls a large componentization/tooling tree (268 deps observed), slowing CI/onboarding for runtime-only clients.
4. **Stale map ACLs after new contract ID** — registration allocates a new numeric contract ID; private-map ACLs can strand a valid redeploy. Oriel’s registration script rewrites all four map ACLs automatically.

Also fixed on our side during live registration: agent-card functions must declare boolean `mutates` (and related descriptor fields). Preflight validation now catches that before network mutation.

---

## Maintainability / handover

**Preference: hand Oriel to Terminal 3 to host and maintain**, with author support for a 30-day transition.

Why this is operable after the challenge:

- Pure policy engine separated from T3N adapters
- Versioned JSON test packs
- Pinned Node lockfile + Rust toolchain
- CI for typecheck, TS tests, Rust tests, WASM build, hash check
- Docker/Render split: target holds signing key; gateway holds observer key
- Runbook covers first deploy, redeploy + ACL rewrite, key rotation, policy updates, monitoring, rollback, acceptance checklist

Details: https://github.com/Takumixbt/oriel/blob/main/docs/HANDOVER.md

MIT licensed. Deterministic verdicts — no proprietary model dependency for the security decision.

---

## Honest limits

A qualification proves that one DID and target-attested version label passed one test-pack version for one finite scope and interval. It is not universal agent safety or measured artifact provenance. Production next steps: signed deployment manifests / remote attestation, observer instrumentation of real tool/egress traces, transformed-leak detectors, scheduled requalification, portable receipts.

---

## Links for reviewers

- Repo: https://github.com/Takumixbt/oriel
- Architecture: https://github.com/Takumixbt/oriel/blob/main/docs/ARCHITECTURE.md
- Threat model: https://github.com/Takumixbt/oriel/blob/main/docs/THREAT_MODEL.md
- Bugs: https://github.com/Takumixbt/oriel/blob/main/docs/BUGS.md
- Handover: https://github.com/Takumixbt/oriel/blob/main/docs/HANDOVER.md
- T3 onboarding: https://go.terminal3.io/adk-community
- T3 quickstart: https://docs.terminal3.io/developers/adk/get-started/quickstart
