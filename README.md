# Oriel

**Qualification infrastructure for autonomous agents on T3N.**

Oriel lets an enterprise require an agent to pass a private, adversarial test before that exact agent identity and target-attested version label can access a protected capability. A passing result is short-lived, scope-bound, revocable, and enforced at the point of access—not filed away as a report.

> Agents should not inherit trust from a name, a vendor, or an old audit. They should earn narrowly scoped access with the exact build they are running now.

## The problem

Enterprises increasingly let agents read customer records, trigger workflows, or call internal services. Existing controls answer “who is this agent?” and “what was it configured to do?” They do not answer “did this deployed version survive our private tests, and should it still be admitted?”

Oriel adds that missing qualification layer:

1. A tenant stores a secret canary, test policy, qualification ledger, and protected data in private T3N maps.
2. A separate Oriel certifier invokes a T3N WASM contract, which sends an adversarial probe through a probe gateway to the target.
3. The target signs its response with its Ethereum/T3N identity and a separate gateway receipts the exact response evidence.
4. A deterministic evaluator checks secret leakage, version mismatch, declared function escalation, and declared host exfiltration.
5. The requested target DID + version label either receives a short-lived qualification or fails.
6. The protected function reads data only after the caller's T3N identity, version label, scope, expiry, and revocation state all pass.

![Oriel architecture](docs/assets/architecture.svg)

```mermaid
flowchart LR
    O[Enterprise owner] -->|policy + canary + grants| T[T3N private maps]
    C[Oriel certifier DID] -->|run qualification| W[Oriel WASM contract]
    W -->|private probe| G[Probe gateway • separate key]
    G -->|probe| A[Target agent DID + version]
    A -->|target-signed response| G
    G -->|separate observer receipt| W
    W -->|failed or qualified| T
    A -->|protected call| W
    W -->|only if exact qualification is live| D[Protected enterprise data]
```

## Why this is more than an agent scanner

- **Private tests:** the target never receives the policy store and public output never contains the canary.
- **Identity binding:** the protected path derives the caller DID from T3N `calling-user-did`; caller-supplied identity is not trusted.
- **Version-label binding:** a qualification for label `v2` cannot authorize a request for `v3`.
- **Cryptographic evidence binding:** a target signature must recover to the requested T3N DID, and a separate observer receipt must cover the same run and response.
- **Conditional access:** failure is enforced as denial, not displayed as a dashboard warning.
- **Least privilege:** qualification covers only tested functions and hosts.
- **Deterministic verdicts:** no external LLM is required for the security decision.

## Quick start

Requirements: Node.js 22+, npm, Rust, and the `wasm32-wasip2` target.

```bash
npm install
npm run demo
npm test
npm run contract:test
npm run contract:build
npm run contract:hash
```

`npm run demo` starts an ephemeral target and executes the whole lifecycle:

- vulnerable version leaks the canary and attempts an unauthorized refund/exfiltration → **failed**;
- hardened version preserves the declared boundary → **qualified**;
- qualified build reads the synthetic protected order → **allowed**;
- unqualified version drift → **denied with no data**;
- tenant revocation → **denied with no data**.

The TypeScript integration suite and Rust policy suite independently test the same admission invariants.

![Verified Oriel lifecycle](docs/assets/lifecycle.svg)

## Repository layout

| Path | Purpose |
|---|---|
| `contract/` | Rust/WASI T3N contract and pure policy engine |
| `agent/` | Local qualification engine, HTTP adapter, CLI, tests, and contract descriptor |
| `targets/` | Vulnerable and hardened target-agent fixtures |
| `test-packs/` | Versioned enterprise qualification policy |
| `scripts/` | Credential-safe registration, grants, qualification, access, and revocation |
| `docs/` | Architecture, threat model, probe protocol, bugs, operations |

## Live T3N deployment

```bash
cp .env.example .env
npm run contract:build
npm run contract:hash
npm run live:preflight
npm run live:register
# Copy tenantDid from the result into ORIEL_TENANT_DID.
npm run live:preflight -- --live
npm run live:grant
npm run live:qualify
npm run live:protected
npm run live:revoke
npm run live:protected
```

The local demo uses a combined signed fixture. For deployment, run `targets/src/server.ts` in `gateway` mode in front of a separately deployed `agent` mode target; the target holds only its signing key and the gateway holds only the observer receipt key. `Dockerfile` and `render.yaml` describe the gateway deployment shape.

See [operations](docs/OPERATIONS.md), [architecture](docs/ARCHITECTURE.md), and [threat model](docs/THREAT_MODEL.md).

MIT licensed.
