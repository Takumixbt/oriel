# Oriel

Qualification infrastructure for autonomous agents on T3N.

An enterprise can require an agent to pass a private adversarial test before that exact agent identity and version label can access a protected capability. Qualifications are short-lived, scope-bound, revocable, and enforced at access time.

![Oriel architecture](docs/assets/architecture.svg)

## How it works

1. A tenant stores policy, a secret canary, qualifications, and protected data in private T3N maps.
2. An Oriel certifier invokes a WASM contract that probes the target through a separate observer gateway.
3. The target signs its response; the gateway receipts the returned evidence with a separate key.
4. A deterministic evaluator checks leakage, version mismatch, unauthorized functions, and unauthorized hosts.
5. The protected function admits the caller only when identity, version, scope, host, expiry, and revocation all pass.

## Quick start

Requirements: Node.js 22+, npm, Rust, `wasm32-wasip2`.

```bash
npm install
npm run demo
npm test
npm run contract:test
npm run contract:build
```

`npm run demo` runs the full local lifecycle: vulnerable target fails, hardened target qualifies, protected access succeeds, version drift and revocation deny with no data.

## Repository layout

| Path | Purpose |
|---|---|
| `contract/` | Rust/WASI T3N contract and policy engine |
| `agent/` | Qualification engine, HTTP adapter, CLI, tests |
| `targets/` | Vulnerable and hardened target fixtures |
| `test-packs/` | Versioned qualification policy |
| `scripts/` | Registration, grants, qualification, access, revocation |
| `docs/` | Architecture, threat model, probe protocol, bugs |

## Live T3N deployment

```bash
cp .env.example .env
npm run contract:build
npm run live:preflight
npm run live:register
# set ORIEL_TENANT_DID from output
npm run live:preflight -- --live
npm run live:grant
npm run live:qualify
npm run live:protected
```

Deploy the target in `agent` mode and a separate `gateway` in front of it. See [operations](docs/OPERATIONS.md), [architecture](docs/ARCHITECTURE.md), and [threat model](docs/THREAT_MODEL.md).

MIT licensed.
