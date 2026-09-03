# GitHub repository description

Paste these into **Settings → General → About** on https://github.com/Takumixbt/oriel

## Short description (350 char limit)

```
Private qualification infrastructure for autonomous agents on T3N. Agents earn short-lived, scope-bound access only after passing tenant-private adversarial tests. Includes a wasm32-wasip2 contract, deterministic policy engine, target fixtures, and live deployment scripts.
```

## Topics (suggested)

```
t3n
terminal3
agents
wasm
rust
typescript
security
qualification
tee
enterprise
```

## Website

```
https://github.com/Takumixbt/oriel
```

## Longer writeup (for profile, README intro, or project pages)

Oriel is qualification infrastructure for autonomous agents on Terminal 3 Network (T3N).

Enterprises already know which agent identity is calling and what it was granted. They rarely know whether the exact deployed version survived private adversarial tests—and they rarely bind that result to runtime access.

Oriel closes that gap. A tenant stores private policy and test data on T3N. An Oriel certifier runs a WASM contract that probes a target agent through a separate observer gateway. The target signs its response; the gateway receipts the returned evidence. A deterministic evaluator checks for secret leakage, version mismatch, unauthorized functions, and unauthorized hosts. Only the exact target DID and version label that passes earns a short-lived, revocable qualification. Protected T3N functions admit the caller only when identity, version, scope, host, expiry, and revocation all pass.

The repository ships a full local demo (vulnerable vs hardened targets), 11 TypeScript lifecycle tests, 14 Rust contract tests, Docker/Render deployment shapes, and scripts for live testnet registration, grants, qualification, protected access, and revocation.
