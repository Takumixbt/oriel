# Verification snapshot

This is the shortest reproducible path for a reviewer. It is intentionally separate from the live deployment runbook: everything here runs locally with synthetic data and no credentials.

## One-command check

```bash
npm ci --include=dev
npm run check
```

`npm run check` performs:

| Check | Expected evidence |
|---|---|
| TypeScript | strict `tsc --noEmit` passes |
| Agent lifecycle | 11 tests pass |
| Rust policy engine | 14 unit tests + 1 doc test pass |
| WASI contract | `wasm32-wasip2` release build succeeds |
| Release identity | `npm run contract:hash` prints the canonical hash below |

## Demo path

```bash
npm run demo
```

The demo creates an ephemeral HTTP target and exercises the complete admission lifecycle:

1. The vulnerable fixture leaks a fresh canary and attempts an unauthorized function and host; qualification fails with three reason codes.
2. The hardened fixture returns a target-signed response and receives a separate observer receipt; qualification succeeds.
3. The exact qualified DID, version, capability, and host scope can read the synthetic order.
4. A different version is denied with `order: null`.
5. Owner revocation is applied.
6. The previously qualified version is denied with `order: null`.

The canary itself is never copied into findings or demo output.

## Current release evidence

- Source and agent-card version: `0.2.0`
- WASI artifact: `wasm32-wasip2` release component
- Artifact size: `305,597` bytes
- SHA-256: `eb39d5fabf27474644e969ff5bc76c238768b2898454c9b49d587bfb4ab17a6b`
- SDK: `@terminal3/t3n-sdk@5.2.0`
- Dependency audit: `npm audit` reports zero vulnerabilities for the checked-in lockfile
- CI: GitHub Actions runs typecheck, TypeScript tests, Rust tests, WASI build, and the contract hash

## Live boundary

The repository contains credential-safe scripts for registration, ACL setup, grants, qualification, protected access, and revocation. A live `0.2.0` transcript is intentionally not claimed here: it requires funded certifier/target identities, an observer receipt secret, and a public HTTPS probe gateway. The exact operator path is documented in [HANDOVER.md](HANDOVER.md).
