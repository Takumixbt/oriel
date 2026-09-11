# Contributing

## Local gate

Run this before opening a change:

```bash
npm ci
npm run check
cargo clippy --manifest-path contract/Cargo.toml --all-targets -- -D warnings
wasm-tools validate contract/target/wasm32-wasip2/release/oriel_contract.wasm
```

## Security semantics

Changes to finding rules, record fields, key derivation, caller identity, expiry, revocation, map names, or protected responses require tests in both the pure Rust engine and the TypeScript lifecycle harness where applicable.

Never put a canary, raw probe payload, target response body, private key, or `.env` value in logs, fixtures, snapshots, issues, or screenshots. Denial tests must assert that protected data is absent.

## Test packs

Treat a published test pack as immutable. Add a new `packVersion` when meaning changes. Document new finding codes and update the threat model and handover guide.

## Contract releases

Increment the Rust constant, Cargo version, WIT package, registration script version, and agent card together. A live redeploy must update all private-map ACLs to the newly assigned contract ID and repeat the acceptance checklist.
