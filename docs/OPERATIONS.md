# Operations

## Prerequisites

- T3N tenant-owner, certifier, and target-agent keys (distinct DIDs)
- Separate observer receipt key for the probe gateway
- Test credits on execution identities
- Public HTTPS probe-gateway and upstream target endpoints
- Node.js 22+, Rust, `wasm32-wasip2` for source builds

Never commit keys or `.env`. Scripts auto-load the gitignored root `.env` and never print private key material.

## First deployment

1. Deploy the target in `agent` mode with `ORIEL_TARGET_ATTESTATION_KEY` set to the target agent key; keep the vulnerable route disabled.
2. Deploy a separate `gateway` instance with `ORIEL_UPSTREAM_TARGET_URL`, `ORIEL_TARGET_DID`, and `ORIEL_OBSERVER_ATTESTATION_KEY`. The gateway is the URL supplied to Oriel; it must not receive the target private key.
3. Copy `.env.example` to `.env` and set `T3N_API_KEY`, `ORIEL_AGENT_KEY`, `TARGET_AGENT_KEY`, `ORIEL_TARGET_DID`, `T3N_ENV`, `ORIEL_TARGET_URL`, and `ORIEL_OBSERVER_ATTESTATION_KEY`.
4. Run `npm ci && npm run check`.
5. Run `npm run live:preflight` before any network mutation.
6. Run `npm run live:register` once; record tenant DID and contract ID.
7. Set `ORIEL_TENANT_DID`, then `npm run live:preflight -- --live`.
8. Run `npm run live:grant`, `npm run live:qualify`, `npm run live:protected`, `npm run live:revoke`, and repeat the protected call to confirm denial.

## Redeployment

T3N assigns a new contract ID on registration. Use `live:register` for redeploys: it rewrites reader/writer ACLs for all four maps. Increment the coherent source version, rebuild, run `npm run contract:hash`, register, republish the descriptor, rerun grants, and repeat the lifecycle test.

## Key rotation

- **Owner:** migrate tenant administration under the T3N-supported process.
- **Certifier:** authenticate the new DID and replace its grant.
- **Target:** treat as a new agent identity; update the gateway target DID and rerun qualification.
- **Observer:** rotate the gateway secret and the matching private map entry together.

## Policy updates

Add a new pack version instead of mutating an existing one. Revoke qualifications when policy meaning changes.

## Monitoring

Track qualification status, denial reasons, expiry rate, target HTTP failures, and contract logs. Never log probe payloads, response bodies, API keys, or canaries.
