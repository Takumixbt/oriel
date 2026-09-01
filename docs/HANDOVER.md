# Operations and handover

## Handover choice

Preferred path: hand Oriel to Terminal 3 to host and maintain, with the author available for a 30-day transition and feature roadmap. The code is MIT licensed, uses no proprietary service for verdicts, and is structured so the tenant owns policy and data.

## Required operator inputs

- one T3N tenant-owner key;
- one distinct Oriel certifier key;
- one distinct target-agent key;
- one separate observer receipt key, stored in the gateway only;
- test credits on the identities that will execute the contract;
- a public HTTPS probe-gateway endpoint and an HTTPS upstream target endpoint;
- Node.js 22+, Rust, and `wasm32-wasip2` for source builds.

Never commit keys or `.env`. The scripts auto-load the gitignored root `.env` and never print private key material.

## First deployment

1. Deploy the target in `agent` mode with `ORIEL_TARGET_ATTESTATION_KEY` set to the target agent key; keep the vulnerable route disabled.
2. Deploy a separate instance in `gateway` mode with `ORIEL_UPSTREAM_TARGET_URL`, `ORIEL_TARGET_DID`, and `ORIEL_OBSERVER_ATTESTATION_KEY`. The gateway is the URL supplied to Oriel; it must not receive the target private key.
3. Copy `.env.example` to `.env`; set `T3N_API_KEY`, `ORIEL_AGENT_KEY`, `TARGET_AGENT_KEY`, `ORIEL_TARGET_DID`, `T3N_ENV`, `ORIEL_TARGET_URL`, and `ORIEL_OBSERVER_ATTESTATION_KEY`. `ORIEL_TARGET_DID` must be the DID derived from `TARGET_AGENT_KEY`; if the target service key is available, set `ORIEL_TARGET_ATTESTATION_KEY` to the same identity key.
4. Run `npm ci && npm run check`.
5. Run `npm run live:preflight` and fix any identity/role mismatch before making network mutations.
6. Run `npm run live:register` exactly once and record its tenant DID and contract ID.
7. Set `ORIEL_TENANT_DID` to the returned DID, then run `npm run live:preflight -- --live` to verify the observer secret stored in the private map.
8. Run `npm run live:grant`. It preserves other agent-auth rows through the SDK's read-merge-write helper.
9. Run `npm run live:qualify` and inspect the target signature/observer-receipt-backed qualification result.
10. Run `npm run live:protected` and confirm the qualified target receives the synthetic record.
11. Run `npm run live:revoke`, then repeat the protected call and confirm denial.

## Redeployment

T3N assigns a new contract ID on registration. Always use `live:register` for a redeploy: it rewrites reader/writer ACLs for all four maps to the new ID. Never register a replacement contract manually without updating map ACLs.

Increment the coherent source version (`contract-version.ts`, Rust, WIT, card, and package metadata), rebuild, run `npm run contract:hash`, register, republish the descriptor, rerun grants with the new version requirement, and repeat the full lifecycle test.

## Key rotation

- Owner key: migrate tenant administration under the T3N-supported process before decommissioning the old key.
- Certifier key: authenticate the new DID and replace its grant; do not give it owner/revoke rights.
- Target key: treat it as a new agent identity, update the target DID at the gateway, and rerun qualification.
- Observer key: rotate the gateway secret and the matching private T3N map entry together; never reuse it as a target key.

## Policy updates

Create a new pack version rather than mutating the meaning of an existing one. Update expiry, allowed functions, and allowed hosts narrowly. Existing qualifications remain bound to their recorded pack version and should be revoked when policy meaning changes.

## Monitoring

Track qualification status counts, denial reasons, expiry rate, target HTTP failures, and contract logs. Never log probe payloads, target response bodies, API keys, or canaries. Alert on repeated version mismatches, host violations, and ACL changes.

## Rollback

Disable or revoke access first. Restore the previous contract version and its grants only after its contract ID is granted map access. A rollback never reuses a qualification from a different version.

## Acceptance checklist

- CI is green.
- Three DIDs are distinct.
- All maps report active with the current contract ACL.
- Vulnerable control fails with three expected findings.
- Hardened control has a valid target signature and separate gateway receipt over the exact response evidence, then qualifies.
- Exact build succeeds on protected call.
- Drift, expiry, impersonation, wrong scope, and revocation deny with null data.
- No output or log contains the canary.
