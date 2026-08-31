# Operations and handover

## Handover choice

Preferred path: hand Oriel to Terminal 3 to host and maintain, with the author available for a 30-day transition and feature roadmap. The code is MIT licensed, uses no proprietary service for verdicts, and is structured so the tenant owns policy and data.

## Required operator inputs

- one T3N tenant-owner key;
- one distinct Oriel certifier key;
- one distinct target-agent key;
- test credits on the identities that will execute the contract;
- a public HTTPS target endpoint;
- Node.js 22+, Rust, and `wasm32-wasip2` for source builds.

Never commit keys or `.env`. The scripts auto-load the gitignored root `.env` and never print private key material.

## First deployment

1. Deploy the target fixture or connect an enterprise target using the documented probe protocol.
2. Copy `.env.example` to `.env`; set `T3N_API_KEY`, `ORIEL_AGENT_KEY`, `TARGET_AGENT_KEY`, `T3N_ENV`, and `ORIEL_TARGET_URL`.
3. Run `npm ci && npm run check`.
4. Run `npm run live:register` exactly once and record its tenant DID and contract ID.
5. Set `ORIEL_TENANT_DID` to the returned DID.
6. Run `npm run live:grant`. It preserves other agent-auth rows through the SDK's read-merge-write helper.
7. Run `npm run live:qualify` and inspect the qualification result.
8. Run `npm run live:protected` and confirm the exact qualified target receives the synthetic record.
9. Run `npm run live:revoke`, then repeat the protected call and confirm denial.

## Redeployment

T3N assigns a new contract ID on registration. Always use `live:register` for a redeploy: it rewrites reader/writer ACLs for all four maps to the new ID. Never register a replacement contract manually without updating map ACLs.

Increment `CONTRACT_VERSION`, rebuild, register, republish the descriptor, rerun grants with the new version requirement, and repeat the full lifecycle test.

## Key rotation

- Owner key: migrate tenant administration under the T3N-supported process before decommissioning the old key.
- Certifier key: authenticate the new DID and replace its grant; do not give it owner/revoke rights.
- Target key: treat it as a new agent identity and rerun qualification.

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
- Hardened control qualifies.
- Exact build succeeds on protected call.
- Drift, expiry, impersonation, wrong scope, and revocation deny with null data.
- No output or log contains the canary.
