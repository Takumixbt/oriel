# Demo script

## 90-second judge walkthrough

**0:00 — Problem**

"Enterprise agents have identities and permissions, but access rarely depends on whether a target-attested version survived the enterprise's private tests. Oriel turns that test result into an admission decision."

**0:15 — Architecture**

Show the architecture diagram. Point out three separate DIDs: tenant owner, Oriel certifier, and target. Show four private T3N maps, the target signature, the separate observer gateway, and the WASM enforcement point. Say explicitly that the current gateway receipts returned HTTP evidence; a production adapter would source action events from a trusted tool/egress proxy.

**0:30 — Run**

```bash
npm run demo
```

The vulnerable target receives a hidden customer-record marker. It leaks the marker, attempts an unauthorized refund, and tries an unapproved host. Oriel returns only three finding codes—the secret itself is absent—and stores a failed record.

**0:50 — Harden and admit**

The same target identity deploys a hardened version label. It signs its response, receives a separate gateway receipt, refuses disclosure, and stays within the approved declared capability/host, earning a short-lived qualification. The protected order call now succeeds.

**1:05 — Prove enforcement**

The next unqualified version calls the same protected function and gets `qualification_not_found` with `order: null`. The owner revokes the hardened record; the previously valid build immediately gets `qualification_revoked`, again with `order: null`.

**1:20 — Close**

“This is not another security report. Oriel makes private, version-specific test performance a live condition of enterprise access. It is deterministic, T3N-native, Docker-deployable, CI-tested, and ready to hand over.”

## Screenshot checklist

Use the checked-in PNGs in `submission/screenshots/` (or regenerate with `npm run demo`, `npm test`, `npm run contract:test`, `npm run contract:hash`):

1. architecture diagram (`01-architecture.png`);
2. lifecycle overview (`02-lifecycle.png`);
3. vulnerable result with three finding codes (`03-vulnerable-failed.png`);
4. hardened result with `qualified` (`04-hardened-qualified.png`);
5. successful protected call showing synthetic order (`05-protected-allowed.png`);
6. version-drift denial with null order (`06-version-drift-denied.png`);
7. post-revocation denial with null order (`07-revocation-denied.png`);
8. green `npm test` and `cargo test` output (`08-npm-test.png`, `09-cargo-test.png`);
9. release contract hash (`10-contract-hash.png`);
10. live T3N registration/grant/qualification output once credentials are supplied.

Never include terminals or screenshots that expose environment variables, private keys, full probe payloads, or canaries.
