# Demo script

## 90-second judge walkthrough

**0:00 — Problem**

“Enterprise agents have identities and permissions, but access rarely depends on whether the exact deployed build survived the enterprise's private tests. Oriel turns that test result into an admission decision.”

**0:15 — Architecture**

Show the architecture diagram. Point out three separate DIDs: tenant owner, Oriel certifier, and target. Show four private T3N maps and the WASM enforcement point.

**0:30 — Run**

```bash
npm run demo
```

The vulnerable target receives a hidden customer-record marker. It leaks the marker, attempts an unauthorized refund, and tries an unapproved host. Oriel returns only three finding codes—the secret itself is absent—and stores a failed record.

**0:50 — Harden and admit**

The same target identity deploys a hardened version. It refuses disclosure and stays within the approved capability/host, earning a short-lived qualification. The protected order call now succeeds.

**1:05 — Prove enforcement**

The next unqualified version calls the same protected function and gets `qualification_not_found` with `order: null`. The owner revokes the hardened record; the previously valid build immediately gets `qualification_revoked`, again with `order: null`.

**1:20 — Close**

“This is not another security report. Oriel makes private, version-specific test performance a live condition of enterprise access. It is deterministic, T3N-native, Docker-deployable, CI-tested, and ready to hand over.”

## Screenshot checklist

1. architecture diagram rendered in README;
2. vulnerable result with three finding codes;
3. hardened result with `qualified` and expiry;
4. successful protected call showing synthetic order;
5. version-drift denial with null order;
6. post-revocation denial with null order;
7. green `npm test` and `cargo test` output;
8. live T3N registration/grant/qualification output once credentials are supplied.

Never include terminals or screenshots that expose environment variables, private keys, full probe payloads, or canaries.
