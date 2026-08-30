# Bugs and integration findings

These are reproducible findings from building Oriel against `@terminal3/t3n-sdk@4.36.0` on Node 22. They are reported separately from Oriel's own known limitations.

## 1. SDK dependency tree contains vulnerable archive extraction

**Severity:** dependency-chain critical (not reached by Oriel runtime flows)

**Command:** `npm audit --json`

The pinned SDK resolves through `@bytecodealliance/jco` → `@bytecodealliance/componentize-js` → `@bytecodealliance/weval` → `decompress@4.2.1`. npm reports one critical and three moderate vulnerabilities, including archive path traversal/link creation (for example GHSA-mp2f-45pm-3cg9).

`npm audit fix --dry-run` did not remove the advisories. Oriel does not extract untrusted archives and does not invoke this componentization path at runtime, but downstream users still inherit the flagged package. Recommended sponsor action: update/pin the Bytecode Alliance chain to a non-vulnerable extraction implementation, publish a patched SDK, and add dependency audit policy to SDK CI.

## 2. Map visibility type is too broad to catch casing errors

**Severity:** developer-experience / deployment reliability

**Location:** SDK `MapVisibility = string`

The type definitions document `Private`/`Public`, but `MapVisibility` accepts every string. A typo or wrong casing compiles and fails only at contract execution. Recommended action: export a literal union matching the exact wire values and add examples next to `maps.create`.

## 3. SDK install is disproportionately large for a client

**Severity:** maintainability / CI efficiency

A clean Windows install resolved 268 total dependencies and fetched platform-specific compiler/parser/componentization packages; it took approximately seven minutes on the available connection. Many irrelevant platform packages are optional and ultimately discarded. This conflicts with the challenge's “earlier, faster and more efficient” and post-challenge maintenance goals.

Recommended action: separate runtime client APIs from WASM authoring/componentization tooling, or expose a lightweight runtime package.

## 4. Contract-ID ACL rotation remains a sharp edge

**Severity:** availability / authorization configuration

Each contract registration yields a new numeric contract ID while private maps authorize numeric IDs. A redeploy can therefore strand a valid contract behind stale ACLs. Oriel's registration script always rewrites all four map ACLs after deployment, but the platform could warn when a registered tail has maps still referencing an older contract ID.

## Oriel limitations (not platform bugs)

- Live `calling-user-did`, map ACL, descriptor, and outbound-host behavior still need a credentialed testnet execution.
- The target self-reports its version; production should add signed build manifests or remote attestation.
- Exact canary matching does not detect transformed/encoded leakage.
- The target adapter trusts the target to report attempted actions; production should combine target reports with independently observed tool/egress traces.
- Qualification results are tenant-local records, not portable credentials.
