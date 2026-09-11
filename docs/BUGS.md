# Bugs and integration findings

These are reproducible findings from building Oriel against Terminal 3's SDK on Node 22. The first snapshot used `@terminal3/t3n-sdk@4.36.0` on 31 August 2026; the current repo baseline is `@terminal3/t3n-sdk@5.2.0` (the version in the current Terminal 3 quickstart), verified on 11 September 2026. Findings are reported separately from Oriel's own limitations, with resolution status called out where the SDK changed. No issue is presented as a confirmed server vulnerability where only client-side evidence is available.

## 1. Historical archive-extraction advisory (resolved by SDK upgrade)

**Severity:** dependency-chain critical in the historical `4.36.0` tree; resolved in the current lockfile

**Reproduce:**

```bash
npm ci --include=dev
npm audit --json
npm ls @terminal3/t3n-sdk @bytecodealliance/jco @bytecodealliance/componentize-js @bytecodealliance/weval decompress --all
```

**Observed in the historical snapshot:** `npm audit` exited with code 1 and reported one critical plus three moderate advisories. The resolved path was `@terminal3/t3n-sdk@4.36.0` → `@bytecodealliance/jco` → `@bytecodealliance/componentize-js` → `@bytecodealliance/weval` → `decompress@4.2.1`.

The advisories include archive path traversal/link creation (for example GHSA-mp2f-45pm-3cg9). `npm audit fix --dry-run` does not remove the findings.

**Current status:** upgrading Oriel to `@terminal3/t3n-sdk@5.2.0` removed the vulnerable chain; `npm ci --include=dev` succeeds and `npm audit` reports zero vulnerabilities for the checked-in lockfile. Oriel still does not extract untrusted archives, and build/componentization tooling remains separate from the target runtime.

## 2. Map visibility type is too broad to catch casing errors

**Severity:** developer-experience / deployment reliability

**Location:** SDK `MapVisibility = string`

**Reproduce:** inspect `node_modules/@terminal3/t3n-sdk/dist/index.d.ts` or compile a map request with `visibility: "private"`. The declaration accepts it because `MapVisibility` is `string`, even though the same declaration documents the canonical wire values as `Private` and `Public`.

**Observed:** invalid casing passes TypeScript instead of producing a compile-time error. The exact backend response for the invalid value still needs a credentialed testnet check, so this report deliberately labels the confirmed defect as a client type-safety gap rather than claiming a specific server error.

**Impact and action:** a deployment typo can reach runtime and fail late, or create an operator ambiguity around map visibility. Export a literal union matching the wire values and add compile-time examples/tests next to `maps.create` and `maps.update`.

## 3. SDK install is disproportionately large for a client

**Severity:** maintainability / CI efficiency

**Reproduce:** remove `node_modules` and run `npm ci` on a clean Windows Node 22 environment, then record the install duration and run `npm ls --all --depth=0`.

**Observed in the historical snapshot:** the build resolved 268 total dependencies and fetched platform-specific compiler/parser/componentization packages; the clean install took approximately seven minutes on the available connection. After moving to SDK `5.2.0`, the current lockfile installs 23 package nodes in this environment and no longer carries the old componentization dependency tree.

**Impact and action:** the upgrade materially improves onboarding and CI time. The remaining platform-level opportunity is still to publish a clearly separated runtime client and authoring/componentization package; Oriel mitigates the risk by pinning the lockfile and keeping the target runtime separate from the contract build.

## 4. Contract-ID ACL rotation remains a sharp edge

**Severity:** availability / authorization configuration

**Reproduce:**

1. Register a contract and note contract ID A.
2. Create or update private maps so their reader/writer ACLs contain A.
3. Register a replacement at the same tail and note the new contract ID B.
4. Invoke B before updating every map ACL.

**Observed:** registration produces a new numeric ID while private maps authorize numeric IDs. A redeploy can therefore strand a valid contract behind stale ACLs until all ACLs are rotated.

**Impact and action:** this is an availability and authorization-configuration footgun, not an Oriel finding—the Oriel registration script updates all four map ACLs and refuses ambiguous map lifecycle states. The platform could make registration plus ACL migration transactional, or warn when a tail's maps still reference an older contract ID.

## Resolved Oriel integration defect found during live registration

**Symptom:** the first testnet registration attempt was rejected with `descriptor malformed: function \`run-qualification\` field \`mutates\` must be a boolean`.

**Cause:** the initial public agent card omitted the required boolean `mutates` field on each function descriptor. The local demo and offline contract tests could not catch this because descriptor validation happens at T3N registration time.

**Fix:** the card now declares `auth`, boolean `mutates`, object `params_schema`, object `returns`, and array `errors`/`examples` fields. It uses `mutates: true` for qualification/revocation and `mutates: false` for read/protected-action functions. The registration path now validates those fields before any network mutation. This is recorded as an Oriel integration defect, not attributed to T3N.

**Recovery detail:** the failed `0.1.0` registration consumed that monotonically increasing contract version before descriptor publication failed; retrying `0.1.0` was rejected as not higher than the current version. Oriel used `0.1.1` for an emergency descriptor repair, then advanced the coherent contract/WIT/card release to `0.1.2` for the clean repeatable registration. Testnet registration and all four map ACL updates succeeded for historical contract ID `824`; the current source is `0.2.0` and needs a new registration/ACL rotation.

**Prevention:** registration now validates every function descriptor field that the live node required before connecting or mutating T3N, checks the card version against the source release, and a unit test covers the preflight path. T3N could make contract registration plus descriptor publication atomic or offer a documented recovery/rollback operation for partial registration. The corrected `0.1.2` registration and grant path are historical; the `0.2.0` registration must be repeated because it adds target/observer attestations and a required protected-call host.

## Oriel limitations (not platform bugs)

- Live `calling-user-did`, map ACL, descriptor, outbound-host, and target/observer attestation behavior still need a credentialed `0.2.0` testnet execution.
- The target now signs its observed version label and response, and a separate gateway receipts the returned evidence; production still needs trusted tool/egress observation plus signed build manifests or remote attestation to prove the actual behavior and artifact binding.
- Exact canary matching does not detect transformed/encoded leakage.
- The contract trusts the observer gateway's receipt, so the gateway must instrument the real tool/egress boundary and must not share its key with the target.
- The current T3N HTTP WIT returns a buffered `list<u8>`; the contract cannot enforce a pre-allocation body limit until the host exposes streaming or a response-size field.
- Qualification results are tenant-local records, not portable credentials.
