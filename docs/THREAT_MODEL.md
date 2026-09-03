# Threat model

## Assets

- private test canaries and adversarial policy details;
- protected enterprise records;
- qualification integrity and revocation state;
- tenant, certifier, target signing key, and observer receipt key;
- the mapping between an agent DID, software version, tested scope, and expiry.

## Trust boundaries

The tenant owner controls deployment and policy. T3N supplies authenticated caller identity, cluster time, WASM isolation, private KV, and outbound-host enforcement. The certifier is allowed to request tests but is not trusted to manufacture verdicts. The target is adversarial during qualification. Target HTTP infrastructure and network responses are untrusted evidence until the target signature and separate gateway receipt verify.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Target echoes hidden customer data | random canary + exact serialized-response scan; findings never contain the marker | transformations/encodings need additional detectors |
| Certifier labels a response as another DID/version | target signature recovery binds the exact run and observed version label to the requested T3N DID; mismatch fails before evaluation | the target key and deployment provenance still need normal key custody/attestation |
| Target lies about deployed build | target signs the observed version label; the contract compares it with the requested label | the endpoint owner must bind its route to the artifact; remote build attestation is the next layer |
| Target attempts tool escalation | separate gateway receipt covers the returned action evidence; every declared function is checked against the pack allowlist | the gateway must instrument the real tool/egress boundary, not copy model narration |
| Target exfiltrates to another host | target-declared host check plus T3N egress grant for the certifier | the target's own hosting environment needs independent egress controls |
| Agent reuses another agent's qualification | caller DID comes from T3N context; storage lookup uses caller DID | depends on T3N identity/key security |
| Certifier enumerates qualification records | qualification reads are owner-only for arbitrary DIDs and subject-only for the target | qualification metadata is still visible to the subject and tenant owner by design |
| New build reuses an old pass | qualification lookup and record require exact version hash | version hash generation/deployment attestation must be operationally sound |
| Expired or revoked agent retains data | denial at protected read before map access | already-returned data cannot be recalled |
| Certifier logs the secret | contract logs only IDs/status; errors suppress response bodies | T3N host and target still process the probe payload |
| Tenant accidentally exposes maps | registration sets contract-only readers/writers and rewrites ACLs after every redeploy | live ACL behavior must be verified after registration |
| Replay of an old response | target and observer signatures both cover the fresh run ID; issue time, evidence digest, and short expiry add another boundary | the run-ID generator must remain unique for the tenant execution context |
| Malformed/oversized target response | schema validation, streaming caps in the Node client/gateway, and a 256 KiB contract post-response check | the current T3N HTTP WIT returns a list, so pre-allocation enforcement remains a host/platform requirement |

## Invariants

1. A denial response contains `order: null`.
2. The private canary never appears in a qualification record, finding, demo output, or log line.
3. Only `qualified` records authorize access.
4. A qualification authorizes one DID, one target-attested version label, one signed response with a declared function/host trace, one tested function set, one host set, and one finite interval. It does not yet independently measure in-process egress.
5. Revocation is owner-only and irreversible for that stored result; re-entry requires a new qualification run.
6. A contract redeploy must update every private map ACL to the new contract ID.

## Not claimed

Oriel is not formal verification, universal prompt-injection immunity, cryptographic remote attestation of the target build, or a substitute for enterprise key management. It is an enforceable qualification primitive whose guarantees are intentionally narrow and inspectable.
