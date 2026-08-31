# Threat model

## Assets

- private test canaries and adversarial policy details;
- protected enterprise records;
- qualification integrity and revocation state;
- tenant, certifier, and target signing keys;
- the mapping between an agent DID, software version, tested scope, and expiry.

## Trust boundaries

The tenant owner controls deployment and policy. T3N supplies authenticated caller identity, cluster time, WASM isolation, private KV, and outbound-host enforcement. The certifier is allowed to request tests but is not trusted to manufacture verdicts. The target is adversarial during qualification. Target HTTP infrastructure and network responses are untrusted evidence.

## Threats and controls

| Threat | Control | Residual risk |
|---|---|---|
| Target echoes hidden customer data | random canary + exact serialized-response scan; findings never contain the marker | transformations/encodings need additional detectors |
| Target lies about deployed build | observed version must equal requested hash | target-supplied version is not yet cryptographically attested |
| Target attempts tool escalation | every attempted function checked against pack allowlist | adapter must faithfully report attempted actions |
| Target exfiltrates to another host | attempted host check plus T3N egress grant for certifier | target's own hosting environment needs independent egress controls |
| Agent reuses another agent's qualification | caller DID comes from T3N context; storage lookup uses caller DID | depends on T3N identity/key security |
| New build reuses an old pass | qualification lookup and record require exact version hash | version hash generation/deployment attestation must be operationally sound |
| Expired or revoked agent retains data | denial at protected read before map access | already-returned data cannot be recalled |
| Certifier logs the secret | contract logs only IDs/status; errors suppress response bodies | T3N host and target still process the probe payload |
| Tenant accidentally exposes maps | registration sets contract-only readers/writers and rewrites ACLs after every redeploy | live ACL behavior must be verified after registration |
| Replay of an old response | run ID, issue time, evidence digest, and short expiry | target protocol does not yet sign run IDs |
| Malformed/oversized target response | schema validation and 256 KiB limit in reference client | live host HTTP limit is platform-dependent |

## Invariants

1. A denial response contains `order: null`.
2. The private canary never appears in a qualification record, finding, demo output, or log line.
3. Only `qualified` records authorize access.
4. A qualification authorizes one DID, one version, one tested function set, one host set, and one finite interval.
5. Revocation is owner-only and irreversible for that stored result; re-entry requires a new qualification run.
6. A contract redeploy must update every private map ACL to the new contract ID.

## Not claimed

Oriel is not formal verification, universal prompt-injection immunity, cryptographic remote attestation of the target build, or a substitute for enterprise key management. It is an enforceable qualification primitive whose guarantees are intentionally narrow and inspectable.
