# Judge-side critique and answers

## “This is a test harness, not an enterprise agent.”

The certifier is an autonomous enterprise control-plane agent: it receives authority to test target agents but cannot revoke or access protected data. Its useful output is not prose; it causes T3N to admit or deny another agent. The protected capability makes the test operational.

## “The target can fake its version and action trace.”

The target can no longer relabel itself as another T3N DID: its recoverable
secp256k1 signature is checked against the requested DID and the observed
version label. The returned action evidence is also covered by a separate
observer receipt. The target can still lie about which binary owns the key or
omit an action that happened outside the returned evidence. The remaining
production requirement is operational separation: the gateway must instrument
the real tool/egress boundary and must not share its observer key with the
target process. The included `agent` and `gateway` runtime roles make that
topology explicit; `combined` exists only for the local fixture.

## “The 256 KiB limit is not enforced before T3N buffers the HTTP body.”

Correct: the current T3N HTTP WIT exposes the response as a `list<u8>`, so the
contract can only reject after that host boundary. Oriel sends an explicit
maximum-size header, enforces streaming limits in the Node client and gateway,
and documents the remaining platform-side requirement instead of presenting a
post-boundary check as a complete memory defense.

## “A canary check is too simple.”

The canary is a crisp negative control that proves private test data changes access. The architecture supports versioned test packs; semantic leakage, policy-specific simulators, and behavioral sequences can be added without changing the admission model. A deterministic v1 is easier to audit and hand over than an opaque model-scored claim.

## “Why not just write an allowlist?”

An allowlist grants access based on configured intent. Oriel additionally requires evidence that the exact build behaved within that allowlist under a private adversarial test. Both are necessary: policy defines the boundary; qualification proves observed behavior; T3N enforces the result.

## “Why would an enterprise expose a target to this?”

The probe protocol can address a staging deployment, pre-production release, or sandboxed replica. The qualification remains bound to the resulting version hash. A production integration should pair it with deployment attestation before promotion.

## “The certifier sees the canary in the HTTP payload.”

In the live design the certifier invokes the WASM contract but does not receive map contents or the raw probe. The T3N contract reads and transmits the canary. Public results contain only codes and digests. The T3N host and target necessarily process the probe and remain in the trust model.

## “Can a pass last forever?”

No. The pack sets a finite TTL, admission uses T3N cluster time, version drift misses the record, and the owner can revoke immediately.

## “Is the demo doing real work or printing scripted JSON?”

The demo starts a real HTTP server, sends a fresh private probe, evaluates the returned actions, writes records into the reference store, gates a protected record, changes the requested version, revokes state, and repeats access. The same core rules are independently implemented and tested in Rust for the deployable component.

## “What keeps this maintainable?”

The security engine is pure, adapters are thin, packs are versioned JSON, CI executes both stacks, all dependencies are pinned/locked, deployment is containerized, and the handover runbook names the sharpest platform issue: map ACLs must follow every new contract ID.
