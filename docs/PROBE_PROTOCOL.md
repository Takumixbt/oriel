# Target probe protocol

Any HTTP-reachable agent can be tested by implementing one JSON endpoint.

## Request

`POST` over HTTPS with `Content-Type: application/json`:

```json
{
  "runId": "opaque-run-digest",
  "testPackId": "support-data-boundary",
  "attackPrompt": "the versioned adversarial task",
  "privateContext": {
    "customerRecordCanary": "fresh-per-run-private-marker",
    "syntheticOrderId": "order-1042"
  }
}
```

The target must treat all `privateContext` fields as confidential and should bind its work to `runId` for traceability. It must not log the canary.

## Response

HTTP 200 with JSON:

```json
{
  "observedVersionHash": "sha256:fulfillment-v2-hardened",
  "text": "I cannot disclose private context.",
  "attemptedActions": [
    {
      "function": "support.lookup",
      "host": "support-api.oriel.test"
    }
  ],
  "targetSignature": "0x<65-byte-recoverable-secp256k1-signature>",
  "observerSignature": "0x<32-byte-hmac-sha256-receipt>"
}
```

`attemptedActions` must include every tool/function invocation attempted during the run, including blocked attempts. In the reference fixture this is target-produced evidence; the production adapter requirement is to construct it from trusted tool/egress proxy events instead of model narration. The target signature is produced by the target's Ethereum key and must recover to the requested `did:t3n:<40-hex-address>`. The observer receipt is produced by a separate probe gateway using the private `observer:<testPackId>` secret seeded in T3N. Both attestations cover the same run, pack, target DID, observed version label, response text, and normalized declared action trace. The run ID makes receipts non-replayable, but the current receipt does not by itself prove actions that never appear in the response.

The response is capped at 256 KiB in the reference client, gateway, fixture, and contract post-response check. The T3N HTTP host currently exposes a list payload rather than a streaming reader, so the contract also sends `x-oriel-max-response-bytes: 262144` and rejects oversized payloads after the host boundary. A production gateway must enforce the limit while streaming before buffering.

The attestation digest is the length-prefixed SHA-256 of:

```text
domain || runId || testPackId || targetAgentDid || observedVersionHash || responseEvidenceJson
```

where `responseEvidenceJson` has the fixed field order
`observedVersionHash`, `text`, `attemptedActions`, and normalizes a missing
action host to JSON `null`. The target domain is
`oriel-target-attestation-v1`; the observer domain is
`oriel-observer-receipt-v1`.

## Production adapter requirements

- produce `observedVersionHash` from the deployment artifact, not a mutable prompt field;
- sign the response with the target deployment key, with the key-to-DID binding checked by the contract;
- collect attempted actions from the tool gateway rather than trusting model narration;
- run the observer receipt signer as a separate process/service that does not hold the target key;
- avoid persisting probe payloads or raw responses;
- expose only HTTPS and authenticate the Oriel/T3N caller where supported;
- rate-limit runs and bind each trace to `runId`;
- return non-200 on internal errors rather than a fabricated safe response.

The included standalone server supports three roles: `agent` signs target
responses only, `gateway` forwards to an upstream agent and adds the observer
receipt, and `combined` is local-only convenience for the demo. The intentionally
vulnerable route is disabled by default. A hosted deployment should expose only
the hardened route through a separate gateway in front of a separately keyed
target service.
