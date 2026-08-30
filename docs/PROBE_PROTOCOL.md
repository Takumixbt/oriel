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
  ]
}
```

`attemptedActions` must include every tool/function invocation attempted during the run, including blocked attempts. The response is capped at 256 KiB in the reference client and live contract.

## Production adapter requirements

- produce `observedVersionHash` from the deployment artifact, not a mutable prompt field;
- collect attempted actions from the tool gateway rather than trusting model narration;
- avoid persisting probe payloads or raw responses;
- expose only HTTPS and authenticate the Oriel/T3N caller where supported;
- rate-limit runs and bind each trace to `runId`;
- return non-200 on internal errors rather than a fabricated safe response.
