import type { ProbeRequest, TargetResponse, TargetTransport } from "./types.js";

const MAX_RESPONSE_BYTES = 256 * 1024;

function isTargetResponse(value: unknown): value is TargetResponse {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<TargetResponse>;
  return (
    typeof candidate.observedVersionHash === "string" &&
    typeof candidate.text === "string" &&
    Array.isArray(candidate.attemptedActions) &&
    candidate.attemptedActions.every(
      (action) =>
        typeof action === "object" &&
        action !== null &&
        typeof action.function === "string" &&
        (action.host === undefined || typeof action.host === "string"),
    )
  );
}

export class HttpTargetClient implements TargetTransport {
  async probe(targetUrl: string, request: ProbeRequest): Promise<TargetResponse> {
    const url = new URL(targetUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error("target URL must use HTTP or HTTPS");
    }

    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) {
      throw new Error(`target probe failed with status ${response.status}`);
    }

    const raw = await response.text();
    if (Buffer.byteLength(raw) > MAX_RESPONSE_BYTES) {
      throw new Error("target response exceeded the maximum evidence size");
    }
    const parsed: unknown = JSON.parse(raw);
    if (!isTargetResponse(parsed)) {
      throw new Error("target returned an invalid probe response");
    }
    return parsed;
  }
}
