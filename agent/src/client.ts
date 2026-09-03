import type { ProbeRequest, TargetResponse, TargetTransport } from "./types.js";
import {
  MAX_ATTESTATION_BYTES,
  MAX_RESPONSE_BYTES,
  MAX_SCOPE_ENTRY_BYTES,
  MAX_TARGET_ACTIONS,
  MAX_TARGET_TEXT_BYTES,
} from "./limits.js";

function isTargetResponse(value: unknown): value is TargetResponse {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<TargetResponse>;
  return (
    typeof candidate.observedVersionHash === "string" &&
    candidate.observedVersionHash.length > 0 &&
    candidate.observedVersionHash.length <= MAX_SCOPE_ENTRY_BYTES &&
    typeof candidate.text === "string" &&
    candidate.text.length <= MAX_TARGET_TEXT_BYTES &&
    Array.isArray(candidate.attemptedActions) &&
    candidate.attemptedActions.length <= MAX_TARGET_ACTIONS &&
    typeof candidate.targetSignature === "string" &&
    candidate.targetSignature.length > 0 &&
    candidate.targetSignature.length <= MAX_ATTESTATION_BYTES &&
    typeof candidate.observerSignature === "string" &&
    candidate.observerSignature.length > 0 &&
    candidate.observerSignature.length <= MAX_ATTESTATION_BYTES &&
    candidate.attemptedActions.every(
      (action) =>
        typeof action === "object" &&
        action !== null &&
        typeof action.function === "string" &&
        action.function.length > 0 &&
        action.function.length <= MAX_SCOPE_ENTRY_BYTES &&
        (action.host === undefined ||
          (typeof action.host === "string" &&
            action.host.length > 0 &&
            action.host.length <= MAX_SCOPE_ENTRY_BYTES)),
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

    const raw = await readCappedBody(response);
    const parsed: unknown = JSON.parse(raw);
    if (!isTargetResponse(parsed)) {
      throw new Error("target returned an invalid probe response");
    }
    return parsed;
  }
}

async function readCappedBody(response: Response): Promise<string> {
  if (response.body === null) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("target response exceeded the maximum evidence size");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(body);
}
