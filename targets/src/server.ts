import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import {
  DEMO_OBSERVER_KEY,
  ethereumDidFromPrivateKey,
  signObserverReceipt,
  signTargetResponse,
} from "../../agent/src/attestation.js";
import { MAX_RESPONSE_BYTES } from "../../agent/src/limits.js";
import type { ProbeRequest, TargetResponse } from "../../agent/src/types.js";
import {
  TARGET_PRIVATE_KEY,
  hardenedBehavior,
  HARDENED_VERSION,
  vulnerableBehavior,
  VULNERABLE_VERSION,
} from "./behavior.js";

const MAX_REQUEST_BYTES = 256 * 1024;

export interface TargetAttestationOptions {
  targetPrivateKey?: string;
  observerKey?: string;
}

interface TargetServerHandle {
  baseUrl: string;
  close: () => Promise<void>;
}

async function readJson(request: IncomingMessage): Promise<ProbeRequest> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > MAX_REQUEST_BYTES) throw new Error("request too large");
    chunks.push(buffer);
  }
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (typeof parsed !== "object" || parsed === null) throw new Error("invalid request");
  return parsed as ProbeRequest;
}

function json(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  if (Buffer.byteLength(payload) > MAX_RESPONSE_BYTES) {
    response.writeHead(413, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "response_too_large" }));
    return;
  }
  response.writeHead(status, { "content-type": "application/json" });
  response.end(payload);
}

export async function startTargetServer(
  port = 0,
  host = "127.0.0.1",
  enableVulnerableFixture = true,
  attestation: TargetAttestationOptions = {},
): Promise<TargetServerHandle> {
  const targetPrivateKey = attestation.targetPrivateKey ?? TARGET_PRIVATE_KEY;
  const observerKey = attestation.observerKey ?? DEMO_OBSERVER_KEY;
  const targetDid = ethereumDidFromPrivateKey(targetPrivateKey);
  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/health") {
        return json(response, 200, { status: "ok" });
      }
      if (request.method !== "POST") return json(response, 405, { error: "method_not_allowed" });
      const probe = await readJson(request);
      if (request.url === "/vulnerable/v1/run") {
        if (!enableVulnerableFixture) return json(response, 404, { error: "not_found" });
        return json(response, 200, attest(probe, vulnerableBehavior(probe), targetDid, targetPrivateKey, observerKey));
      }
      if (request.url === "/hardened/v2/run") {
        return json(response, 200, attest(probe, hardenedBehavior(probe), targetDid, targetPrivateKey, observerKey));
      }
      return json(response, 404, { error: "not_found" });
    } catch {
      return json(response, 400, { error: "invalid_probe" });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("target server did not bind");
  return {
    baseUrl: `http://${host}:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

/**
 * Run only the target side of the protocol. In production this process holds
 * the target signing key, while a separate probe gateway holds the observer
 * receipt key and adds the separate receipt.
 */
export async function startTargetAgentServer(
  port = 0,
  host = "127.0.0.1",
  enableVulnerableFixture = false,
  targetPrivateKey = TARGET_PRIVATE_KEY,
): Promise<TargetServerHandle> {
  const targetDid = ethereumDidFromPrivateKey(targetPrivateKey);
  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/health") {
        return json(response, 200, { status: "ok", role: "target-agent" });
      }
      if (request.method !== "POST") return json(response, 405, { error: "method_not_allowed" });
      const probe = await readJson(request);
      if (request.url === "/vulnerable/v1/run") {
        if (!enableVulnerableFixture) return json(response, 404, { error: "not_found" });
        return json(response, 200, signTargetOnly(probe, vulnerableBehavior(probe), targetDid, targetPrivateKey));
      }
      if (request.url === "/hardened/v2/run") {
        return json(response, 200, signTargetOnly(probe, hardenedBehavior(probe), targetDid, targetPrivateKey));
      }
      return json(response, 404, { error: "not_found" });
    } catch {
      return json(response, 400, { error: "invalid_probe" });
    }
  });
  return listen(server, port, host);
}

/**
 * The production-facing adapter. It forwards probes to a target agent and
 * adds an observer HMAC receipt over the exact target evidence. The observer
 * key is intentionally not passed to the upstream target.
 */
export async function startProbeGateway(
  port: number,
  host: string,
  upstreamUrl: string,
  targetDid: string,
  observerKey: string,
): Promise<TargetServerHandle> {
  const upstream = new URL(upstreamUrl);
  if (upstream.protocol !== "https:") throw new Error("gateway upstream URL must use HTTPS");
  if (observerKey.length < 16) throw new Error("observer receipt key must be at least 16 characters");
  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/health") {
        return json(response, 200, { status: "ok", role: "probe-gateway", targetDid });
      }
      if (request.method !== "POST") return json(response, 405, { error: "method_not_allowed" });
      const probe = await readJson(request);
      const upstreamResponse = await fetch(upstream, {
        method: "POST",
        headers: { "content-type": "application/json", "x-oriel-gateway": "true" },
        body: JSON.stringify(probe),
        signal: AbortSignal.timeout(10_000),
      });
      if (!upstreamResponse.ok) return json(response, 502, { error: "target_unavailable" });
      const parsed: unknown = JSON.parse(await readCappedBody(upstreamResponse));
      if (!isSignedTargetResponse(parsed)) return json(response, 502, { error: "target_attestation_missing" });
      const unsigned = { ...parsed, observerSignature: "" };
      return json(response, 200, {
        ...unsigned,
        observerSignature: signObserverReceipt(
          probe.runId,
          probe.testPackId,
          targetDid,
          unsigned,
          observerKey,
        ),
      });
    } catch {
      return json(response, 400, { error: "invalid_probe" });
    }
  });
  return listen(server, port, host);
}

function signTargetOnly(
  request: ProbeRequest,
  response: Omit<TargetResponse, "targetSignature" | "observerSignature">,
  targetDid: string,
  targetPrivateKey: string,
): TargetResponse {
  const unsigned = { ...response, targetSignature: "", observerSignature: "" } as TargetResponse;
  return {
    ...unsigned,
    targetSignature: signTargetResponse(
      request.runId,
      request.testPackId,
      targetDid,
      unsigned,
      targetPrivateKey,
    ),
  };
}

function isSignedTargetResponse(value: unknown): value is TargetResponse {
  if (typeof value !== "object" || value === null) return false;
  const response = value as Partial<TargetResponse>;
  return typeof response.observedVersionHash === "string"
    && typeof response.text === "string"
    && Array.isArray(response.attemptedActions)
    && typeof response.targetSignature === "string"
    && response.targetSignature.length > 0;
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

async function listen(server: ReturnType<typeof createServer>, port: number, host: string): Promise<TargetServerHandle> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("target server did not bind");
  return {
    baseUrl: `http://${host}:${address.port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

function attest(
  request: ProbeRequest,
  response: Omit<TargetResponse, "targetSignature" | "observerSignature">,
  targetDid: string,
  targetPrivateKey: string,
  observerKey: string,
): TargetResponse {
  const unsigned = { ...response, targetSignature: "", observerSignature: "" } as TargetResponse;
  return {
    ...unsigned,
    targetSignature: signTargetResponse(
      request.runId,
      request.testPackId,
      targetDid,
      unsigned,
      targetPrivateKey,
    ),
    observerSignature: signObserverReceipt(
      request.runId,
      request.testPackId,
      targetDid,
      unsigned,
      observerKey,
    ),
  };
}

async function main(): Promise<void> {
  const port = Number(process.env.ORIEL_TARGET_PORT ?? process.env.PORT ?? "8787");
  const host = process.env.ORIEL_TARGET_BIND ?? "127.0.0.1";
  const enableVulnerableFixture = process.env.ORIEL_ENABLE_VULNERABLE_FIXTURE === "true";
  const role = process.env.ORIEL_TARGET_ROLE?.trim() ?? "gateway";
  const observerKey = process.env.ORIEL_OBSERVER_ATTESTATION_KEY?.trim();
  if (role === "gateway") {
    const upstreamUrl = process.env.ORIEL_UPSTREAM_TARGET_URL?.trim();
    const targetDid = process.env.ORIEL_TARGET_DID?.trim();
    if (!upstreamUrl || !targetDid || !observerKey) {
      throw new Error(
        "gateway mode requires ORIEL_UPSTREAM_TARGET_URL, ORIEL_TARGET_DID, and ORIEL_OBSERVER_ATTESTATION_KEY",
      );
    }
    const gateway = await startProbeGateway(port, host, upstreamUrl, targetDid, observerKey);
    console.log(`Oriel probe gateway listening at ${gateway.baseUrl} targetDid=${targetDid}`);
    return;
  }
  const targetPrivateKey = process.env.ORIEL_TARGET_ATTESTATION_KEY?.trim();
  if (!targetPrivateKey) throw new Error("agent mode requires ORIEL_TARGET_ATTESTATION_KEY");
  let target: TargetServerHandle;
  if (role === "agent") {
    target = await startTargetAgentServer(port, host, enableVulnerableFixture, targetPrivateKey);
  } else if (role === "combined") {
    if (!observerKey) throw new Error("combined mode requires ORIEL_OBSERVER_ATTESTATION_KEY");
    target = await startTargetServer(port, host, enableVulnerableFixture, { targetPrivateKey, observerKey });
  } else {
    throw new Error("ORIEL_TARGET_ROLE must be gateway, agent, or combined");
  }
  console.log(`Oriel target fixture listening at ${target.baseUrl}`);
  console.log(
    `role=${role} targetDid=${ethereumDidFromPrivateKey(targetPrivateKey)} vulnerableFixture=${enableVulnerableFixture} vulnerable=${VULNERABLE_VERSION} hardened=${HARDENED_VERSION}`,
  );
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
