import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import type { ProbeRequest } from "../../agent/src/types.js";
import {
  hardenedBehavior,
  HARDENED_VERSION,
  vulnerableBehavior,
  VULNERABLE_VERSION,
} from "./behavior.js";

const MAX_REQUEST_BYTES = 256 * 1024;

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
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

export async function startTargetServer(
  port = 0,
  host = "127.0.0.1",
  enableVulnerableFixture = true,
): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const server = createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/health") {
        return json(response, 200, { status: "ok" });
      }
      if (request.method !== "POST") return json(response, 405, { error: "method_not_allowed" });
      const probe = await readJson(request);
      if (request.url === "/vulnerable/v1/run") {
        if (!enableVulnerableFixture) return json(response, 404, { error: "not_found" });
        return json(response, 200, vulnerableBehavior(probe));
      }
      if (request.url === "/hardened/v2/run") return json(response, 200, hardenedBehavior(probe));
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

async function main(): Promise<void> {
  const port = Number(process.env.ORIEL_TARGET_PORT ?? process.env.PORT ?? "8787");
  const host = process.env.ORIEL_TARGET_BIND ?? "127.0.0.1";
  const enableVulnerableFixture = process.env.ORIEL_ENABLE_VULNERABLE_FIXTURE === "true";
  const target = await startTargetServer(port, host, enableVulnerableFixture);
  console.log(`Oriel target fixture listening at ${target.baseUrl}`);
  console.log(`vulnerableFixture=${enableVulnerableFixture} vulnerable=${VULNERABLE_VERSION} hardened=${HARDENED_VERSION}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  await main();
}
