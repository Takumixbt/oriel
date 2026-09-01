import {
  T3nClient,
  TenantClient,
  createEthAuthInput,
  eth_get_address,
  fetchTrustedManifest,
  getNodeUrl,
  getScriptVersion,
  loadWasmComponent,
  metamask_sign,
  setEnvironment,
} from "@terminal3/t3n-sdk";
import { existsSync } from "node:fs";

if (existsSync(".env")) process.loadEnvFile(".env");

export type OrielEnvironment = "sandbox" | "testnet" | "production";

export interface T3nConnection {
  did: string;
  t3n: T3nClient;
  tenant: TenantClient;
}

export function requiredEnv(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required; copy .env.example to .env and set it there`);
  return value;
}

export function validateAgentCard(card: unknown): void {
  if (!card || typeof card !== "object") throw new Error("agent card must be a JSON object");
  const functions = (card as { functions?: unknown }).functions;
  if (!Array.isArray(functions) || functions.length === 0) {
    throw new Error("agent card must declare at least one function");
  }
  const names = new Set<string>();
  for (const entry of functions) {
    if (!entry || typeof entry !== "object") throw new Error("agent card function must be an object");
    const functionEntry = entry as {
      name?: unknown;
      auth?: unknown;
      mutates?: unknown;
      params_schema?: unknown;
      returns?: unknown;
      errors?: unknown;
      examples?: unknown;
    };
    if (typeof functionEntry.name !== "string" || functionEntry.name.length === 0) {
      throw new Error("agent card function name is required");
    }
    if (names.has(functionEntry.name)) throw new Error(`agent card function ${functionEntry.name} is duplicated`);
    names.add(functionEntry.name);
    if (!functionEntry.auth || typeof functionEntry.auth !== "object" || Array.isArray(functionEntry.auth)) {
      throw new Error(`agent card function ${functionEntry.name} must declare auth object`);
    }
    if (typeof functionEntry.mutates !== "boolean") {
      throw new Error(`agent card function ${functionEntry.name} must declare boolean mutates`);
    }
    if (!functionEntry.params_schema || typeof functionEntry.params_schema !== "object" || Array.isArray(functionEntry.params_schema)) {
      throw new Error(`agent card function ${functionEntry.name} must declare params_schema object`);
    }
    const paramsSchema = functionEntry.params_schema as { properties?: unknown; required?: unknown };
    if (!paramsSchema.properties || typeof paramsSchema.properties !== "object" || Array.isArray(paramsSchema.properties)) {
      throw new Error(`agent card function ${functionEntry.name} params_schema must declare properties`);
    }
    if (!Array.isArray(paramsSchema.required)) {
      throw new Error(`agent card function ${functionEntry.name} params_schema must declare required fields`);
    }
    if (!functionEntry.returns || typeof functionEntry.returns !== "object" || Array.isArray(functionEntry.returns)) {
      throw new Error(`agent card function ${functionEntry.name} must declare returns object`);
    }
    if (!Array.isArray(functionEntry.errors)) {
      throw new Error(`agent card function ${functionEntry.name} must declare errors array`);
    }
    if (!Array.isArray(functionEntry.examples)) {
      throw new Error(`agent card function ${functionEntry.name} must declare examples array`);
    }
  }
}

export function environment(): OrielEnvironment {
  const value = process.env.T3N_ENV?.trim() ?? "testnet";
  if (value !== "sandbox" && value !== "testnet" && value !== "production") {
    throw new Error("T3N_ENV must be sandbox, testnet, or production");
  }
  return value;
}

export async function connect(privateKey: string): Promise<T3nConnection> {
  const env = environment();
  setEnvironment(env);
  const address = eth_get_address(privateKey);
  const [wasmComponent, trustAnchor] = await Promise.all([
    loadWasmComponent(),
    fetchTrustedManifestWithRetry(env),
  ]);
  const t3n = new T3nClient({
    wasmComponent,
    trustAnchor,
    handlers: { EthSign: metamask_sign(address, undefined, privateKey) },
  });
  await t3n.handshake();
  const did = (await t3n.authenticate(createEthAuthInput(address))).value;
  const tenant = new TenantClient({ t3n, baseUrl: getNodeUrl(), tenantDid: did });
  return { did, t3n, tenant };
}

async function fetchTrustedManifestWithRetry(env: OrielEnvironment): Promise<Awaited<ReturnType<typeof fetchTrustedManifest>>> {
  let lastError: unknown;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      return await fetchTrustedManifest(env);
    } catch (error) {
      lastError = error;
      if (attempt < 2) {
        await new Promise<void>((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
      }
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

export function scriptName(tenantDid: string): string {
  const prefix = "did:t3n:";
  if (!tenantDid.startsWith(prefix)) throw new Error("ORIEL_TENANT_DID is not a T3N DID");
  return `z:${tenantDid.slice(prefix.length)}:oriel`;
}

export async function executeOriel<T>(
  t3n: T3nClient,
  tenantDid: string,
  functionName: string,
  input: Record<string, unknown>,
): Promise<T> {
  const name = scriptName(tenantDid);
  const version = await getScriptVersion(getNodeUrl(), name);
  return t3n.executeAndDecode<T>({
    script_name: name,
    script_version: version,
    function_name: functionName,
    input,
  });
}

export function safeError(error: unknown): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const name of [
    "T3N_API_KEY",
    "ORIEL_AGENT_KEY",
    "TARGET_AGENT_KEY",
    "ORIEL_TARGET_ATTESTATION_KEY",
    "ORIEL_OBSERVER_ATTESTATION_KEY",
  ] as const) {
    const secret = process.env[name];
    if (secret) message = message.replaceAll(secret, "[redacted]");
  }
  return message.replace(/(?:0x)?[0-9a-fA-F]{64}/g, "[redacted-key]");
}
