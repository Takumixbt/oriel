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
    fetchTrustedManifest(env),
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
  for (const name of ["T3N_API_KEY", "ORIEL_AGENT_KEY", "TARGET_AGENT_KEY"] as const) {
    const secret = process.env[name];
    if (secret) message = message.replaceAll(secret, "[redacted]");
  }
  return message.replace(/(?:0x)?[0-9a-fA-F]{64}/g, "[redacted-key]");
}
