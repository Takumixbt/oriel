import { createHash, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { connect, requiredEnv, safeError, scriptName, validateAgentCard } from "./t3n.js";

const CONTRACT_VERSION = "0.1.2";
const CONTRACT_TAIL = "oriel";
const MAPS = [
  "oriel-secrets",
  "oriel-policies",
  "oriel-qualifications",
  "oriel-protected-data",
] as const;

async function main(): Promise<void> {
  const wasmPath = fileURLToPath(
    new URL("../contract/target/wasm32-wasip2/release/oriel_contract.wasm", import.meta.url),
  );
  const wasm = await readFile(wasmPath);

  const descriptorPath = fileURLToPath(new URL("../agent/agent-card.json", import.meta.url));
  const descriptor: unknown = JSON.parse(await readFile(descriptorPath, "utf8"));
  validateAgentCard(descriptor);

  const owner = await connect(requiredEnv("T3N_API_KEY"));
  await owner.tenant.tenant.me();

  const registered = await owner.tenant.contracts.register({
    tail: CONTRACT_TAIL,
    version: CONTRACT_VERSION,
    wasm,
  });
  const contractId = registered.contract_id;

  await owner.tenant.contracts.setDescriptor({
    tail: CONTRACT_TAIL,
    version: CONTRACT_VERSION,
    descriptor,
  });

  for (const tail of MAPS) {
    const status = await owner.tenant.maps.getStatus(tail);
    const acl = {
      visibility: "Private",
      writers: { only: [contractId] },
      readers: { only: [contractId] },
    };
    if (status === "absent") {
      await owner.tenant.maps.create({ tail, ...acl });
    } else if (status === "active") {
      await owner.tenant.maps.update(tail, acl);
    } else {
      throw new Error(`map ${tail} is still deleting; wait for it to become absent`);
    }
  }

  const policyPath = fileURLToPath(
    new URL("../test-packs/support-data-boundary.v1.json", import.meta.url),
  );
  const policy = await readFile(policyPath, "utf8");
  const privateCanarySeed = `oriel_${randomBytes(32).toString("hex")}`;
  await owner.tenant.maps.entrySet("oriel-policies", "pack:support-data-boundary", policy);
  await owner.tenant.maps.entrySet(
    "oriel-secrets",
    "canary:support-data-boundary",
    privateCanarySeed,
  );
  await owner.tenant.maps.entrySet(
    "oriel-protected-data",
    "order:order-1042",
    JSON.stringify({
      orderId: "order-1042",
      customerTier: "private-enterprise",
      state: "in_transit",
      eta: "2026-09-02",
    }),
  );

  console.log(JSON.stringify({
    status: "registered",
    tenantDid: owner.did,
    scriptName: scriptName(owner.did),
    version: CONTRACT_VERSION,
    contractId,
    wasmSha256: createHash("sha256").update(wasm).digest("hex"),
    maps: MAPS,
    privateCanarySeeded: true,
    next: "Set ORIEL_TENANT_DID to tenantDid, then run npm run live:grant",
  }, null, 2));
}

main().catch((error: unknown) => {
  console.error(`registration failed: ${safeError(error)}`);
  process.exitCode = 1;
});
