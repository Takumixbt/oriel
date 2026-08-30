import { connect, executeOriel, requiredEnv, safeError } from "./t3n.js";

async function main(): Promise<void> {
  const tenantDid = requiredEnv("ORIEL_TENANT_DID");
  const owner = await connect(requiredEnv("T3N_API_KEY"));
  if (owner.did !== tenantDid) throw new Error("T3N_API_KEY does not own ORIEL_TENANT_DID");
  const target = await connect(requiredEnv("TARGET_AGENT_KEY"));
  const result = await executeOriel(
    owner.t3n,
    tenantDid,
    "revoke-qualification",
    {
      agentDid: target.did,
      agentVersionHash: process.env.ORIEL_TARGET_VERSION?.trim()
        ?? "sha256:fulfillment-v2-hardened",
      reason: process.env.ORIEL_REVOCATION_REASON?.trim() ?? "operator revocation",
    },
  );
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  console.error(`revocation failed: ${safeError(error)}`);
  process.exitCode = 1;
});
