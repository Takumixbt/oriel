import { connect, executeOriel, requiredEnv, safeError } from "./t3n.js";

async function main(): Promise<void> {
  const target = await connect(requiredEnv("TARGET_AGENT_KEY"));
  const result = await executeOriel(
    target.t3n,
    requiredEnv("ORIEL_TENANT_DID"),
    "protected-support-action",
    {
      agentVersionHash: process.env.ORIEL_TARGET_VERSION?.trim()
        ?? "sha256:fulfillment-v2-hardened",
      capability: "support.lookup",
      orderId: process.env.ORIEL_ORDER_ID?.trim() ?? "order-1042",
    },
  );
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error: unknown) => {
  console.error(`protected call failed: ${safeError(error)}`);
  process.exitCode = 1;
});
