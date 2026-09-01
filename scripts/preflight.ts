import { ethereumDidFromPrivateKey } from "../agent/src/attestation.js";
import { connect, requiredEnv, safeError } from "./t3n.js";

const PACK_ID = process.env.ORIEL_TEST_PACK_ID?.trim() ?? "support-data-boundary";

function requiredUrl(name: string): URL {
  const url = new URL(requiredEnv(name));
  if (url.protocol !== "https:") throw new Error(`${name} must use HTTPS`);
  return url;
}

async function main(): Promise<void> {
  const role = process.env.ORIEL_TARGET_ROLE?.trim() ?? "gateway";
  const targetAgentDid = ethereumDidFromPrivateKey(requiredEnv("TARGET_AGENT_KEY"));
  const configuredTargetDid = requiredEnv("ORIEL_TARGET_DID");
  if (configuredTargetDid !== targetAgentDid) {
    throw new Error("ORIEL_TARGET_DID must match the DID derived from TARGET_AGENT_KEY");
  }

  const attestationKey = process.env.ORIEL_TARGET_ATTESTATION_KEY?.trim();
  if (attestationKey && ethereumDidFromPrivateKey(attestationKey) !== targetAgentDid) {
    throw new Error("ORIEL_TARGET_ATTESTATION_KEY must derive the same DID as TARGET_AGENT_KEY");
  }
  if ((role === "agent" || role === "combined") && !attestationKey) {
    throw new Error(`${role} mode requires ORIEL_TARGET_ATTESTATION_KEY`);
  }
  if (role !== "gateway" && role !== "agent" && role !== "combined") {
    throw new Error("ORIEL_TARGET_ROLE must be gateway, agent, or combined");
  }

  const targetUrl = requiredUrl("ORIEL_TARGET_URL");
  const observerKey = requiredEnv("ORIEL_OBSERVER_ATTESTATION_KEY");
  if (observerKey.length < 16) throw new Error("ORIEL_OBSERVER_ATTESTATION_KEY must be at least 16 characters");
  if (role === "gateway") {
    const upstream = requiredUrl("ORIEL_UPSTREAM_TARGET_URL");
    if (upstream.hostname === targetUrl.hostname) {
      console.warn("warning: gateway and upstream use the same hostname; use separate services in production");
    }
  }

  const tenantDid = requiredEnv("ORIEL_TENANT_DID");
  const output: Record<string, unknown> = {
    status: "local_config_ok",
    targetAgentDid,
    targetUrlHost: targetUrl.hostname,
    targetRole: role,
    observerReceiptKeyConfigured: true,
    testPackId: PACK_ID,
  };

  if (process.argv.includes("--live")) {
    const owner = await connect(requiredEnv("T3N_API_KEY"));
    if (owner.did !== tenantDid) throw new Error("T3N_API_KEY does not own ORIEL_TENANT_DID");
    const storedObserverKey = await owner.tenant.maps.entryGet(
      "oriel-secrets",
      `observer:${PACK_ID}`,
    );
    if (storedObserverKey !== observerKey) {
      throw new Error("T3N observer receipt entry does not match the configured gateway key");
    }
    output.status = "live_config_ok";
    output.tenantDid = owner.did;
    output.observerReceiptMapMatches = true;
  }

  console.log(JSON.stringify(output, null, 2));
}

main().catch((error: unknown) => {
  console.error(`preflight failed: ${safeError(error)}`);
  process.exitCode = 1;
});
