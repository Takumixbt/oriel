import { getNodeUrl, getScriptVersion } from "@terminal3/t3n-sdk";
import { connect, requiredEnv, safeError, scriptName } from "./t3n.js";

async function main(): Promise<void> {
  const tenantDid = requiredEnv("ORIEL_TENANT_DID");
  const targetUrl = new URL(requiredEnv("ORIEL_TARGET_URL"));
  if (targetUrl.protocol !== "https:") throw new Error("ORIEL_TARGET_URL must use HTTPS for T3N");

  const certifier = await connect(requiredEnv("ORIEL_AGENT_KEY"));
  const target = await connect(requiredEnv("TARGET_AGENT_KEY"));
  const owner = await connect(requiredEnv("T3N_API_KEY"));
  if (owner.did !== tenantDid) throw new Error("T3N_API_KEY does not own ORIEL_TENANT_DID");
  if (new Set([owner.did, certifier.did, target.did]).size !== 3) {
    throw new Error("owner, certifier, and target must use three distinct T3N identities");
  }

  const name = scriptName(tenantDid);
  const version = await getScriptVersion(getNodeUrl(), name);
  await owner.t3n.updateAgentAuth(certifier.did, {
    scriptName: name,
    versionReq: version,
    functions: ["run-qualification"],
    allowedHosts: [targetUrl.hostname],
  });
  await owner.t3n.updateAgentAuth(target.did, {
    scriptName: name,
    versionReq: version,
    functions: ["protected-support-action", "get-qualification"],
    allowedHosts: [],
  });
  await owner.t3n.updateAgentAuth(owner.did, {
    scriptName: name,
    versionReq: version,
    functions: ["revoke-qualification", "get-qualification"],
    allowedHosts: [],
  });

  console.log(JSON.stringify({
    status: "granted",
    tenantOwnerDid: owner.did,
    certifierDid: certifier.did,
    targetAgentDid: target.did,
    contract: `${name}@${version}`,
    certifierEgressHost: targetUrl.hostname,
    next: "Run npm run live:qualify, then npm run live:protected",
  }, null, 2));
}

main().catch((error: unknown) => {
  console.error(`grant failed: ${safeError(error)}`);
  process.exitCode = 1;
});
