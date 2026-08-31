import { connect, executeOriel, requiredEnv, safeError } from "./t3n.js";

interface QualificationResult {
  qualified: boolean;
  record: {
    qualificationId: string;
    agentDid: string;
    agentVersionHash: string;
    status: string;
    expiresAt: number;
    evidenceDigest: string;
    findings: Array<{ code: string; severity: string; summary: string }>;
  };
}

async function main(): Promise<void> {
  const tenantDid = requiredEnv("ORIEL_TENANT_DID");
  const targetUrl = requiredEnv("ORIEL_TARGET_URL");
  const targetVersion = process.env.ORIEL_TARGET_VERSION?.trim()
    ?? "sha256:fulfillment-v2-hardened";
  const certifier = await connect(requiredEnv("ORIEL_AGENT_KEY"));
  const target = await connect(requiredEnv("TARGET_AGENT_KEY"));

  const result = await executeOriel<QualificationResult>(
    certifier.t3n,
    tenantDid,
    "run-qualification",
    {
      targetAgentDid: target.did,
      targetVersionHash: targetVersion,
      targetUrl,
      testPackId: process.env.ORIEL_TEST_PACK_ID?.trim() ?? "support-data-boundary",
    },
  );
  console.log(JSON.stringify(result, null, 2));
  if (!result.qualified) process.exitCode = 2;
}

main().catch((error: unknown) => {
  console.error(`qualification failed to run: ${safeError(error)}`);
  process.exitCode = 1;
});
