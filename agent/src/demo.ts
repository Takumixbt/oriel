import { HttpTargetClient } from "./client.js";
import { OrielEngine } from "./engine.js";
import { lengthPrefixedSha256 } from "./hash.js";
import { loadDefaultPolicy } from "./policy.js";
import { InMemoryOrielStore } from "./store.js";
import { HARDENED_VERSION, TARGET_DID, VULNERABLE_VERSION } from "../../targets/src/behavior.js";
import { startTargetServer } from "../../targets/src/server.js";

const OWNER_DID = "did:t3n:demo:merchant";

export async function runDemo(): Promise<unknown> {
  const fixture = await startTargetServer();
  try {
    let now = 1_788_000_000;
    let canarySequence = 0;
    const store = new InMemoryOrielStore();
    store.putProtectedOrder("order-1042", {
      orderId: "order-1042",
      customerTier: "private-enterprise",
      state: "in_transit",
      eta: "2026-09-02",
    });
    const engine = new OrielEngine({
      ownerDid: OWNER_DID,
      store,
      transport: new HttpTargetClient(),
      now: () => now,
      createCanary: () => `oriel_${lengthPrefixedSha256([
        "demo-private-seed",
        String(++canarySequence),
      ])}`,
    });
    const policy = await loadDefaultPolicy();

    const vulnerable = await engine.qualify({
      targetAgentDid: TARGET_DID,
      targetVersionHash: VULNERABLE_VERSION,
      targetUrl: `${fixture.baseUrl}/vulnerable/v1/run`,
      policy,
    });
    const hardened = await engine.qualify({
      targetAgentDid: TARGET_DID,
      targetVersionHash: HARDENED_VERSION,
      targetUrl: `${fixture.baseUrl}/hardened/v2/run`,
      policy,
    });
    const admitted = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: HARDENED_VERSION,
      capability: "support.lookup",
      orderId: "order-1042",
    });
    const versionDrift = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: "sha256:fulfillment-v3-unqualified",
      capability: "support.lookup",
      orderId: "order-1042",
    });
    now += 30;
    const revokedRecord = engine.revoke(
      OWNER_DID,
      TARGET_DID,
      HARDENED_VERSION,
      "target deployment retired",
    );
    const afterRevocation = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: HARDENED_VERSION,
      capability: "support.lookup",
      orderId: "order-1042",
    });

    return {
      product: "Oriel",
      thesis: "Agents earn scoped, short-lived access by surviving private tests.",
      identities: {
        tenantOwner: OWNER_DID,
        certifier: "did:t3n:demo:oriel-certifier",
        targetAgent: TARGET_DID,
      },
      lifecycle: [
        {
          step: "private_adversarial_test",
          targetVersion: VULNERABLE_VERSION,
          status: vulnerable.record.status,
          findings: vulnerable.record.findings.map(({ code, severity }) => ({ code, severity })),
          evidenceDigest: vulnerable.record.evidenceDigest,
        },
        {
          step: "harden_and_retest",
          targetVersion: HARDENED_VERSION,
          status: hardened.record.status,
          qualificationId: hardened.record.qualificationId,
          expiresAt: hardened.record.expiresAt,
        },
        { step: "qualified_access", decision: admitted },
        { step: "unqualified_version_drift", decision: versionDrift },
        {
          step: "owner_revocation",
          status: revokedRecord.status,
          revokedAt: revokedRecord.revokedAt,
        },
        { step: "revoked_access", decision: afterRevocation },
      ],
    };
  } finally {
    await fixture.close();
  }
}
