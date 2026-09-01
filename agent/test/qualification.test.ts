import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import {
  DEMO_OBSERVER_KEY,
  DEMO_TARGET_PRIVATE_KEY,
  signObserverReceipt,
  signTargetResponse,
} from "../src/attestation.js";
import { HttpTargetClient } from "../src/client.js";
import { runDemo } from "../src/demo.js";
import { checkAccess, evaluateResponse, OrielEngine } from "../src/engine.js";
import { loadDefaultPolicy } from "../src/policy.js";
import { InMemoryOrielStore, qualificationKey } from "../src/store.js";
import type { QualificationRecord, TargetResponse, TargetTransport } from "../src/types.js";
import {
  HARDENED_VERSION,
  TARGET_DID,
  VULNERABLE_VERSION,
} from "../../targets/src/behavior.js";
import { startTargetServer } from "../../targets/src/server.js";

const PRIVATE_CANARY = "oriel_DO_NOT_DISCLOSE_9e30e8";
const OWNER_DID = "did:t3n:test:owner";

test("private canary leakage fails without appearing in public evidence", async () => {
  const policy = await loadDefaultPolicy();
  const transport: TargetTransport = {
    async probe(_targetUrl, request) {
      const response: TargetResponse = {
        observedVersionHash: "v1",
        text: `hidden=${PRIVATE_CANARY}`,
        attemptedActions: [],
        targetSignature: "",
        observerSignature: "",
      };
      return {
        ...response,
        targetSignature: signTargetResponse(
          request.runId,
          request.testPackId,
          TARGET_DID,
          response,
          DEMO_TARGET_PRIVATE_KEY,
        ),
        observerSignature: signObserverReceipt(
          request.runId,
          request.testPackId,
          TARGET_DID,
          response,
          DEMO_OBSERVER_KEY,
        ),
      };
    },
  };
  const store = new InMemoryOrielStore();
  const engine = new OrielEngine({
    ownerDid: OWNER_DID,
    store,
    transport,
    observerKey: DEMO_OBSERVER_KEY,
    now: () => 100,
    createCanary: () => PRIVATE_CANARY,
  });
  const result = await engine.qualify({
    targetAgentDid: TARGET_DID,
    targetVersionHash: "v1",
    targetUrl: "https://target.test/run",
    policy,
  });

  assert.equal(result.qualified, false);
  assert.deepEqual(result.record.findings.map((finding) => finding.code), ["CANARY_LEAK"]);
  assert.equal(JSON.stringify(result).includes(PRIVATE_CANARY), false);
});

test("HTTP lifecycle qualifies only the hardened version and gates protected data", async () => {
  const target = await startTargetServer();
  try {
    let now = 1_000;
    const store = new InMemoryOrielStore();
    store.putProtectedOrder("order-1042", { state: "in_transit" });
    const engine = new OrielEngine({
      ownerDid: OWNER_DID,
      store,
      transport: new HttpTargetClient(),
      observerKey: DEMO_OBSERVER_KEY,
      now: () => now,
      createCanary: () => PRIVATE_CANARY,
    });
    const policy = await loadDefaultPolicy();

    const vulnerable = await engine.qualify({
      targetAgentDid: TARGET_DID,
      targetVersionHash: VULNERABLE_VERSION,
      targetUrl: `${target.baseUrl}/vulnerable/v1/run`,
      policy,
    });
    assert.equal(vulnerable.qualified, false);
    assert.deepEqual(
      vulnerable.record.findings.map((finding) => finding.code),
      ["CANARY_LEAK", "UNAUTHORIZED_FUNCTION", "UNAUTHORIZED_HOST"],
    );

    const hardened = await engine.qualify({
      targetAgentDid: TARGET_DID,
      targetVersionHash: HARDENED_VERSION,
      targetUrl: `${target.baseUrl}/hardened/v2/run`,
      policy,
    });
    assert.equal(hardened.qualified, true);
    assert.equal(hardened.record.findings.length, 0);

    const admitted = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: HARDENED_VERSION,
      capability: "support.lookup",
      orderId: "order-1042",
    });
    assert.equal(admitted.allowed, true);
    assert.deepEqual(admitted.order, { state: "in_transit" });

    const drifted = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: "v3-not-qualified",
      capability: "support.lookup",
      orderId: "order-1042",
    });
    assert.deepEqual(drifted, {
      allowed: false,
      reason: "qualification_not_found",
      qualificationId: null,
      order: null,
    });

    const wrongScope = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: HARDENED_VERSION,
      capability: "support.issue-refund",
      orderId: "order-1042",
    });
    assert.equal(wrongScope.reason, "capability_not_qualified");
    assert.equal(wrongScope.order, null);

    const impersonator = engine.protectedSupportAction("did:t3n:test:impersonator", {
      agentVersionHash: HARDENED_VERSION,
      capability: "support.lookup",
      orderId: "order-1042",
    });
    assert.equal(impersonator.reason, "qualification_not_found");

    now = hardened.record.expiresAt;
    const expired = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: HARDENED_VERSION,
      capability: "support.lookup",
      orderId: "order-1042",
    });
    assert.equal(expired.reason, "qualification_expired");

    now -= 1;
    assert.throws(
      () => engine.revoke("did:t3n:test:impersonator", TARGET_DID, HARDENED_VERSION, "no"),
      /only the tenant owner/,
    );
    engine.revoke(OWNER_DID, TARGET_DID, HARDENED_VERSION, "retired");
    const revoked = engine.protectedSupportAction(TARGET_DID, {
      agentVersionHash: HARDENED_VERSION,
      capability: "support.lookup",
      orderId: "order-1042",
    });
    assert.equal(revoked.reason, "qualification_revoked");
    assert.equal(JSON.stringify({ vulnerable, hardened }).includes(PRIVATE_CANARY), false);
  } finally {
    await target.close();
  }
});

test("qualification fails closed when either attestation is not valid", async () => {
  const target = await startTargetServer();
  try {
    const policy = await loadDefaultPolicy();
    const signed = await new HttpTargetClient().probe(
      `${target.baseUrl}/hardened/v2/run`,
      {
        runId: "attestation-test-run",
        testPackId: policy.packId,
        attackPrompt: policy.attackPrompt,
        privateContext: { customerRecordCanary: PRIVATE_CANARY, syntheticOrderId: "order-1042" },
      },
    );
    const tampered: TargetResponse = {
      ...signed,
      text: `${signed.text} tampered`,
    };
    const engine = new OrielEngine({
      ownerDid: OWNER_DID,
      store: new InMemoryOrielStore(),
      observerKey: DEMO_OBSERVER_KEY,
      transport: { probe: async () => tampered },
      now: () => 100,
    });
    await assert.rejects(
      engine.qualify({
        targetAgentDid: TARGET_DID,
        targetVersionHash: HARDENED_VERSION,
        targetUrl: "https://target.test/run",
        policy,
      }),
      /target signature|observer receipt/,
    );

    const observerFailure = new OrielEngine({
      ownerDid: OWNER_DID,
      store: new InMemoryOrielStore(),
      observerKey: "different-observer-key-1234",
      transport: new HttpTargetClient(),
      now: () => 100,
    });
    await assert.rejects(
      observerFailure.qualify({
        targetAgentDid: TARGET_DID,
        targetVersionHash: HARDENED_VERSION,
        targetUrl: `${target.baseUrl}/hardened/v2/run`,
        policy,
      }),
      /observer receipt/,
    );
  } finally {
    await target.close();
  }
});

test("access checks are identity, version, host, scope, status and time bound", () => {
  const record: QualificationRecord = {
    qualificationId: "q1",
    agentDid: "did:t3n:target",
    agentVersionHash: "v2",
    testPackId: "pack",
    testPackVersion: "1",
    testedFunctions: ["support.lookup"],
    allowedHosts: ["support.test"],
    status: "qualified",
    issuedAt: 10,
    expiresAt: 20,
    evidenceDigest: "evidence",
    findings: [],
    revokedAt: null,
    revocationReason: null,
  };
  assert.deepEqual(
    checkAccess(record, {
      agentDid: record.agentDid,
      agentVersionHash: record.agentVersionHash,
      capability: "support.lookup",
      host: "support.test",
      nowSecs: 11,
    }),
    { allowed: true, reason: "qualified" },
  );
  assert.equal(
    checkAccess(record, {
      agentDid: "did:t3n:other",
      agentVersionHash: "v2",
      capability: "support.lookup",
      nowSecs: 11,
      host: "support.test",
    }).reason,
    "caller_did_mismatch",
  );
  assert.equal(
    checkAccess(record, {
      agentDid: record.agentDid,
      agentVersionHash: "v3",
      capability: "support.lookup",
      host: "support.test",
      nowSecs: 11,
    }).reason,
    "version_not_qualified",
  );
  assert.equal(
    checkAccess(record, {
      agentDid: record.agentDid,
      agentVersionHash: "v2",
      capability: "support.lookup",
      host: "evil.test",
      nowSecs: 11,
    }).reason,
    "host_not_qualified",
  );
  assert.equal(
    checkAccess(record, {
      agentDid: record.agentDid,
      agentVersionHash: record.agentVersionHash,
      capability: "support.lookup",
      host: "",
      nowSecs: 11,
    }).reason,
    "host_not_qualified",
  );
});

test("empty canaries and transparent qualification keys are rejected", async () => {
  const policy = await loadDefaultPolicy();
  assert.throws(
    () => evaluateResponse("v1", "", policy, {
      observedVersionHash: "v1",
      text: "safe",
      attemptedActions: [],
      targetSignature: "",
      observerSignature: "",
    }),
    /must not be empty/,
  );
  const key = qualificationKey("did:t3n:private-agent", "secret-version");
  assert.equal(key.includes("private-agent"), false);
  assert.equal(key.includes("secret-version"), false);
});

test("documented demo evidence matches the executable lifecycle", async () => {
  const expected: unknown = JSON.parse(
    await readFile(new URL("../../docs/demo-output.example.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(await runDemo(), expected);
});
