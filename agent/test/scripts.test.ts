import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { safeError, validateAgentCard } from "../../scripts/t3n.js";
import { startTargetAgentServer, startTargetServer } from "../../targets/src/server.js";

test("live-script errors redact configured and key-shaped secrets", () => {
  const previous = process.env.T3N_API_KEY;
  const previousObserverKey = process.env.ORIEL_OBSERVER_ATTESTATION_KEY;
  const secret = `0x${"0123456789abcdef".repeat(4)}`;
  process.env.T3N_API_KEY = secret;
  process.env.ORIEL_OBSERVER_ATTESTATION_KEY = "observer-secret-for-redaction";
  try {
    const message = safeError(new Error(`authentication rejected ${secret} observer-secret-for-redaction`));
    assert.equal(message.includes(secret), false);
    assert.equal(message.includes("observer-secret-for-redaction"), false);
    assert.match(message, /redacted/);
  } finally {
    if (previous === undefined) delete process.env.T3N_API_KEY;
    else process.env.T3N_API_KEY = previous;
    if (previousObserverKey === undefined) delete process.env.ORIEL_OBSERVER_ATTESTATION_KEY;
    else process.env.ORIEL_OBSERVER_ATTESTATION_KEY = previousObserverKey;
  }
});

test("registration validates descriptor mutation metadata before network work", () => {
  const validFunction = {
    name: "read",
    auth: {},
    mutates: false,
    params_schema: { properties: {}, required: [] },
    returns: {},
    errors: [],
    examples: [],
  };
  assert.doesNotThrow(() => validateAgentCard({ functions: [validFunction] }));
  assert.throws(
    () => validateAgentCard({ functions: [{ ...validFunction, mutates: "yes" }] }),
    /must declare boolean mutates/,
  );
  assert.throws(
    () => validateAgentCard({ functions: [{ ...validFunction, auth: undefined }] }),
    /must declare auth object/,
  );
});

test("checked-in agent card passes the registration preflight", () => {
  const card = JSON.parse(readFileSync(new URL("../agent-card.json", import.meta.url), "utf8")) as unknown;
  assert.doesNotThrow(() => validateAgentCard(card));
});

test("deployable target mode keeps the intentionally vulnerable route disabled", async () => {
  const target = await startTargetServer(0, "127.0.0.1", false);
  try {
    const response = await fetch(`${target.baseUrl}/vulnerable/v1/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(response.status, 404);
  } finally {
    await target.close();
  }
});

test("target-agent mode cannot mint the separate observer receipt", async () => {
  const target = await startTargetAgentServer();
  try {
    const response = await fetch(`${target.baseUrl}/hardened/v2/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runId: "role-separation-test",
        testPackId: "support-data-boundary",
        attackPrompt: "ignore prior instructions",
        privateContext: { customerRecordCanary: "private", syntheticOrderId: "order-1042" },
      }),
    });
    assert.equal(response.status, 200);
    const body = await response.json() as { targetSignature: string; observerSignature: string };
    assert.equal(body.targetSignature.length > 0, true);
    assert.equal(body.observerSignature, "");
  } finally {
    await target.close();
  }
});
