import assert from "node:assert/strict";
import { test } from "node:test";
import { safeError, validateAgentCard } from "../../scripts/t3n.js";
import { startTargetServer } from "../../targets/src/server.js";

test("live-script errors redact configured and key-shaped secrets", () => {
  const previous = process.env.T3N_API_KEY;
  const secret = `0x${"0123456789abcdef".repeat(4)}`;
  process.env.T3N_API_KEY = secret;
  try {
    const message = safeError(new Error(`authentication rejected ${secret}`));
    assert.equal(message.includes(secret), false);
    assert.match(message, /redacted/);
  } finally {
    if (previous === undefined) delete process.env.T3N_API_KEY;
    else process.env.T3N_API_KEY = previous;
  }
});

test("registration validates descriptor mutation metadata before network work", () => {
  const validFunction = {
    name: "read",
    auth: {},
    mutates: false,
    params_schema: {},
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
