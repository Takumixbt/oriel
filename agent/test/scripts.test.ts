import assert from "node:assert/strict";
import { test } from "node:test";
import { safeError } from "../../scripts/t3n.js";

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
