import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { CONTRACT_VERSION } from "../contract-version.js";

const artifactPath = fileURLToPath(
  new URL("../contract/target/wasm32-wasip2/release/oriel_contract.wasm", import.meta.url),
);
const wasm = await readFile(artifactPath);
const sha256 = createHash("sha256").update(wasm).digest("hex");
const expected = process.env.ORIEL_EXPECTED_WASM_SHA256?.trim().toLowerCase();
if (expected && expected !== sha256) {
  throw new Error(`WASM hash mismatch: expected ${expected}, got ${sha256}`);
}
console.log(JSON.stringify({ contractVersion: CONTRACT_VERSION, bytes: wasm.byteLength, sha256 }, null, 2));
