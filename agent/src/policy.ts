import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import type { TestPolicy } from "./types.js";

export async function loadDefaultPolicy(): Promise<TestPolicy> {
  const path = fileURLToPath(
    new URL("../../test-packs/support-data-boundary.v1.json", import.meta.url),
  );
  return JSON.parse(await readFile(path, "utf8")) as TestPolicy;
}
