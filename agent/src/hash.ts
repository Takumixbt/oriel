import { createHash } from "node:crypto";

export function lengthPrefixedSha256(parts: Array<string | Uint8Array>): string {
  return Buffer.from(lengthPrefixedSha256Bytes(parts)).toString("hex");
}

export function lengthPrefixedSha256Bytes(parts: Array<string | Uint8Array>): Uint8Array {
  const hash = createHash("sha256");
  for (const part of parts) {
    const bytes = typeof part === "string" ? Buffer.from(part) : Buffer.from(part);
    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(bytes.byteLength));
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest();
}

export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(",")}}`;
}

export function u64Le(value: number): Uint8Array {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64LE(BigInt(value));
  return bytes;
}
