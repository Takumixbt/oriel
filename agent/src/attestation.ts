import { createHmac, timingSafeEqual } from "node:crypto";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { lengthPrefixedSha256Bytes } from "./hash.js";
import type { TargetResponse } from "./types.js";

export const DEMO_TARGET_PRIVATE_KEY = `0x${"11".repeat(32)}`;
export const DEMO_OBSERVER_KEY = "oriel-demo-observer-key-v1";

const TARGET_ATTESTATION_DOMAIN = "oriel-target-attestation-v1";
const OBSERVER_RECEIPT_DOMAIN = "oriel-observer-receipt-v1";

function decodeHex(value: string, label: string): Uint8Array {
  const raw = value.replace(/^0x/i, "");
  if (!/^[0-9a-f]+$/i.test(raw) || raw.length % 2 !== 0) {
    throw new Error(`${label} must be hexadecimal`);
  }
  return Uint8Array.from(Buffer.from(raw, "hex"));
}

export function privateKeyBytes(value: string): Uint8Array {
  const key = decodeHex(value, "private key");
  if (key.byteLength !== 32 || !secp256k1.utils.isValidSecretKey(key)) {
    throw new Error("private key must be a valid 32-byte secp256k1 key");
  }
  return key;
}

export function ethereumDidFromPublicKey(publicKey: Uint8Array): string {
  const uncompressed = publicKey.byteLength === 65
    ? publicKey
    : publicKey.byteLength === 33
      ? secp256k1.Point.fromBytes(publicKey).toBytes(false)
      : undefined;
  if (uncompressed === undefined || uncompressed[0] !== 4) {
    throw new Error("Ethereum identity recovery requires a valid secp256k1 public key");
  }
  const addressHash = keccak_256(uncompressed.subarray(1));
  return `did:t3n:${Buffer.from(addressHash.subarray(-20)).toString("hex")}`;
}

export function ethereumDidFromPrivateKey(privateKey: string): string {
  return ethereumDidFromPublicKey(secp256k1.getPublicKey(privateKeyBytes(privateKey), false));
}

function normalizedActions(response: TargetResponse): Array<{ function: string; host: string | null }> {
  return response.attemptedActions.map((action) => ({
    function: action.function,
    host: action.host ?? null,
  }));
}

export function responseEvidenceJson(response: TargetResponse): string {
  return JSON.stringify({
    observedVersionHash: response.observedVersionHash,
    text: response.text,
    attemptedActions: normalizedActions(response),
  });
}

export function responseEvidenceWithAttestationsJson(response: TargetResponse): string {
  return JSON.stringify({
    observedVersionHash: response.observedVersionHash,
    text: response.text,
    attemptedActions: normalizedActions(response),
    targetSignature: response.targetSignature,
    observerSignature: response.observerSignature,
  });
}

function attestationDigest(
  domain: string,
  runId: string,
  testPackId: string,
  targetAgentDid: string,
  response: TargetResponse,
): Uint8Array {
  return lengthPrefixedSha256Bytes([
    domain,
    runId,
    testPackId,
    targetAgentDid,
    response.observedVersionHash,
    responseEvidenceJson(response),
  ]);
}

export function targetAttestationDigest(
  runId: string,
  testPackId: string,
  targetAgentDid: string,
  response: TargetResponse,
): Uint8Array {
  return attestationDigest(TARGET_ATTESTATION_DOMAIN, runId, testPackId, targetAgentDid, response);
}

export function observerReceiptDigest(
  runId: string,
  testPackId: string,
  targetAgentDid: string,
  response: TargetResponse,
): Uint8Array {
  return attestationDigest(OBSERVER_RECEIPT_DOMAIN, runId, testPackId, targetAgentDid, response);
}

export function signTargetResponse(
  runId: string,
  testPackId: string,
  targetAgentDid: string,
  response: TargetResponse,
  privateKey: string,
): string {
  const signerDid = ethereumDidFromPrivateKey(privateKey);
  if (signerDid !== targetAgentDid) throw new Error("target signing key does not match configured target DID");
  const signature = secp256k1.sign(
    targetAttestationDigest(runId, testPackId, targetAgentDid, response),
    privateKeyBytes(privateKey),
    { prehash: false, lowS: true, format: "recovered" },
  );
  return `0x${Buffer.from(signature).toString("hex")}`;
}

export function signObserverReceipt(
  runId: string,
  testPackId: string,
  targetAgentDid: string,
  response: TargetResponse,
  observerKey: string,
): string {
  return `0x${createHmac("sha256", observerKey)
    .update(observerReceiptDigest(runId, testPackId, targetAgentDid, response))
    .digest("hex")}`;
}

export function verifyResponseAttestations(
  runId: string,
  testPackId: string,
  targetAgentDid: string,
  response: TargetResponse,
  observerKey: string,
): void {
  const digest = targetAttestationDigest(runId, testPackId, targetAgentDid, response);
  const targetSignature = decodeHex(response.targetSignature, "target signature");
  if (targetSignature.byteLength !== 65) throw new Error("target signature has the wrong length");
  const recovered = secp256k1.recoverPublicKey(targetSignature, digest, { prehash: false });
  if (!secp256k1.verify(targetSignature.subarray(1), digest, recovered, { prehash: false })) {
    throw new Error("target signature failed verification");
  }
  if (ethereumDidFromPublicKey(recovered) !== targetAgentDid) {
    throw new Error("target signature identity does not match the requested DID");
  }

  const expected = createHmac("sha256", observerKey)
    .update(observerReceiptDigest(runId, testPackId, targetAgentDid, response))
    .digest();
  const supplied = decodeHex(response.observerSignature, "observer signature");
  if (supplied.byteLength !== expected.byteLength || !timingSafeEqual(supplied, expected)) {
    throw new Error("observer receipt failed verification");
  }
}
