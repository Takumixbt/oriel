import type { QualificationRecord } from "./types.js";
import { lengthPrefixedSha256 } from "./hash.js";

export function qualificationKey(agentDid: string, versionHash: string): string {
  return `qualification:${lengthPrefixedSha256([agentDid, versionHash])}`;
}

export interface OrielStore {
  getQualification(agentDid: string, versionHash: string): QualificationRecord | undefined;
  putQualification(record: QualificationRecord): void;
  getProtectedOrder(orderId: string): unknown | undefined;
  putProtectedOrder(orderId: string, value: unknown): void;
}

export class InMemoryOrielStore implements OrielStore {
  readonly #qualifications = new Map<string, QualificationRecord>();
  readonly #orders = new Map<string, unknown>();

  getQualification(agentDid: string, versionHash: string): QualificationRecord | undefined {
    return this.#qualifications.get(qualificationKey(agentDid, versionHash));
  }

  putQualification(record: QualificationRecord): void {
    this.#qualifications.set(
      qualificationKey(record.agentDid, record.agentVersionHash),
      structuredClone(record),
    );
  }

  getProtectedOrder(orderId: string): unknown | undefined {
    return this.#orders.get(orderId);
  }

  putProtectedOrder(orderId: string, value: unknown): void {
    this.#orders.set(orderId, structuredClone(value));
  }
}
