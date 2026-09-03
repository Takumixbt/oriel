export type QualificationStatus = "qualified" | "failed" | "revoked";
export type Severity = "critical" | "high";

export type FindingCode =
  | "CANARY_LEAK"
  | "VERSION_MISMATCH"
  | "UNAUTHORIZED_FUNCTION"
  | "UNAUTHORIZED_HOST";

export interface TestPolicy {
  packId: string;
  packVersion: string;
  attackPrompt: string;
  allowedFunctions: string[];
  allowedHosts: string[];
  expiresInSecs: number;
}

export interface AttemptedAction {
  function: string;
  host?: string;
}

export interface TargetResponse {
  observedVersionHash: string;
  text: string;
  attemptedActions: AttemptedAction[];
  targetSignature: string;
  observerSignature: string;
}

export interface ProbeRequest {
  runId: string;
  testPackId: string;
  attackPrompt: string;
  privateContext: {
    customerRecordCanary: string;
    syntheticOrderId: string;
  };
}

export interface Finding {
  code: FindingCode;
  severity: Severity;
  summary: string;
}

export interface QualificationRecord {
  qualificationId: string;
  agentDid: string;
  agentVersionHash: string;
  testPackId: string;
  testPackVersion: string;
  testedFunctions: string[];
  allowedHosts: string[];
  status: QualificationStatus;
  issuedAt: number;
  expiresAt: number;
  evidenceDigest: string;
  findings: Finding[];
  revokedAt: number | null;
  revocationReason: string | null;
}

export interface QualificationRequest {
  targetAgentDid: string;
  targetVersionHash: string;
  targetUrl: string;
  policy: TestPolicy;
}

export interface QualificationResult {
  qualified: boolean;
  record: QualificationRecord;
}

export interface ProtectedSupportRequest {
  agentVersionHash: string;
  capability: string;
  orderId: string;
}

export interface ProtectedSupportResponse {
  allowed: boolean;
  reason: string;
  qualificationId: string | null;
  order: unknown | null;
}

export interface AccessRequest {
  agentDid: string;
  agentVersionHash: string;
  capability: string;
  host: string;
  nowSecs: number;
}

export interface AccessDecision {
  allowed: boolean;
  reason: string;
}

export interface TargetTransport {
  probe(targetUrl: string, request: ProbeRequest): Promise<TargetResponse>;
}
