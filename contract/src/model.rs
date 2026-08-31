use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TestPolicy {
    pub pack_id: String,
    pub pack_version: String,
    pub attack_prompt: String,
    pub allowed_functions: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub expires_in_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttemptedAction {
    pub function: String,
    pub host: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TargetResponse {
    pub observed_version_hash: String,
    pub text: String,
    #[serde(default)]
    pub attempted_actions: Vec<AttemptedAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCode {
    CanaryLeak,
    VersionMismatch,
    UnauthorizedFunction,
    UnauthorizedHost,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub code: FindingCode,
    pub severity: Severity,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualificationStatus {
    Qualified,
    Failed,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QualificationRecord {
    pub qualification_id: String,
    pub agent_did: String,
    pub agent_version_hash: String,
    pub test_pack_id: String,
    pub test_pack_version: String,
    pub tested_functions: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub status: QualificationStatus,
    pub issued_at: u64,
    pub expires_at: u64,
    pub evidence_digest: String,
    pub findings: Vec<Finding>,
    pub revoked_at: Option<u64>,
    pub revocation_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunQualificationRequest {
    pub target_agent_did: String,
    pub target_version_hash: String,
    pub target_url: String,
    pub test_pack_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProbeRequest {
    pub run_id: String,
    pub test_pack_id: String,
    pub attack_prompt: String,
    pub private_context: PrivateProbeContext,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PrivateProbeContext {
    pub customer_record_canary: String,
    pub synthetic_order_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct QualificationResult {
    pub qualified: bool,
    pub record: QualificationRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GetQualificationRequest {
    pub agent_did: String,
    pub agent_version_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GetQualificationResponse {
    pub found: bool,
    pub record: Option<QualificationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedSupportRequest {
    pub agent_version_hash: String,
    pub capability: String,
    pub order_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProtectedSupportResponse {
    pub allowed: bool,
    pub reason: String,
    pub qualification_id: Option<String>,
    pub order: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RevokeQualificationRequest {
    pub agent_did: String,
    pub agent_version_hash: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessRequest {
    pub agent_did: String,
    pub agent_version_hash: String,
    pub capability: String,
    pub host: Option<String>,
    pub now_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessDecision {
    pub allowed: bool,
    pub reason: String,
}
