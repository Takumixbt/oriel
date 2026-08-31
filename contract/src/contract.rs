use crate::model::{
    GetQualificationRequest, ProtectedSupportRequest, RevokeQualificationRequest,
    RunQualificationRequest,
};

#[cfg(target_arch = "wasm32")]
use crate::{
    engine::{
        build_record, can_read_qualification, check_access, derive_run_canary, qualification_key,
        sha256_bytes, sha256_hex,
    },
    model::{
        AccessRequest, GetQualificationResponse, PrivateProbeContext, ProbeRequest,
        ProtectedSupportResponse, QualificationRecord, QualificationResult, QualificationStatus,
        TargetResponse, TestPolicy,
    },
};

const SECRETS_TAIL: &str = "oriel-secrets";
const POLICIES_TAIL: &str = "oriel-policies";
const QUALIFICATIONS_TAIL: &str = "oriel-qualifications";
const PROTECTED_DATA_TAIL: &str = "oriel-protected-data";

pub fn run_qualification(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: RunQualificationRequest =
        serde_json::from_slice(input).map_err(|e| format!("run-qualification: bad input: {e}"))?;

    #[cfg(target_arch = "wasm32")]
    {
        let response = run_qualification_wasm(req)?;
        serde_json::to_vec(&response).map_err(|e| e.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("run_qualification is only implemented on the wasm32 target".to_string())
    }
}

pub fn get_qualification(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: GetQualificationRequest =
        serde_json::from_slice(input).map_err(|e| format!("get-qualification: bad input: {e}"))?;

    #[cfg(target_arch = "wasm32")]
    {
        let response = get_qualification_wasm(req)?;
        serde_json::to_vec(&response).map_err(|e| e.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("get_qualification is only implemented on the wasm32 target".to_string())
    }
}

pub fn protected_support_action(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: ProtectedSupportRequest = serde_json::from_slice(input)
        .map_err(|e| format!("protected-support-action: bad input: {e}"))?;

    #[cfg(target_arch = "wasm32")]
    {
        let response = protected_support_action_wasm(req)?;
        serde_json::to_vec(&response).map_err(|e| e.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("protected_support_action is only implemented on the wasm32 target".to_string())
    }
}

pub fn revoke_qualification(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: RevokeQualificationRequest = serde_json::from_slice(input)
        .map_err(|e| format!("revoke-qualification: bad input: {e}"))?;

    #[cfg(target_arch = "wasm32")]
    {
        let response = revoke_qualification_wasm(req)?;
        serde_json::to_vec(&response).map_err(|e| e.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = req;
        Err("revoke_qualification is only implemented on the wasm32 target".to_string())
    }
}

#[cfg(target_arch = "wasm32")]
use crate::host::{
    interfaces::{http as http_iface, kv_store, logging},
    tenant::tenant_context,
};

#[cfg(target_arch = "wasm32")]
fn map_name(tail: &str) -> String {
    format!("z:{}:{tail}", hex::encode(tenant_context::tenant_did()))
}

#[cfg(target_arch = "wasm32")]
fn caller_did() -> Result<String, String> {
    tenant_context::calling_user_did()
        .map(|did| format!("did:t3n:{}", hex::encode(did)))
        .ok_or_else(|| "authenticated caller required".to_string())
}

#[cfg(target_arch = "wasm32")]
fn read_required(tail: &str, key: &str) -> Result<Vec<u8>, String> {
    kv_store::get(&map_name(tail), key.as_bytes())
        .map_err(|e| format!("private map read failed: {e}"))?
        .ok_or_else(|| format!("required private entry is missing: {key}"))
}

#[cfg(target_arch = "wasm32")]
fn load_record(agent_did: &str, version_hash: &str) -> Result<Option<QualificationRecord>, String> {
    let key = qualification_key(agent_did, version_hash);
    let value = kv_store::get(&map_name(QUALIFICATIONS_TAIL), key.as_bytes())
        .map_err(|e| format!("qualification read failed: {e}"))?;
    value
        .map(|bytes| {
            serde_json::from_slice(&bytes)
                .map_err(|e| format!("stored qualification is malformed: {e}"))
        })
        .transpose()
}

#[cfg(target_arch = "wasm32")]
fn store_record(record: &QualificationRecord) -> Result<(), String> {
    let key = qualification_key(&record.agent_did, &record.agent_version_hash);
    let value = serde_json::to_vec(record)
        .map_err(|e| format!("qualification serialization failed: {e}"))?;
    let digest = sha256_bytes(&[&value]);
    kv_store::set_claims_digest(&digest).map_err(|e| format!("claims digest failed: {e}"))?;
    kv_store::put(&map_name(QUALIFICATIONS_TAIL), key.as_bytes(), &value)
        .map_err(|e| format!("qualification write failed: {e}"))
}

#[cfg(target_arch = "wasm32")]
fn run_qualification_wasm(req: RunQualificationRequest) -> Result<QualificationResult, String> {
    if !req.target_url.starts_with("https://") {
        return Err("target URL must use https".to_string());
    }

    let policy_key = format!("pack:{}", req.test_pack_id);
    let policy_bytes = read_required(POLICIES_TAIL, &policy_key)?;
    let policy: TestPolicy = serde_json::from_slice(&policy_bytes)
        .map_err(|e| format!("stored test policy is malformed: {e}"))?;
    if policy.pack_id != req.test_pack_id {
        return Err("stored policy ID does not match requested pack".to_string());
    }

    let canary_key = format!("canary:{}", req.test_pack_id);
    let now = tenant_context::cluster_timestamp_secs();
    let seq = tenant_context::seq_no();
    let private_seed = read_required(SECRETS_TAIL, &canary_key)?;
    let canary = derive_run_canary(
        &private_seed,
        &req.target_agent_did,
        &req.target_version_hash,
        now,
        seq,
    )?;
    let run_id = sha256_hex(&[
        req.target_agent_did.as_bytes(),
        req.target_version_hash.as_bytes(),
        &now.to_le_bytes(),
        &seq.to_le_bytes(),
    ]);
    let probe = ProbeRequest {
        run_id,
        test_pack_id: req.test_pack_id.clone(),
        attack_prompt: policy.attack_prompt.clone(),
        private_context: PrivateProbeContext {
            customer_record_canary: canary.clone(),
            synthetic_order_id: "order-1042".to_string(),
        },
    };
    let payload =
        serde_json::to_vec(&probe).map_err(|e| format!("probe serialization failed: {e}"))?;

    let target_http = http_iface::call(&http_iface::Request {
        method: http_iface::Verb::Post,
        url: req.target_url,
        headers: Some(vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "User-Agent".to_string(),
                "oriel-contract/0.1 qualification-probe".to_string(),
            ),
        ]),
        payload: Some(payload),
    })
    .map_err(|e| format!("target request failed: {e}"))?;

    if target_http.code != 200 {
        return Err(format!(
            "target returned HTTP {}; response body suppressed",
            target_http.code
        ));
    }
    if target_http.payload.len() > 256 * 1024 {
        return Err("target response exceeded the maximum evidence size".to_string());
    }
    let target_response: TargetResponse = serde_json::from_slice(&target_http.payload)
        .map_err(|_| "target returned a malformed response; body suppressed".to_string())?;

    let record = build_record(
        &req.target_agent_did,
        &req.target_version_hash,
        now,
        &policy,
        &target_response,
        &canary,
    )?;
    store_record(&record)?;

    let safe_status = match record.status {
        QualificationStatus::Qualified => "qualified",
        QualificationStatus::Failed => "failed",
        QualificationStatus::Revoked => "revoked",
    };
    let _ = logging::info(&format!(
        "oriel qualification={} status={} findings={}",
        record.qualification_id,
        safe_status,
        record.findings.len()
    ));

    Ok(QualificationResult {
        qualified: record.status == QualificationStatus::Qualified,
        record,
    })
}

#[cfg(target_arch = "wasm32")]
fn get_qualification_wasm(
    req: GetQualificationRequest,
) -> Result<GetQualificationResponse, String> {
    let caller = caller_did()?;
    let tenant_owner = format!("did:t3n:{}", hex::encode(tenant_context::tenant_did()));
    if !can_read_qualification(&caller, &tenant_owner, &req.agent_did) {
        return Ok(GetQualificationResponse {
            found: false,
            record: None,
        });
    }
    let record = load_record(&req.agent_did, &req.agent_version_hash)?;
    Ok(GetQualificationResponse {
        found: record.is_some(),
        record,
    })
}

#[cfg(target_arch = "wasm32")]
fn protected_support_action_wasm(
    req: ProtectedSupportRequest,
) -> Result<ProtectedSupportResponse, String> {
    let agent_did = caller_did().map_err(|e| format!("protected-support-action: {e}"))?;
    let Some(record) = load_record(&agent_did, &req.agent_version_hash)? else {
        return Ok(ProtectedSupportResponse {
            allowed: false,
            reason: "qualification_not_found".to_string(),
            qualification_id: None,
            order: None,
        });
    };

    let decision = check_access(
        &record,
        &AccessRequest {
            agent_did,
            agent_version_hash: req.agent_version_hash,
            capability: req.capability,
            host: None,
            now_secs: tenant_context::cluster_timestamp_secs(),
        },
    );
    if !decision.allowed {
        return Ok(ProtectedSupportResponse {
            allowed: false,
            reason: decision.reason,
            qualification_id: Some(record.qualification_id),
            order: None,
        });
    }

    let order_key = format!("order:{}", req.order_id);
    let order_bytes = read_required(PROTECTED_DATA_TAIL, &order_key)?;
    let order = serde_json::from_slice(&order_bytes)
        .map_err(|e| format!("stored protected order is malformed: {e}"))?;

    Ok(ProtectedSupportResponse {
        allowed: true,
        reason: decision.reason,
        qualification_id: Some(record.qualification_id),
        order: Some(order),
    })
}

#[cfg(target_arch = "wasm32")]
fn revoke_qualification_wasm(
    req: RevokeQualificationRequest,
) -> Result<QualificationRecord, String> {
    if req.reason.trim().is_empty() || req.reason.len() > 200 {
        return Err("revocation reason must be between 1 and 200 characters".to_string());
    }

    let caller = tenant_context::calling_user_did()
        .ok_or_else(|| "revoke-qualification: authenticated tenant owner required".to_string())?;
    if caller != tenant_context::tenant_did() {
        return Err("revoke-qualification: tenant owner only".to_string());
    }

    let mut record = load_record(&req.agent_did, &req.agent_version_hash)?
        .ok_or_else(|| "qualification not found".to_string())?;
    record.status = QualificationStatus::Revoked;
    record.revoked_at = Some(tenant_context::cluster_timestamp_secs());
    record.revocation_reason = Some(req.reason);
    store_record(&record)?;
    let _ = logging::info(&format!(
        "oriel qualification={} status=revoked",
        record.qualification_id
    ));
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_exports_reject_malformed_json_without_echoing_input() {
        for result in [
            run_qualification(b"private-secret"),
            get_qualification(b"private-secret"),
            protected_support_action(b"private-secret"),
            revoke_qualification(b"private-secret"),
        ] {
            let message = result.expect_err("bad JSON must fail");
            assert!(message.contains("bad input"));
            assert!(!message.contains("private-secret"));
        }
    }
}
