use alloc::{format, string::String, vec::Vec};

use hmac::{Hmac, Mac};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::model::{AttemptedAction, TargetResponse};

type HmacSha256 = Hmac<Sha256>;

const TARGET_ATTESTATION_DOMAIN: &[u8] = b"oriel-target-attestation-v1";
const OBSERVER_RECEIPT_DOMAIN: &[u8] = b"oriel-observer-receipt-v1";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseEvidence<'a> {
    observed_version_hash: &'a str,
    text: &'a str,
    attempted_actions: &'a [AttemptedAction],
}

fn length_prefixed_sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((*part).len().to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn target_attestation_digest(
    run_id: &str,
    test_pack_id: &str,
    target_agent_did: &str,
    response: &TargetResponse,
) -> Result<[u8; 32], String> {
    attestation_digest(
        TARGET_ATTESTATION_DOMAIN,
        run_id,
        test_pack_id,
        target_agent_did,
        response,
    )
}

pub fn observer_receipt_digest(
    run_id: &str,
    test_pack_id: &str,
    target_agent_did: &str,
    response: &TargetResponse,
) -> Result<[u8; 32], String> {
    attestation_digest(
        OBSERVER_RECEIPT_DOMAIN,
        run_id,
        test_pack_id,
        target_agent_did,
        response,
    )
}

fn attestation_digest(
    domain: &[u8],
    run_id: &str,
    test_pack_id: &str,
    target_agent_did: &str,
    response: &TargetResponse,
) -> Result<[u8; 32], String> {
    let evidence = serde_json::to_vec(&ResponseEvidence {
        observed_version_hash: &response.observed_version_hash,
        text: &response.text,
        attempted_actions: &response.attempted_actions,
    })
    .map_err(|e| format!("could not serialize attestation evidence: {e}"))?;

    Ok(length_prefixed_sha256(&[
        domain,
        run_id.as_bytes(),
        test_pack_id.as_bytes(),
        target_agent_did.as_bytes(),
        response.observed_version_hash.as_bytes(),
        &evidence,
    ]))
}

pub fn response_evidence_bytes(response: &TargetResponse) -> Result<Vec<u8>, String> {
    serde_json::to_vec(response).map_err(|e| format!("could not serialize response evidence: {e}"))
}

pub fn verify_response_attestations(
    run_id: &str,
    test_pack_id: &str,
    target_agent_did: &str,
    response: &TargetResponse,
    observer_key: &[u8],
) -> Result<(), String> {
    let target_digest =
        target_attestation_digest(run_id, test_pack_id, target_agent_did, response)?;
    verify_target_signature(&target_digest, target_agent_did, &response.target_signature)?;

    let observer_digest =
        observer_receipt_digest(run_id, test_pack_id, target_agent_did, response)?;
    verify_observer_signature(&observer_digest, observer_key, &response.observer_signature)
}

fn verify_target_signature(
    digest: &[u8; 32],
    expected_did: &str,
    encoded_signature: &str,
) -> Result<(), String> {
    let signature_bytes = decode_hex(encoded_signature, 65, "target signature")?;
    let recovery_id = RecoveryId::try_from(signature_bytes[0])
        .map_err(|_| "target signature has an invalid recovery id".to_string())?;
    let signature = Signature::from_slice(&signature_bytes[1..])
        .map_err(|_| "target signature has an invalid compact encoding".to_string())?;
    let verifying_key = VerifyingKey::recover_from_prehash(digest, &signature, recovery_id)
        .map_err(|_| "target signature could not recover an identity".to_string())?;
    verifying_key
        .verify_prehash(digest, &signature)
        .map_err(|_| "target signature failed verification".to_string())?;

    let public_key = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key.as_bytes();
    let address_hash = Keccak256::digest(&public_key_bytes[1..]);
    let derived_did = format!("did:t3n:{}", hex::encode(&address_hash[12..]));
    if derived_did != expected_did {
        return Err("target signature identity does not match the requested DID".to_string());
    }
    Ok(())
}

fn verify_observer_signature(
    digest: &[u8; 32],
    observer_key: &[u8],
    encoded_signature: &str,
) -> Result<(), String> {
    if observer_key.len() < 16 {
        return Err("observer receipt key is too short".to_string());
    }
    let signature = decode_hex(encoded_signature, 32, "observer signature")?;
    let mut mac = HmacSha256::new_from_slice(observer_key)
        .map_err(|_| "observer receipt key is invalid".to_string())?;
    mac.update(digest);
    mac.verify_slice(&signature)
        .map_err(|_| "observer receipt failed verification".to_string())
}

fn decode_hex(value: &str, expected_bytes: usize, label: &str) -> Result<Vec<u8>, String> {
    let raw = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if raw.len() != expected_bytes * 2 {
        return Err(format!("{label} has the wrong length"));
    }
    hex::decode(raw).map_err(|_| format!("{label} is not valid hex"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AttemptedAction, TargetResponse};

    fn response() -> TargetResponse {
        TargetResponse {
            observed_version_hash: "v2".to_string(),
            text: "safe".to_string(),
            attempted_actions: vec![AttemptedAction {
                function: "support.lookup".to_string(),
                host: Some("support-api.oriel.test".to_string()),
            }],
            target_signature: "0x00".to_string(),
            observer_signature: "0x00".to_string(),
        }
    }

    #[test]
    fn attestation_digest_changes_when_response_evidence_changes() {
        let first =
            target_attestation_digest("run-1", "pack", "did:t3n:abc", &response()).expect("digest");
        let mut changed = response();
        changed.text = "changed".to_string();
        let second =
            target_attestation_digest("run-1", "pack", "did:t3n:abc", &changed).expect("digest");
        assert_ne!(first, second);
    }

    #[test]
    fn malformed_signatures_fail_closed_without_echoing_them() {
        let error = verify_response_attestations(
            "run-1",
            "pack",
            "did:t3n:abc",
            &response(),
            b"observer-key-123456",
        )
        .expect_err("malformed signatures must fail");
        assert!(error.contains("target signature"));
        assert!(!error.contains("0x00"));
    }

    #[test]
    fn node_attestation_fixture_verifies_in_the_rust_contract() {
        let response = TargetResponse {
            observed_version_hash: "sha256:fixture-v2".to_string(),
            text: "safe response".to_string(),
            attempted_actions: vec![AttemptedAction {
                function: "support.lookup".to_string(),
                host: Some("support-api.oriel.test".to_string()),
            }],
            target_signature: "0x016462b35d50191458f88f5803057a1e5d5f5aa79cf8a39ba4631af61740cfdcfd19faf9b105ddbd31a3c1100254933b5d6707d66c3c740a9b88bcc405761d7110".to_string(),
            observer_signature: "0xf79f173adc6173bb52816f1998d607cd2e6b34b02cf57b1b0d1dd99014f9ad78".to_string(),
        };
        verify_response_attestations(
            "run-cross-language",
            "support-data-boundary",
            "did:t3n:19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
            &response,
            b"oriel-demo-observer-key-v1",
        )
        .expect("Node-generated target and observer attestations should verify");
    }
}
