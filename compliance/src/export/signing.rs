//! Ed25519 signing for exported evidence bundles.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::json_export;
use super::SignedEvidenceBundle;
use crate::error::{ComplianceError, ComplianceResult};

/// Sign a `SignedEvidenceBundle` by:
/// 1. Serializing the bundle to JSON (with `signature: null`)
/// 2. Computing SHA-256 of the JSON
/// 3. Signing the hash with Ed25519
/// 4. Setting the `signature` field
pub fn sign_bundle(
    bundle: &mut SignedEvidenceBundle,
    signing_key: &SigningKey,
) -> ComplianceResult<()> {
    // Clear any existing signature before serializing
    bundle.signature = None;

    let json = json_export::to_json(bundle)?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let hash = hasher.finalize();

    let signature = signing_key.sign(&hash);
    bundle.signature = Some(signature.to_bytes().to_vec());

    Ok(())
}

/// Verify the Ed25519 signature on a `SignedEvidenceBundle`.
pub fn verify_bundle_signature(
    bundle: &SignedEvidenceBundle,
    public_key: &VerifyingKey,
) -> ComplianceResult<bool> {
    let signature_bytes = bundle
        .signature
        .as_ref()
        .ok_or_else(|| ComplianceError::signature_error("Bundle has no signature"))?;

    if signature_bytes.len() != 64 {
        return Err(ComplianceError::signature_error(format!(
            "Invalid signature length: {} (expected 64)",
            signature_bytes.len()
        )));
    }

    // Reconstruct the unsigned JSON
    let mut unsigned = bundle.clone();
    unsigned.signature = None;
    let json = json_export::to_json(&unsigned)?;

    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    let hash = hasher.finalize();

    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(signature_bytes);
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    match public_key.verify_strict(&hash, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EvidenceBundle, EvidenceItem, EvidenceType};
    use crate::policy::{PolicyResult, RuleResult};
    use rand::rngs::OsRng;

    fn make_test_bundle() -> SignedEvidenceBundle {
        SignedEvidenceBundle {
            bundle: EvidenceBundle {
                schema_version: "0.1".to_string(),
                bundle_id: "sign-test".to_string(),
                created_at: "2026-02-17T00:00:00Z".to_string(),
                items: vec![EvidenceItem {
                    item_id: "item-1".to_string(),
                    evidence_type: EvidenceType::Receipt,
                    data: vec![10, 20, 30],
                    hash: [2u8; 32],
                    description: "test".to_string(),
                }],
                bindings: vec![],
            },
            policy_result: PolicyResult {
                compliant: true,
                profile_name: "baseline".to_string(),
                rules: vec![RuleResult {
                    rule_id: "SIG-001".to_string(),
                    rule_name: "test".to_string(),
                    passed: true,
                    reason: "ok".to_string(),
                }],
                summary: "ok".to_string(),
            },
            control_results: vec![],
            exported_at: "2026-02-17T00:00:00Z".to_string(),
            signature: None,
        }
    }

    #[test]
    fn test_sign_and_verify() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();

        let mut bundle = make_test_bundle();
        sign_bundle(&mut bundle, &signing_key).unwrap();
        assert!(bundle.signature.is_some());

        let valid = verify_bundle_signature(&bundle, &public_key).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_tampered() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();

        let mut bundle = make_test_bundle();
        sign_bundle(&mut bundle, &signing_key).unwrap();

        // Tamper
        bundle.policy_result.compliant = false;

        let valid = verify_bundle_signature(&bundle, &public_key).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_wrong_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let other_key = SigningKey::generate(&mut OsRng);

        let mut bundle = make_test_bundle();
        sign_bundle(&mut bundle, &signing_key).unwrap();

        let valid = verify_bundle_signature(&bundle, &other_key.verifying_key()).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_verify_no_signature() {
        let public_key = SigningKey::generate(&mut OsRng).verifying_key();
        let bundle = make_test_bundle();
        assert!(verify_bundle_signature(&bundle, &public_key).is_err());
    }
}
