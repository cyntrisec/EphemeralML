use anyhow::{bail, Context, Result};
use ciborium::Value;
use ed25519_dalek::VerifyingKey;

/// Extract the receipt signing key from an attestation document.
///
/// For Nitro COSE_Sign1 documents, this verifies the attestation signature and
/// certificate chain before trusting the embedded user_data. For plain CBOR map
/// mock documents, callers must explicitly opt in with `allow_mock = true`.
pub fn extract_key_from_attestation(att_bytes: &[u8], allow_mock: bool) -> Result<VerifyingKey> {
    let doc: Value = ephemeral_ml_common::cbor::from_slice(att_bytes)
        .context("Invalid CBOR attestation document")?;

    let map_entries = match &doc {
        Value::Array(arr) if arr.len() == 4 => {
            let policy = crate::PolicyManager::new();
            let mut verifier = crate::attestation_verifier::AttestationVerifier::new(policy);
            let identity = verifier
                .verify_attestation_bytes_skip_nonce(att_bytes)
                .context(
                    "Attestation COSE signature or certificate chain verification failed. \
                 The attestation document is not authentic.",
                )?;

            return VerifyingKey::from_bytes(&identity.receipt_signing_key)
                .context("Invalid receipt signing key from verified attestation");
        }
        Value::Map(m) => {
            if !allow_mock {
                bail!(
                    "Attestation document is a plain CBOR map (mock format) without \
                     cryptographic verification. This is NOT safe for production use.\n\
                     If you are testing locally, pass --allow-mock to accept unverified \
                     attestation documents."
                );
            }
            m.clone()
        }
        _ => bail!("Attestation document is neither COSE_Sign1 nor CBOR map"),
    };

    let user_data_key = Value::Text("user_data".to_string());
    let user_data_bytes = match ephemeral_ml_common::cbor::map_get(&map_entries, &user_data_key) {
        Some(Value::Bytes(b)) => b,
        _ => bail!("No user_data bytes in attestation document"),
    };

    let user_data: ephemeral_ml_common::AttestationUserData =
        if let Ok(parsed) = serde_json::from_slice(user_data_bytes) {
            parsed
        } else {
            ephemeral_ml_common::cbor::from_slice(user_data_bytes)
                .context("Failed to parse user_data from attestation (tried JSON and CBOR)")?
        };

    VerifyingKey::from_bytes(&user_data.receipt_signing_key).context("Invalid receipt signing key")
}
