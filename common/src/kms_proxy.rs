use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// KMS Request types (matching Host definition)
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "op", content = "payload")]
pub enum KmsRequest {
    Decrypt {
         ciphertext_blob: Vec<u8>,
         key_id: Option<String>,
         encryption_context: Option<HashMap<String, String>>,
         grant_tokens: Option<Vec<String>>,
         recipient: Option<Vec<u8>>, // Attestation document
    },
    GenerateDataKey {
        key_id: String,
        key_spec: String,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KmsResponse {
    Decrypt {
        /// If Recipient was provided in request, this contains the payload encrypted to the recipient key.
        ciphertext_for_recipient: Option<Vec<u8>>,
        /// If Recipient was NOT provided, this contains plaintext (NOT SAFE for Enclaves).
        plaintext: Option<Vec<u8>>,
        key_id: Option<String>,
    },
    GenerateDataKey {
        ciphertext_blob: Vec<u8>,
        plaintext: Vec<u8>,
        key_id: String,
    },
    Error(String),
}
