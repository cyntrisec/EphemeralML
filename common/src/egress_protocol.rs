//! Cyntrisec enclave-to-host egress protocol v1.
//!
//! The v1 wire format is deterministic CBOR with schema version first:
//! `[schema_version, tag, payload]`. Requests use operation tags and responses
//! use result tags. Decode fails closed on unknown schema versions or tags.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::cbor::Value;
use crate::error::{EphemeralError, Result};

pub const EGRESS_PROTOCOL_VERSION: u8 = 1;

const OP_KMS_DECRYPT: &str = "kms_decrypt";
const OP_S3_PUT_OBJECT: &str = "s3_put_object";
const RESULT_OK: &str = "ok";
const RESULT_ERR: &str = "err";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum EgressRequest {
    KmsDecrypt(KmsDecryptRequest),
    S3PutObject(S3PutObjectRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsDecryptRequest {
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    pub key_arn: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_context: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3PutObjectRequest {
    pub bucket: String,
    pub key: String,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kms_key_arn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", content = "data", rename_all = "snake_case")]
pub enum EgressResponse {
    Ok(EgressOkResponse),
    Err(EgressError),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "data", rename_all = "snake_case")]
pub enum EgressOkResponse {
    KmsDecrypt(KmsDecryptResponse),
    S3PutObject(S3PutObjectResponse),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KmsDecryptResponse {
    #[serde(with = "serde_bytes")]
    pub plaintext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3PutObjectResponse {
    pub etag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressError {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_request_id: Option<String>,
}

impl EgressError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            aws_request_id: None,
        }
    }

    pub fn with_aws_request_id(mut self, aws_request_id: impl Into<String>) -> Self {
        self.aws_request_id = Some(aws_request_id.into());
        self
    }
}

impl fmt::Display for EgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.aws_request_id {
            Some(request_id) => write!(
                f,
                "{}: {} (aws_request_id={})",
                self.code, self.message, request_id
            ),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for EgressError {}

#[derive(Debug, Serialize, Deserialize)]
struct VersionedWire(u8, String, Value);

impl EgressRequest {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let (op, payload) = match self {
            Self::KmsDecrypt(req) => (OP_KMS_DECRYPT, to_payload_value(req, "KmsDecryptRequest")?),
            Self::S3PutObject(req) => (
                OP_S3_PUT_OBJECT,
                to_payload_value(req, "S3PutObjectRequest")?,
            ),
        };
        encode_wire(op, payload, "EgressRequest")
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        let wire = decode_wire(data, "EgressRequest")?;
        match wire.1.as_str() {
            OP_KMS_DECRYPT => Ok(Self::KmsDecrypt(from_payload_value(
                wire.2,
                "KmsDecryptRequest",
            )?)),
            OP_S3_PUT_OBJECT => Ok(Self::S3PutObject(from_payload_value(
                wire.2,
                "S3PutObjectRequest",
            )?)),
            other => Err(EphemeralError::ProtocolError(format!(
                "unsupported EgressRequest op: {other}"
            ))),
        }
    }
}

impl EgressResponse {
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let (result, payload) = match self {
            Self::Ok(ok) => (RESULT_OK, to_payload_value(ok, "EgressOkResponse")?),
            Self::Err(err) => (RESULT_ERR, to_payload_value(err, "EgressError")?),
        };
        encode_wire(result, payload, "EgressResponse")
    }

    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        let wire = decode_wire(data, "EgressResponse")?;
        match wire.1.as_str() {
            RESULT_OK => Ok(Self::Ok(from_payload_value(wire.2, "EgressOkResponse")?)),
            RESULT_ERR => Ok(Self::Err(from_payload_value(wire.2, "EgressError")?)),
            other => Err(EphemeralError::ProtocolError(format!(
                "unsupported EgressResponse result: {other}"
            ))),
        }
    }
}

fn encode_wire(tag: &str, payload: Value, label: &str) -> Result<Vec<u8>> {
    let wire = VersionedWire(EGRESS_PROTOCOL_VERSION, tag.to_string(), payload);
    crate::cbor::to_vec(&wire).map_err(|err| {
        EphemeralError::SerializationError(format!("{label} encoding failed: {err}"))
    })
}

fn decode_wire(data: &[u8], label: &str) -> Result<VersionedWire> {
    let wire: VersionedWire = crate::cbor::from_slice(data).map_err(|err| {
        EphemeralError::SerializationError(format!("{label} decoding failed: {err}"))
    })?;
    if wire.0 != EGRESS_PROTOCOL_VERSION {
        return Err(EphemeralError::ProtocolError(format!(
            "unsupported {label} schema_version: {}",
            wire.0
        )));
    }
    Ok(wire)
}

fn to_payload_value<T: Serialize>(value: &T, label: &str) -> Result<Value> {
    crate::cbor::to_value(value).map_err(|err| {
        EphemeralError::SerializationError(format!("{label} encoding failed: {err}"))
    })
}

fn from_payload_value<T: for<'de> Deserialize<'de>>(value: Value, label: &str) -> Result<T> {
    let bytes = crate::cbor::value_to_vec(&value).map_err(|err| {
        EphemeralError::SerializationError(format!("{label} value encoding failed: {err}"))
    })?;
    crate::cbor::from_slice(&bytes).map_err(|err| {
        EphemeralError::SerializationError(format!("{label} decoding failed: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kms_request() -> EgressRequest {
        let mut ctx = BTreeMap::new();
        ctx.insert("model".to_string(), "llama-3.1-8b".to_string());
        EgressRequest::KmsDecrypt(KmsDecryptRequest {
            ciphertext: vec![0xC0, 0xFF, 0xEE],
            key_arn: "arn:aws:kms:us-east-1:111122223333:key/model".to_string(),
            encryption_context: Some(ctx),
        })
    }

    fn s3_request() -> EgressRequest {
        let mut metadata = BTreeMap::new();
        metadata.insert("air-receipt-sha256".to_string(), "abc123".to_string());
        EgressRequest::S3PutObject(S3PutObjectRequest {
            bucket: "cyntrisec-evidence".to_string(),
            key: "bundles/receipt.tar.gz".to_string(),
            body: vec![0x1F, 0x8B, 0x08],
            content_type: Some("application/gzip".to_string()),
            kms_key_arn: Some("arn:aws:kms:us-east-1:111122223333:key/evidence".to_string()),
            metadata: Some(metadata),
        })
    }

    fn kms_ok() -> EgressResponse {
        EgressResponse::Ok(EgressOkResponse::KmsDecrypt(KmsDecryptResponse {
            plaintext: vec![0xDE, 0xAD, 0xBE, 0xEF],
        }))
    }

    fn s3_ok() -> EgressResponse {
        EgressResponse::Ok(EgressOkResponse::S3PutObject(S3PutObjectResponse {
            etag: "\"abc123\"".to_string(),
            version_id: Some("3Lg...".to_string()),
        }))
    }

    fn err_response() -> EgressResponse {
        EgressResponse::Err(
            EgressError::new("s3.access_denied", "put object denied").with_aws_request_id("REQ123"),
        )
    }

    #[test]
    fn egress_kms_decrypt_request_roundtrips() {
        let encoded = kms_request().to_cbor().unwrap();
        let decoded = EgressRequest::from_cbor(&encoded).unwrap();
        assert_eq!(decoded, kms_request());
    }

    #[test]
    fn egress_s3_put_object_request_roundtrips() {
        let encoded = s3_request().to_cbor().unwrap();
        let decoded = EgressRequest::from_cbor(&encoded).unwrap();
        assert_eq!(decoded, s3_request());
    }

    #[test]
    fn egress_ok_responses_roundtrip() {
        for response in [kms_ok(), s3_ok()] {
            let encoded = response.to_cbor().unwrap();
            let decoded = EgressResponse::from_cbor(&encoded).unwrap();
            assert_eq!(decoded, response);
        }
    }

    #[test]
    fn egress_error_response_roundtrips() {
        let encoded = err_response().to_cbor().unwrap();
        let decoded = EgressResponse::from_cbor(&encoded).unwrap();
        assert_eq!(decoded, err_response());
    }

    #[test]
    fn egress_decode_rejects_unknown_schema_version() {
        let mut encoded = kms_request().to_cbor().unwrap();
        encoded[1] = 2;
        let err = EgressRequest::from_cbor(&encoded).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported EgressRequest schema_version: 2"));
    }

    #[test]
    fn egress_decode_rejects_unknown_request_op() {
        let payload = to_payload_value(
            &KmsDecryptRequest {
                ciphertext: vec![1],
                key_arn: "arn".to_string(),
                encryption_context: None,
            },
            "test",
        )
        .unwrap();
        let encoded = encode_wire("s3_get_object", payload, "test").unwrap();
        let err = EgressRequest::from_cbor(&encoded).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported EgressRequest op: s3_get_object"));
    }

    #[test]
    fn egress_decode_rejects_unknown_response_op_variant() {
        let payload = crate::cbor::to_value(&serde_json::json!({
            "op": "s3_get_object",
            "data": {"body": [1, 2, 3]}
        }))
        .unwrap();
        let encoded = encode_wire(RESULT_OK, payload, "test").unwrap();
        let err = EgressResponse::from_cbor(&encoded).unwrap_err();
        assert!(err.to_string().contains("EgressOkResponse decoding failed"));
    }

    #[test]
    fn egress_decode_rejects_unknown_response_result() {
        let payload = to_payload_value(&EgressError::new("test.error", "test"), "test").unwrap();
        let encoded = encode_wire("pending", payload, "test").unwrap();
        let err = EgressResponse::from_cbor(&encoded).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported EgressResponse result: pending"));
    }

    #[test]
    fn egress_wire_encoding_is_version_first() {
        let encoded = kms_request().to_cbor().unwrap();
        assert_eq!(encoded[0], 0x83); // CBOR array of 3 items.
        assert_eq!(encoded[1], EGRESS_PROTOCOL_VERSION);
    }

    #[test]
    fn egress_golden_vectors_match_spec_files() {
        let cases = [
            (
                "kms-decrypt-request",
                kms_request().to_cbor().unwrap(),
                include_str!("../../spec/v1/vectors/egress/kms-decrypt-request.cbor.hex"),
            ),
            (
                "s3-put-object-request",
                s3_request().to_cbor().unwrap(),
                include_str!("../../spec/v1/vectors/egress/s3-put-object-request.cbor.hex"),
            ),
            (
                "kms-decrypt-ok-response",
                kms_ok().to_cbor().unwrap(),
                include_str!("../../spec/v1/vectors/egress/kms-decrypt-ok-response.cbor.hex"),
            ),
            (
                "s3-put-object-ok-response",
                s3_ok().to_cbor().unwrap(),
                include_str!("../../spec/v1/vectors/egress/s3-put-object-ok-response.cbor.hex"),
            ),
            (
                "error-response",
                err_response().to_cbor().unwrap(),
                include_str!("../../spec/v1/vectors/egress/error-response.cbor.hex"),
            ),
        ];

        for (name, actual, expected) in cases {
            let expected = hex::decode(expected.trim()).expect("vector hex should decode");
            assert_eq!(actual, expected, "{name} vector drifted");
        }
    }
}
