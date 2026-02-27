//! CBOR serialization helpers wrapping ciborium.
//!
//! Provides drop-in replacement functions for the serde_cbor API,
//! enabling migration from the unmaintained serde_cbor crate (RUSTSEC-2021-0127).

pub use ciborium::Value;

use serde::{de::DeserializeOwned, Serialize};
use std::cmp::Ordering;

/// Unified CBOR error type covering both serialization and deserialization.
#[derive(Debug)]
pub struct CborError(pub String);

impl std::fmt::Display for CborError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CborError {}

impl<T: std::fmt::Debug> From<ciborium::ser::Error<T>> for CborError {
    fn from(e: ciborium::ser::Error<T>) -> Self {
        Self(format!("{:?}", e))
    }
}

impl<T: std::fmt::Debug> From<ciborium::de::Error<T>> for CborError {
    fn from(e: ciborium::de::Error<T>) -> Self {
        Self(format!("{:?}", e))
    }
}

/// Serialize a value to CBOR bytes (replacement for `serde_cbor::to_vec`).
pub fn to_vec<T: Serialize>(val: &T) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf)?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes (replacement for `serde_cbor::from_slice`).
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError> {
    ciborium::from_reader(bytes).map_err(CborError::from)
}

/// Convert a serializable value to `ciborium::Value` with recursively sorted map keys.
///
/// Replacement for `serde_cbor::value::to_value`. Map keys are sorted per
/// RFC 8949 §4.2.1 (shorter encoded key first, then bytewise lexicographic),
/// ensuring deterministic canonical encoding for receipt signing.
pub fn to_value<T: Serialize>(val: &T) -> Result<Value, CborError> {
    let value = Value::serialized(val).map_err(|e| CborError(e.to_string()))?;
    Ok(sort_value_maps(value))
}

/// Recursively sort all Map entries per RFC 8949 §4.2.1 deterministic encoding.
fn sort_value_maps(val: Value) -> Value {
    match val {
        Value::Map(entries) => {
            let mut sorted: Vec<(Value, Value)> = entries
                .into_iter()
                .map(|(k, v)| (sort_value_maps(k), sort_value_maps(v)))
                .collect();
            sorted.sort_by(|(k1, _), (k2, _)| cmp_cbor_keys(k1, k2));
            Value::Map(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_value_maps).collect()),
        other => other,
    }
}

/// Compare CBOR map keys per RFC 8949 Section 4.2.1 (Deterministically Encoded CBOR).
///
/// Keys are compared by their encoded byte representations:
/// shorter encoded key sorts first, then bytewise lexicographic comparison.
/// This replaces the previous serde_cbor-derived ordering which incorrectly
/// sorted integer keys by logical value (putting negatives before positives).
pub fn cmp_cbor_keys(a: &Value, b: &Value) -> Ordering {
    fn encode_key(v: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).expect("CBOR key encoding should not fail");
        buf
    }

    let a_enc = encode_key(a);
    let b_enc = encode_key(b);
    // RFC 8949 §4.2.1: shorter encoded form sorts first,
    // then bytewise lexicographic comparison for equal lengths.
    a_enc.len().cmp(&b_enc.len()).then_with(|| a_enc.cmp(&b_enc))
}

/// Serialize a `ciborium::Value` to CBOR bytes.
///
/// Unlike `to_vec` (which goes through serde), this encodes a pre-built
/// `Value` tree directly — preserving map key ordering as-is.
pub fn value_to_vec(val: &Value) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf)?;
    Ok(buf)
}

/// Look up a key in a ciborium Map's entries.
pub fn map_get<'a>(entries: &'a [(Value, Value)], key: &Value) -> Option<&'a Value> {
    entries
        .iter()
        .find_map(|(k, v)| if k == key { Some(v) } else { None })
}

/// Check if a key exists in a ciborium Map's entries.
pub fn map_contains_key(entries: &[(Value, Value)], key: &Value) -> bool {
    entries.iter().any(|(k, _)| k == key)
}
