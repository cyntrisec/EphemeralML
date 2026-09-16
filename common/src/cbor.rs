//! CBOR serialization helpers wrapping ciborium.
//!
//! Provides drop-in replacement functions for the serde_cbor API,
//! enabling migration from the unmaintained serde_cbor crate (RUSTSEC-2021-0127).

pub use ciborium::Value;

use serde::{de::DeserializeOwned, Serialize};
use std::cmp::Ordering;
use std::io::Cursor;

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

/// Deserialize exactly one CBOR item from a byte slice.
///
/// Generic CBOR decoders may successfully return the first item while leaving
/// trailing bytes unread. AIR verifier-critical fields (notably the CWT payload
/// bstr) require the byte string to contain exactly one CBOR item.
pub fn from_slice_exact<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CborError> {
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::from_reader(&mut cursor).map_err(CborError::from)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CborError(format!(
            "trailing bytes after CBOR item: {} byte(s)",
            bytes.len() as u64 - cursor.position()
        )));
    }
    Ok(value)
}

/// Convert a serializable value to `ciborium::Value` with recursively sorted map keys.
///
/// Replacement for `serde_cbor::value::to_value`. Map keys are sorted per
/// RFC 8949 §4.2.1 (bytewise lexicographic order of the encoded keys),
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
/// Keys are compared by the bytewise lexicographic order of their deterministic
/// encodings (RFC 8949 §4.2.1), NOT the §4.2.3 length-first ordering. This
/// replaces the previous serde_cbor-derived ordering which incorrectly sorted
/// integer keys by logical value (putting negatives before positives).
pub fn cmp_cbor_keys(a: &Value, b: &Value) -> Ordering {
    fn encode_key(v: &Value) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(v, &mut buf).expect("CBOR key encoding should not fail");
        buf
    }

    let a_enc = encode_key(a);
    let b_enc = encode_key(b);
    // RFC 8949 §4.2.1: bytewise lexicographic comparison of the encoded keys
    // (NOT the §4.2.3 length-first ordering).
    a_enc.cmp(&b_enc)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::Ordering;

    /// Locks RFC 8949 §4.2.1 (bytewise) ordering and guards against a regression
    /// to §4.2.3 (length-first). The canonical example: integer key 100 encodes
    /// as 0x18 0x64 (2 bytes) and -1 as 0x20 (1 byte). Under §4.2.1 bytewise,
    /// 0x18.. < 0x20 so 100 sorts BEFORE -1; under §4.2.3 length-first, the
    /// 1-byte -1 would sort first. This test fails if the comparator reverts.
    #[test]
    fn cmp_cbor_keys_is_bytewise_not_length_first() {
        let k100 = Value::Integer(100.into());
        let kneg1 = Value::Integer((-1).into());
        assert_eq!(
            cmp_cbor_keys(&k100, &kneg1),
            Ordering::Less,
            "RFC 8949 §4.2.1 bytewise: 100 (0x1864) MUST sort before -1 (0x20)"
        );
        assert_eq!(cmp_cbor_keys(&kneg1, &k100), Ordering::Greater);
    }

    /// A sorted map with divergence-zone keys ends up in bytewise (§4.2.1) order.
    #[test]
    fn sort_value_maps_uses_bytewise_order() {
        let m = Value::Map(vec![
            (Value::Integer((-1).into()), Value::Bool(true)),
            (Value::Integer(100.into()), Value::Bool(false)),
        ]);
        if let Value::Map(entries) = sort_value_maps(m) {
            // 100 (0x1864) sorts before -1 (0x20) under §4.2.1 bytewise.
            assert_eq!(entries[0].0, Value::Integer(100.into()));
            assert_eq!(entries[1].0, Value::Integer((-1).into()));
        } else {
            panic!("expected a Map");
        }
    }
}
