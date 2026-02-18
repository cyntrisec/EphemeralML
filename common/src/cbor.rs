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
/// Replacement for `serde_cbor::value::to_value`. Map keys are sorted to match
/// serde_cbor's `BTreeMap`-based ordering (variant index then content), ensuring
/// deterministic canonical encoding for receipt signing.
pub fn to_value<T: Serialize>(val: &T) -> Result<Value, CborError> {
    let value = Value::serialized(val).map_err(|e| CborError(e.to_string()))?;
    Ok(sort_value_maps(value))
}

/// Recursively sort all Map entries to match serde_cbor's BTreeMap key ordering.
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

/// Compare CBOR map keys matching serde_cbor's derived `Ord` on `Value`.
///
/// serde_cbor orders variants: Integer, Bytes, Text, Array, Map, Tag, Bool, Null, Float.
/// Within a variant, standard Rust comparison applies (i128 for Integer, String for Text, etc.).
fn cmp_cbor_keys(a: &Value, b: &Value) -> Ordering {
    fn variant_idx(v: &Value) -> u8 {
        match v {
            Value::Integer(_) => 0,
            Value::Bytes(_) => 1,
            Value::Text(_) => 2,
            Value::Array(_) => 3,
            Value::Map(_) => 4,
            Value::Tag(_, _) => 5,
            Value::Bool(_) => 6,
            Value::Null => 7,
            Value::Float(_) => 8,
            _ => 9,
        }
    }

    variant_idx(a)
        .cmp(&variant_idx(b))
        .then_with(|| match (a, b) {
            (Value::Integer(x), Value::Integer(y)) => {
                let xv: i128 = (*x).into();
                let yv: i128 = (*y).into();
                xv.cmp(&yv)
            }
            (Value::Text(x), Value::Text(y)) => x.cmp(y),
            (Value::Bytes(x), Value::Bytes(y)) => x.cmp(y),
            (Value::Bool(x), Value::Bool(y)) => x.cmp(y),
            _ => Ordering::Equal,
        })
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
