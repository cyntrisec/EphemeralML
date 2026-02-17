//! Evidence types and bundle structure for compliance proof bundles.

pub mod collector;
pub mod schema;

use serde::{Deserialize, Serialize};

/// The type of evidence contained in an evidence item.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum EvidenceType {
    /// An attested execution receipt (AER).
    Receipt,
    /// A raw attestation document (e.g. COSE_Sign1 from Nitro, TDX quote).
    Attestation,
    /// A model manifest with hashes and metadata.
    ModelManifest,
    /// A policy configuration snapshot.
    PolicyConfig,
}

/// A single piece of evidence in a bundle.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidenceItem {
    /// Unique identifier for this item within the bundle.
    pub item_id: String,
    /// The type of evidence.
    pub evidence_type: EvidenceType,
    /// Raw evidence data (CBOR, JSON, or opaque bytes).
    #[serde(with = "hex_serde")]
    pub data: Vec<u8>,
    /// SHA-256 hash of `data`.
    pub hash: [u8; 32],
    /// Human-readable description of the evidence.
    pub description: String,
}

/// A binding between two evidence items, expressing a cryptographic or logical
/// relationship (e.g. "signing key is bound to attestation document").
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidenceBinding {
    /// The item ID that is the source of the binding.
    pub source_item_id: String,
    /// The item ID that is the target of the binding.
    pub target_item_id: String,
    /// Description of the binding relationship.
    pub binding_type: String,
    /// Optional cryptographic hash tying source to target.
    pub binding_hash: Option<[u8; 32]>,
}

/// A complete evidence bundle containing items, bindings, and metadata.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidenceBundle {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// Unique identifier for this bundle.
    pub bundle_id: String,
    /// RFC 3339 timestamp of when the bundle was created.
    pub created_at: String,
    /// Evidence items.
    pub items: Vec<EvidenceItem>,
    /// Bindings between evidence items.
    pub bindings: Vec<EvidenceBinding>,
}

/// Serde helper for hex-encoding `Vec<u8>` fields.
mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}
