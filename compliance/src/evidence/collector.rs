//! Evidence bundle collector for incrementally building bundles.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{EvidenceBinding, EvidenceBundle, EvidenceItem, EvidenceType};
use crate::error::{ComplianceError, ComplianceResult};

/// Incrementally collects evidence items and bindings into an `EvidenceBundle`.
pub struct EvidenceBundleCollector {
    items: Vec<EvidenceItem>,
    bindings: Vec<EvidenceBinding>,
}

impl EvidenceBundleCollector {
    /// Create a new empty collector.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            bindings: Vec::new(),
        }
    }

    /// Add a receipt (CBOR-encoded `AttestationReceipt`) to the bundle.
    ///
    /// Returns the generated item ID.
    pub fn add_receipt(&mut self, receipt_bytes: &[u8]) -> ComplianceResult<String> {
        if receipt_bytes.is_empty() {
            return Err(ComplianceError::invalid_bundle(
                "Receipt data must not be empty",
            ));
        }

        let item_id = format!("receipt-{}", Uuid::new_v4());
        let hash = sha256(receipt_bytes);

        self.items.push(EvidenceItem {
            item_id: item_id.clone(),
            evidence_type: EvidenceType::Receipt,
            data: receipt_bytes.to_vec(),
            hash,
            description: "Attested Execution Receipt".to_string(),
        });

        Ok(item_id)
    }

    /// Add a raw attestation document to the bundle.
    ///
    /// Returns the generated item ID.
    pub fn add_attestation(&mut self, att_bytes: &[u8]) -> ComplianceResult<String> {
        if att_bytes.is_empty() {
            return Err(ComplianceError::invalid_bundle(
                "Attestation data must not be empty",
            ));
        }

        let item_id = format!("attestation-{}", Uuid::new_v4());
        let hash = sha256(att_bytes);

        self.items.push(EvidenceItem {
            item_id: item_id.clone(),
            evidence_type: EvidenceType::Attestation,
            data: att_bytes.to_vec(),
            hash,
            description: "Attestation document".to_string(),
        });

        Ok(item_id)
    }

    /// Add a model manifest to the bundle.
    ///
    /// Returns the generated item ID.
    pub fn add_model_manifest(&mut self, manifest_bytes: &[u8]) -> ComplianceResult<String> {
        if manifest_bytes.is_empty() {
            return Err(ComplianceError::invalid_bundle(
                "Model manifest data must not be empty",
            ));
        }

        let item_id = format!("manifest-{}", Uuid::new_v4());
        let hash = sha256(manifest_bytes);

        self.items.push(EvidenceItem {
            item_id: item_id.clone(),
            evidence_type: EvidenceType::ModelManifest,
            data: manifest_bytes.to_vec(),
            hash,
            description: "Model manifest".to_string(),
        });

        Ok(item_id)
    }

    /// Add a binding between two evidence items.
    pub fn add_binding(
        &mut self,
        source: &str,
        target: &str,
        binding_type: &str,
        hash: Option<[u8; 32]>,
    ) {
        self.bindings.push(EvidenceBinding {
            source_item_id: source.to_string(),
            target_item_id: target.to_string(),
            binding_type: binding_type.to_string(),
            binding_hash: hash,
        });
    }

    /// Finalize the collector into an `EvidenceBundle`.
    ///
    /// Assigns a unique bundle ID and creation timestamp.
    pub fn build(self) -> ComplianceResult<EvidenceBundle> {
        if self.items.is_empty() {
            return Err(ComplianceError::invalid_bundle(
                "Cannot build a bundle with no evidence items",
            ));
        }

        let bundle = EvidenceBundle {
            schema_version: "0.1".to_string(),
            bundle_id: format!("bundle-{}", Uuid::new_v4()),
            created_at: chrono::Utc::now().to_rfc3339(),
            items: self.items,
            bindings: self.bindings,
        };

        Ok(bundle)
    }
}

impl Default for EvidenceBundleCollector {
    fn default() -> Self {
        Self::new()
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_and_build() {
        let mut collector = EvidenceBundleCollector::new();
        let r_id = collector.add_receipt(b"receipt-data").unwrap();
        let a_id = collector.add_attestation(b"attestation-data").unwrap();
        collector.add_binding(&r_id, &a_id, "signing-key-attestation", None);

        let bundle = collector.build().unwrap();
        assert_eq!(bundle.schema_version, "0.1");
        assert!(bundle.bundle_id.starts_with("bundle-"));
        assert_eq!(bundle.items.len(), 2);
        assert_eq!(bundle.bindings.len(), 1);
    }

    #[test]
    fn test_empty_receipt_rejected() {
        let mut collector = EvidenceBundleCollector::new();
        assert!(collector.add_receipt(b"").is_err());
    }

    #[test]
    fn test_empty_attestation_rejected() {
        let mut collector = EvidenceBundleCollector::new();
        assert!(collector.add_attestation(b"").is_err());
    }

    #[test]
    fn test_empty_build_rejected() {
        let collector = EvidenceBundleCollector::new();
        assert!(collector.build().is_err());
    }

    #[test]
    fn test_hash_is_sha256() {
        let data = b"hello world";
        let hash = sha256(data);
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(hex::encode(hash), expected);
    }
}
