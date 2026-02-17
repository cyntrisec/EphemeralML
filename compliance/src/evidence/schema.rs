//! Schema validation for evidence bundles.

use super::EvidenceBundle;
use crate::error::{ComplianceError, ComplianceResult};

/// The only supported schema version.
pub const CURRENT_SCHEMA_VERSION: &str = "0.1";

/// Validate an evidence bundle against the schema constraints.
///
/// Checks:
/// - `schema_version` must be `"0.1"`
/// - `bundle_id` must be non-empty
/// - At least one evidence item must be present
/// - Every item must have a non-zero hash (not all zeroes)
/// - Every item must have a non-empty `item_id`
pub fn validate_bundle(bundle: &EvidenceBundle) -> ComplianceResult<()> {
    // Schema version
    if bundle.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(ComplianceError::schema_error(format!(
            "Unsupported schema version '{}', expected '{}'",
            bundle.schema_version, CURRENT_SCHEMA_VERSION
        )));
    }

    // Bundle ID
    if bundle.bundle_id.is_empty() {
        return Err(ComplianceError::schema_error("bundle_id must not be empty"));
    }

    // At least one item
    if bundle.items.is_empty() {
        return Err(ComplianceError::schema_error(
            "Bundle must contain at least one evidence item",
        ));
    }

    // Item constraints
    for item in &bundle.items {
        if item.item_id.is_empty() {
            return Err(ComplianceError::schema_error(
                "Evidence item has an empty item_id",
            ));
        }

        if item.hash == [0u8; 32] {
            return Err(ComplianceError::schema_error(format!(
                "Evidence item '{}' has an all-zero hash",
                item.item_id
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EvidenceItem, EvidenceType};

    fn make_valid_item(id: &str) -> EvidenceItem {
        EvidenceItem {
            item_id: id.to_string(),
            evidence_type: EvidenceType::Receipt,
            data: vec![1, 2, 3],
            hash: [1u8; 32],
            description: "test item".to_string(),
        }
    }

    fn make_valid_bundle() -> EvidenceBundle {
        EvidenceBundle {
            schema_version: "0.1".to_string(),
            bundle_id: "bundle-001".to_string(),
            created_at: "2026-02-17T00:00:00Z".to_string(),
            items: vec![make_valid_item("item-1")],
            bindings: vec![],
        }
    }

    #[test]
    fn test_valid_bundle_passes() {
        assert!(validate_bundle(&make_valid_bundle()).is_ok());
    }

    #[test]
    fn test_wrong_schema_version() {
        let mut b = make_valid_bundle();
        b.schema_version = "1.0".to_string();
        assert!(validate_bundle(&b).is_err());
    }

    #[test]
    fn test_empty_bundle_id() {
        let mut b = make_valid_bundle();
        b.bundle_id = String::new();
        assert!(validate_bundle(&b).is_err());
    }

    #[test]
    fn test_no_items() {
        let mut b = make_valid_bundle();
        b.items.clear();
        assert!(validate_bundle(&b).is_err());
    }

    #[test]
    fn test_zero_hash_rejected() {
        let mut b = make_valid_bundle();
        b.items[0].hash = [0u8; 32];
        assert!(validate_bundle(&b).is_err());
    }

    #[test]
    fn test_empty_item_id_rejected() {
        let mut b = make_valid_bundle();
        b.items[0].item_id = String::new();
        assert!(validate_bundle(&b).is_err());
    }
}
