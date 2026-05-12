//! Local proxy policy inputs for worker attestation pinning.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{EphemeralError, Result};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CyntrisecPolicy {
    #[serde(
        default,
        alias = "EnclaveImageSha384",
        alias = "ImageSha384",
        alias = "PCR0",
        alias = "pcr0",
        alias = "enclave_pcr0_sha384",
        alias = "image_sha384"
    )]
    pub enclave_image_sha384: Option<String>,
    #[serde(
        default,
        alias = "EnclavePcr1Sha384",
        alias = "PCR1",
        alias = "pcr1",
        alias = "enclave_pcr1_sha384"
    )]
    pub pcr1: Option<String>,
    #[serde(
        default,
        alias = "EnclavePcr2Sha384",
        alias = "PCR2",
        alias = "pcr2",
        alias = "enclave_pcr2_sha384"
    )]
    pub pcr2: Option<String>,
}

impl CyntrisecPolicy {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|err| EphemeralError::SerializationError(err.to_string()))
    }

    pub fn expected_measurement_values(&self) -> Result<BTreeMap<usize, Vec<u8>>> {
        let mut values = BTreeMap::new();
        push_measurement(
            &mut values,
            0,
            self.enclave_image_sha384.as_deref(),
            "enclave_image_sha384",
        )?;
        push_measurement(&mut values, 1, self.pcr1.as_deref(), "pcr1")?;
        push_measurement(&mut values, 2, self.pcr2.as_deref(), "pcr2")?;
        Ok(values)
    }
}

fn push_measurement(
    values: &mut BTreeMap<usize, Vec<u8>>,
    index: usize,
    raw: Option<&str>,
    label: &str,
) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let normalized = raw
        .strip_prefix("sha384:")
        .or_else(|| raw.strip_prefix("SHA384:"))
        .unwrap_or(raw);
    let bytes = hex::decode(normalized).map_err(|err| {
        EphemeralError::ValidationError(format!("{label} is not valid hex: {err}"))
    })?;
    if bytes.len() != 48 {
        return Err(EphemeralError::ValidationError(format!(
            "{label} must decode to 48 bytes, got {}",
            bytes.len()
        )));
    }
    values.insert(index, bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_extracts_flat_nitro_measurements() {
        let pcr0 = "00".repeat(48);
        let pcr1 = "11".repeat(48);
        let pcr2 = "22".repeat(48);
        let json = format!(
            r#"{{
                "enclave_image_sha384": "{pcr0}",
                "pcr1": "sha384:{pcr1}",
                "pcr2": "{pcr2}"
            }}"#
        );
        let policy = CyntrisecPolicy::from_json(json.as_bytes()).unwrap();
        let measurements = policy.expected_measurement_values().unwrap();
        assert_eq!(measurements.get(&0).unwrap(), &vec![0x00; 48]);
        assert_eq!(measurements.get(&1).unwrap(), &vec![0x11; 48]);
        assert_eq!(measurements.get(&2).unwrap(), &vec![0x22; 48]);
    }

    #[test]
    fn policy_rejects_wrong_measurement_length() {
        let policy = CyntrisecPolicy {
            enclave_image_sha384: Some("00".repeat(32)),
            pcr1: None,
            pcr2: None,
        };
        let err = policy.expected_measurement_values().unwrap_err();
        assert!(err.to_string().contains("48 bytes"));
    }
}
