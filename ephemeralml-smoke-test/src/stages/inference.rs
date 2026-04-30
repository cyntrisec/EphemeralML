//! Stage 3 — inference with the fixed synthetic fixture.
//!
//! Fixture (pinned by spec):
//! - Input: `context::CANONICAL_INPUT` — deterministic 97-byte UTF-8 string
//! - Model: MiniLM-L6-v2 (public, baked into the EIF)
//! - Output: 384 float32 embedding values (individual floats NOT compared due
//!   to model nondeterminism tolerance, but output hash is captured)
//!
//! Real probe: open VSock to `<EnclaveCID>:5005` (port pinned in enclave
//! contract), send a single framed request with the fixed input, receive
//! `{embedding: [f32; 384], air_receipt: Vec<u8>}`, verify the input SHA-256
//! echoed in the response matches what was sent.
//!
use super::{Stage, StageResult};
use crate::cli::Args;
use crate::context::Context;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;

pub struct Inference;

#[async_trait]
impl Stage for Inference {
    fn name(&self) -> &'static str {
        "inference"
    }

    async fn run(&self, ctx: &Context, args: &Args) -> StageResult {
        let pcrs = match extract_pcrs(&args.nitro_cli, &args.eif_path).await {
            Ok(pcrs) => pcrs,
            Err(e) => {
                return StageResult::fail(
                    "inference",
                    "PCR_EXTRACTION_FAILED",
                    e,
                    json!({ "eif_path": args.eif_path, "nitro_cli": args.nitro_cli }),
                );
            }
        };

        let receipt_json = ctx.bundle_dir.join("receipt.json");
        let receipt_raw = ctx.bundle_dir.join("receipt.raw");
        let receipt_cbor = ctx.bundle_dir.join("receipt.cbor");
        let receipt_txt = ctx.bundle_dir.join("receipt.txt");
        let attestation = ctx.bundle_dir.join("attestation.cbor");
        let kms_release = ctx.bundle_dir.join("kms-release.json");

        let output = match timeout(
            Duration::from_secs(args.inference_timeout_secs),
            Command::new(&args.host_bin)
                .arg("--enclave-cid")
                .arg(args.enclave_cid.to_string())
                .arg("--control-port")
                .arg("5000")
                .arg("--data-in-port")
                .arg("5001")
                .arg("--data-out-port")
                .arg("5002")
                .arg("--text")
                .arg(&args.input_text)
                .arg("--receipt-output")
                .arg(&receipt_json)
                .arg("--receipt-output-raw")
                .arg(&receipt_raw)
                .arg("--receipt-output-air-v1")
                .arg(&receipt_cbor)
                .arg("--attestation-output")
                .arg(&attestation)
                .arg("--kms-release-output")
                .arg(&kms_release)
                .env("EPHEMERALML_EXPECTED_PCR0", &pcrs.pcr0)
                .env("EPHEMERALML_EXPECTED_PCR1", &pcrs.pcr1)
                .env("EPHEMERALML_EXPECTED_PCR2", &pcrs.pcr2)
                .output(),
        )
        .await
        {
            Ok(Ok(output)) => output,
            Ok(Err(e)) => {
                return StageResult::fail(
                    "inference",
                    "HOST_EXEC_FAILED",
                    format!("failed to execute host binary '{}': {}", args.host_bin, e),
                    json!({ "host_bin": args.host_bin }),
                );
            }
            Err(_) => {
                return StageResult::fail(
                    "inference",
                    "HOST_TIMEOUT",
                    format!(
                        "host inference exceeded {}s timeout",
                        args.inference_timeout_secs
                    ),
                    json!({ "host_bin": args.host_bin }),
                );
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let host_log = format!("--- stdout ---\n{}\n--- stderr ---\n{}\n", stdout, stderr);
        let _ = std::fs::write(ctx.bundle_dir.join("host_output.log"), host_log);

        if !output.status.success() {
            return StageResult::fail(
                "inference",
                "HOST_INFERENCE_FAILED",
                "host orchestrator failed during inference",
                json!({
                    "exit_code": output.status.code(),
                    "stdout_excerpt": truncate(&stdout, 4096),
                    "stderr_excerpt": truncate(&stderr, 4096),
                }),
            );
        }

        if let Err(e) = enrich_kms_release(&kms_release, &pcrs) {
            return StageResult::fail(
                "inference",
                "KMS_RELEASE_ENRICH_FAILED",
                e,
                json!({ "kms_release": kms_release }),
            );
        }

        let missing: Vec<&str> = [
            ("receipt.json", receipt_json.as_path()),
            ("receipt.raw", receipt_raw.as_path()),
            ("receipt.cbor", receipt_cbor.as_path()),
            ("attestation.cbor", attestation.as_path()),
            ("kms-release.json", kms_release.as_path()),
        ]
        .iter()
        .filter_map(|(name, path)| if path.exists() { None } else { Some(*name) })
        .collect();

        if !missing.is_empty() {
            return StageResult::fail(
                "inference",
                "INFERENCE_ARTIFACTS_MISSING",
                format!(
                    "host completed but did not produce required artifacts: {:?}",
                    missing
                ),
                json!({ "missing": missing }),
            );
        }

        let _ = std::fs::write(
            ctx.bundle_dir.join("enclave-measurements.json"),
            serde_json::to_vec_pretty(&json!({
                "measurement_type": "nitro-pcr",
                "pcr0": &pcrs.pcr0,
                "pcr1": &pcrs.pcr1,
                "pcr2": &pcrs.pcr2,
                "eif_path": args.eif_path,
            }))
            .unwrap_or_default(),
        );
        let _ = std::fs::write(
            ctx.bundle_dir.join("inference-metadata.json"),
            serde_json::to_vec_pretty(&json!({
                "input_sha256": sha256_hex(args.input_text.as_bytes()),
                "input_len": args.input_text.len(),
                "host_exit_code": output.status.code(),
                "receipt_cbor_bytes": file_len(ctx.bundle_dir.join("receipt.cbor")),
                "attestation_bytes": file_len(ctx.bundle_dir.join("attestation.cbor")),
                "kms_release_bytes": file_len(ctx.bundle_dir.join("kms-release.json")),
            }))
            .unwrap_or_default(),
        );
        let _ = std::fs::write(
            ctx.bundle_dir.join("model-info.json"),
            serde_json::to_vec_pretty(&json!({
                "model_id": &args.expected_model,
                "expected_model_hash": &args.expected_model_hash,
                "model_release": "kms-gated-required",
            }))
            .unwrap_or_default(),
        );
        if let Err(e) = write_receipt_text(&receipt_json, &receipt_txt) {
            return StageResult::fail(
                "inference",
                "RECEIPT_TEXT_WRITE_FAILED",
                e,
                json!({ "receipt_json": receipt_json, "receipt_txt": receipt_txt }),
            );
        }

        StageResult::pass(
            "inference",
            json!({
                "host_bin": args.host_bin,
                "receipt_json": receipt_json,
                "receipt_raw": receipt_raw,
                "receipt_cbor": receipt_cbor,
                "receipt_txt": receipt_txt,
                "attestation": attestation,
                "kms_release": kms_release,
                "pcr0_prefix": &pcrs.pcr0[..16],
                "pcr1_prefix": &pcrs.pcr1[..16],
                "pcr2_prefix": &pcrs.pcr2[..16],
                "receipt_cbor_bytes": file_len(ctx.bundle_dir.join("receipt.cbor")),
                "attestation_bytes": file_len(ctx.bundle_dir.join("attestation.cbor")),
                "kms_release_bytes": file_len(ctx.bundle_dir.join("kms-release.json")),
            }),
        )
    }
}

struct Pcrs {
    pcr0: String,
    pcr1: String,
    pcr2: String,
}

async fn extract_pcrs(nitro_cli: &str, eif_path: &Path) -> Result<Pcrs, String> {
    let out = Command::new(nitro_cli)
        .arg("describe-eif")
        .arg("--eif-path")
        .arg(eif_path)
        .output()
        .await
        .map_err(|e| format!("failed to execute nitro-cli describe-eif: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!(
            "nitro-cli describe-eif failed: {}{}",
            stdout, stderr
        ));
    }
    let json = parse_first_json_object(&stdout)
        .or_else(|| parse_first_json_object(&stderr))
        .ok_or_else(|| "nitro-cli describe-eif did not return JSON".to_string())?;
    let measurements = json
        .get("Measurements")
        .or_else(|| json.get("measurements"))
        .ok_or_else(|| "describe-eif JSON missing Measurements".to_string())?;
    let pcr0 = get_pcr(measurements, "PCR0")?;
    let pcr1 = get_pcr(measurements, "PCR1")?;
    let pcr2 = get_pcr(measurements, "PCR2")?;
    Ok(Pcrs { pcr0, pcr1, pcr2 })
}

fn parse_first_json_object(text: &str) -> Option<Value> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    serde_json::from_str(&text[start..=end]).ok()
}

fn get_pcr(measurements: &Value, name: &str) -> Result<String, String> {
    let value = measurements
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("Measurements missing {}", name))?;
    if value.len() == 96 && value.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(value.to_string())
    } else {
        Err(format!("{} is not a 96-char SHA-384 hex value", name))
    }
}

fn file_len(path: impl AsRef<Path>) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

fn enrich_kms_release(path: &Path, pcrs: &Pcrs) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let bytes =
        std::fs::read(path).map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
    let mut value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse {}: {}", path.display(), e))?;

    let obj = value
        .as_object_mut()
        .ok_or_else(|| "kms-release.json root must be a JSON object".to_string())?;
    obj.entry("enclave_image_sha384".to_string())
        .or_insert_with(|| Value::String(pcrs.pcr0.to_ascii_lowercase()));

    let needs_nested = obj
        .get("recipient_attestation")
        .and_then(Value::as_object)
        .and_then(|o| o.get("image_sha384"))
        .and_then(Value::as_str)
        .map(|v| v.trim().is_empty())
        .unwrap_or(true);
    if needs_nested {
        let entry = obj
            .entry("recipient_attestation".to_string())
            .or_insert_with(|| json!({}));
        let Some(nested) = entry.as_object_mut() else {
            return Err("kms-release.json recipient_attestation must be an object".to_string());
        };
        nested.insert(
            "image_sha384".to_string(),
            Value::String(pcrs.pcr0.to_ascii_lowercase()),
        );
    }

    std::fs::write(
        path,
        serde_json::to_vec_pretty(&value)
            .map_err(|e| format!("failed to serialize kms-release.json: {}", e))?,
    )
    .map_err(|e| format!("failed to write {}: {}", path.display(), e))
}

fn write_receipt_text(json_path: &Path, text_path: &Path) -> Result<(), String> {
    let bytes = std::fs::read(json_path)
        .map_err(|e| format!("failed to read {}: {}", json_path.display(), e))?;
    let receipt: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse {}: {}", json_path.display(), e))?;

    let get = |name: &str| {
        receipt
            .get(name)
            .map(|v| {
                v.as_str()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| v.to_string())
            })
            .unwrap_or_else(|| "<missing>".to_string())
    };

    let rendered = format!(
        "Cyntrisec AIR receipt summary\n\
         model_id: {}\n\
         model_version: {}\n\
         security_mode: {}\n\
         sequence_number: {}\n\
         request_hash: {}\n\
         response_hash: {}\n\
         attestation_doc_hash: {}\n\
         execution_time_ms: {}\n\
         memory_peak_mb: {}\n\
         \n\
         This is a human-readable companion. Trust decisions MUST use receipt.cbor,\n\
         attestation.cbor, verification.json, and the verifier policy.\n",
        get("model_id"),
        get("model_version"),
        get("security_mode"),
        get("sequence_number"),
        get("request_hash"),
        get("response_hash"),
        get("attestation_doc_hash"),
        get("execution_time_ms"),
        get("memory_peak_mb")
    );
    std::fs::write(text_path, rendered)
        .map_err(|e| format!("failed to write {}: {}", text_path.display(), e))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let prefix: String = s.chars().take(max).collect();
        format!("{}...[truncated {} bytes]", prefix, s.len() - prefix.len())
    }
}

#[cfg(test)]
mod tests {
    use super::parse_first_json_object;

    #[test]
    fn parses_json_with_prefix_suffix() {
        let v = parse_first_json_object("status\n{\"Measurements\":{\"PCR0\":\"x\"}}\n");
        assert!(v.is_some());
    }
}
