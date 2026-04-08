#[cfg(feature = "mock")]
use ephemeral_ml_client::mock::MockSecureClient;
#[cfg(any(feature = "mock", feature = "gcp"))]
use ephemeral_ml_client::secure_client::SecureClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,confidential_ml_transport=warn".into()),
        )
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();

    #[cfg(feature = "mock")]
    {
        println!("EphemeralML Client (Mock Mode)");

        // Create mock client
        let mut client = MockSecureClient::new();

        // Test attestation verification
        let mock_attestation = MockSecureClient::generate_mock_attestation();
        let attestation_bytes = serde_json::to_vec(&mock_attestation)?;

        match client.verify_enclave_attestation(&attestation_bytes) {
            Ok(valid) => println!(
                "Attestation verification: {}",
                if valid { "VALID" } else { "INVALID" }
            ),
            Err(e) => println!("Attestation verification failed: {}", e),
        }

        // Test secure channel establishment
        match client.establish_channel("127.0.0.1:8080").await {
            Ok(()) => println!("Secure channel established"),
            Err(e) => println!("Failed to establish secure channel: {}", e),
        }

        println!("Mock client demo completed");
    }

    #[cfg(feature = "gcp")]
    {
        println!("EphemeralML Client (GCP Mode)");

        let mut client = ephemeral_ml_client::SecureEnclaveClient::new("gcp-client".to_string());

        let addr = std::env::var("EPHEMERALML_ENCLAVE_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9000".to_string());

        let receipt_path = std::env::var("EPHEMERALML_RECEIPT_PATH")
            .unwrap_or_else(|_| "/tmp/ephemeralml-receipt.json".to_string());
        let model_id = std::env::var("EPHEMERALML_GCP_VERIFY_MODEL_ID")
            .unwrap_or_else(|_| "stage-0".to_string());

        match client.establish_channel(&addr).await {
            Ok(()) => {
                println!("Secure channel established with GCP enclave");

                // Save the server's receipt signing public key for offline verification
                if let Some(pk) = client.server_receipt_signing_key() {
                    let pk_path = format!("{}.pubkey", receipt_path);
                    std::fs::write(&pk_path, hex::encode(pk)).ok();
                    println!("Receipt public key saved to {}", pk_path);
                }

                // Run inference with dummy input matching MiniLM-L6-v2 (384-dim)
                let input_tensor: Vec<f32> = vec![0.1; 384];
                println!("Using model_id={}", model_id);
                match client.execute_inference(&model_id, input_tensor).await {
                    Ok(result) => {
                        println!(
                            "Inference succeeded: {} floats returned",
                            result.output_tensor.len()
                        );
                        println!(
                            "First 5 values: {:?}",
                            &result.output_tensor[..result.output_tensor.len().min(5)]
                        );

                        // Save receipt to disk
                        match serde_json::to_string_pretty(&result.receipt) {
                            Ok(json) => {
                                if let Err(e) = std::fs::write(&receipt_path, &json) {
                                    eprintln!("Warning: failed to save receipt: {}", e);
                                } else {
                                    println!("Receipt saved to {}", receipt_path);
                                    println!("Receipt ID: {}", result.receipt.receipt_id);
                                }
                            }
                            Err(e) => eprintln!("Warning: failed to serialize receipt: {}", e),
                        }

                        // Save AIR v1 receipt (CBOR) if present
                        if let Some(ref air_b64) = result.air_v1_receipt_b64 {
                            use base64::Engine as _;
                            match base64::engine::general_purpose::STANDARD.decode(air_b64) {
                                Ok(cbor_bytes) => {
                                    let cbor_path = "/tmp/ephemeralml-receipt.cbor";
                                    if let Err(e) = std::fs::write(cbor_path, &cbor_bytes) {
                                        eprintln!("Warning: failed to save AIR v1 receipt: {}", e);
                                    } else {
                                        println!("AIR v1 receipt saved to {}", cbor_path);
                                    }
                                }
                                Err(e) => {
                                    eprintln!(
                                        "Warning: failed to decode AIR v1 receipt base64: {}",
                                        e
                                    );
                                }
                            }
                        }

                        // Save sidecar evidence files alongside receipt
                        if let Some(ref att_b64) = result.boot_attestation_b64 {
                            use base64::Engine as _;
                            if let Ok(att_bytes) =
                                base64::engine::general_purpose::STANDARD.decode(att_b64)
                            {
                                let att_path = "/tmp/ephemeralml-attestation.bin";
                                if let Err(e) = std::fs::write(att_path, &att_bytes) {
                                    eprintln!("Warning: failed to save attestation: {}", e);
                                } else {
                                    println!("Attestation saved to {}", att_path);
                                }
                            }
                        }
                        if let Some(ref manifest_json) = result.model_manifest_json {
                            let manifest_path = "/tmp/ephemeralml-manifest.json";
                            if let Err(e) = std::fs::write(manifest_path, manifest_json) {
                                eprintln!("Warning: failed to save manifest: {}", e);
                            } else {
                                println!("Manifest saved to {}", manifest_path);
                            }
                        }
                        if let Some(ref scheme) = result.air_v1_model_hash_scheme {
                            println!("AIR v1 model_hash_scheme: {}", scheme);
                        }
                        if let Some(ref coverage) = result.model_identity_coverage {
                            println!("Model identity coverage:");
                            for (artifact, covered) in coverage {
                                println!(
                                    "  {}: {}",
                                    artifact,
                                    if *covered { "bound" } else { "not bound" }
                                );
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Inference failed: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to establish channel: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(any(feature = "mock", feature = "gcp")))]
    {
        println!("EphemeralML Client (Production Mode)");
        println!("Use SecureEnclaveClient::with_policy() for production.");
    }

    Ok(())
}
