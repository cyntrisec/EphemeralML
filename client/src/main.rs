#[cfg(feature = "mock")]
use ephemeral_ml_client::mock::MockSecureClient;
use ephemeral_ml_client::secure_client::SecureClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
                match client.execute_inference("stage-0", input_tensor).await {
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
