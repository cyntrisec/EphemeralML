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
        println!("Use SecureEnclaveClient to connect to a GCP enclave.");

        let mut client =
            ephemeral_ml_client::SecureEnclaveClient::new("gcp-client".to_string());

        let addr = std::env::var("EPHEMERALML_ENCLAVE_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:9001".to_string());

        match client.establish_channel(&addr).await {
            Ok(()) => println!("Secure channel established with GCP enclave"),
            Err(e) => println!("Failed to establish channel: {}", e),
        }
    }

    #[cfg(not(any(feature = "mock", feature = "gcp")))]
    {
        println!("EphemeralML Client (Production Mode)");
        println!("Use SecureEnclaveClient::with_policy() for production.");
    }

    Ok(())
}
