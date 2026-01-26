use ephemeral_ml_client::mock::MockSecureClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralML Client (Mock Mode)");
    
    // Create mock client
    let mut client = MockSecureClient::new();
    
    // Test attestation verification
    let mock_attestation = MockSecureClient::generate_mock_attestation();
    let attestation_bytes = serde_json::to_vec(&mock_attestation)?;
    
    match client.verify_enclave_attestation(&attestation_bytes) {
        Ok(valid) => println!("Attestation verification: {}", if valid { "VALID" } else { "INVALID" }),
        Err(e) => println!("Attestation verification failed: {}", e),
    }
    
    // Test secure channel establishment
    match client.establish_attested_channel("127.0.0.1:8080") {
        Ok(channel) => println!("Secure channel established to: {}", channel.endpoint),
        Err(e) => println!("Failed to establish secure channel: {}", e),
    }
    
    println!("Mock client demo completed");
    Ok(())
}