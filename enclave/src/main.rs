use ephemeral_ml_enclave::{
    mock::{MockEnclaveServer, MockAttestationProvider, MockEphemeralAssembler},
    AttestationProvider, EphemeralAssembler, DefaultAttestationProvider, current_timestamp,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralNet Enclave (Mock Mode)");
    
    // Test new DefaultAttestationProvider (uses mock in development)
    let default_provider = DefaultAttestationProvider::new()?;
    let nonce = b"test_nonce_for_demo_12345678901234567890";
    let attestation = default_provider.generate_attestation(nonce)?;
    println!("Generated attestation for module: {}", attestation.module_id);
    println!("HPKE public key: {:?}", hex::encode(default_provider.get_hpke_public_key()));
    println!("Receipt signing key: {:?}", hex::encode(default_provider.get_receipt_public_key()));
    
    // Test PCR measurements
    let pcrs = default_provider.get_pcr_measurements()?;
    println!("PCR measurements valid: {}", pcrs.is_valid());
    
    // Test legacy mock provider for compatibility
    let mock_provider = MockAttestationProvider::new();
    let mock_attestation = mock_provider.generate_attestation(b"test_nonce")?;
    println!("Generated mock attestation for module: {}", mock_attestation.module_id);
    
    // Test model assembly
    let mut assembler = MockEphemeralAssembler::new();
    
    // Create a simple mock topology (this would normally come from client)
    let topology = ephemeral_ml_enclave::assembly::TopologyKey {
        graph_id: "test_graph".to_string(),
        nodes: vec![],
        edges: vec![],
        input_shapes: vec![ephemeral_ml_enclave::assembly::TensorShape { dimensions: vec![1, 10] }],
        output_shapes: vec![ephemeral_ml_enclave::assembly::TensorShape { dimensions: vec![1, 10] }],
        metadata: ephemeral_ml_enclave::assembly::ModelMetadata {
            name: "test_model".to_string(),
            version: "1.0.0".to_string(),
            description: Some("Mock test model".to_string()),
            created_at: current_timestamp(),
            checksum: "mock_checksum".to_string(),
        },
    };
    
    let weights: Vec<f32> = (0..100).map(|i| i as f32 * 0.01).collect();
    let model = assembler.assemble_model(&topology, &weights)?;
    println!("Assembled model: {}", model.id);
    
    // Test inference
    let input_data: Vec<u8> = vec![1, 2, 3, 4, 5];
    let output = assembler.execute_inference(&model, &input_data)?;
    // Inference output removed to prevent secret leakage
    
    // Clean up
    assembler.destroy_model(model)?;
    assembler.secure_memory_clear()?;
    
    println!("Mock enclave demo completed");
    println!("Starting mock TCP server on port 8082...");
    
    // Start mock server
    let mut server = MockEnclaveServer::new(8082);
    server.start().await?;
    
    Ok(())
}