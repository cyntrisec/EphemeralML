#[cfg(not(feature = "production"))]
use ephemeral_ml_enclave::{
    mock::{MockEnclaveServer, MockAttestationProvider, MockEphemeralAssembler},
    AttestationProvider, EphemeralAssembler, DefaultAttestationProvider, current_timestamp,
};
#[cfg(feature = "production")]
use ephemeral_ml_enclave::{DefaultAttestationProvider, CandleInferenceEngine};

#[cfg(feature = "production")]
use ephemeral_ml_enclave::server::ProductionEnclaveServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("EphemeralNet Enclave v1.0.1-debug");
    #[cfg(not(feature = "production"))]
    {
        println!("EphemeralNet Enclave (Mock Mode)");
        
        // Test new DefaultAttestationProvider (uses mock in development)
        let default_provider = DefaultAttestationProvider::new()?;
        let nonce = b"test_nonce_for_demo_12345678901234567890";
        let attestation = default_provider.generate_attestation(nonce)?;
        println!("Generated attestation for module: {}", attestation.module_id);
        println!("HPKE public key: {:?}", hex::encode(default_provider.get_hpke_public_key()));
        println!("Receipt signing key: {:?}", hex::encode(default_provider.get_receipt_public_key()));
        
        // Test model assembly
        let mut assembler = MockEphemeralAssembler::new();
        
        let topology = ephemeral_ml_enclave::assembly::TopologyKey {
            graph_id: "test_graph".to_string(),
            nodes: vec![],
            edges: vec![],
            input_shapes: vec![ephemeral_ml_enclave::assembly::TensorShape { dimensions: vec![1, 10] }],
            output_shapes: vec![ephemeral_ml_enclave::assembly::TensorShape { dimensions: vec![1, 10] }],
            metadata: ephemeral_ml_common::ModelMetadata {
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
        let _output = assembler.execute_inference(&model, &input_data)?;
        
        println!("Starting mock TCP server on port 8082...");
        let server = MockEnclaveServer::new(8082);
        server.start().await?;
    }

    #[cfg(feature = "production")]
    {
        println!("EphemeralNet Enclave (Production Mode)");
        
        let attestation_provider = DefaultAttestationProvider::new()?;
        let inference_engine = CandleInferenceEngine::new()?;

        // TEST MODE: If an environment variable is set, try to load a model and exit
        if std::env::var("TEST_MODEL_LOAD").is_ok() {
            println!("[test] Starting model load test...");
            use ephemeral_ml_enclave::kms_client::KmsClient;
            use ephemeral_ml_enclave::model_loader::ModelLoader;
            
            let kms_client = KmsClient::new(attestation_provider.clone());
            // Use a dummy trusted key for this test
            let _loader = ModelLoader::new(kms_client, [0u8; 32]);
            
            // This will fail unless we provide valid data, but we can catch the error
            // to see how far it gets (e.g., if it can reach the KMS proxy).
            println!("[test] ModelLoader initialized.");
        }

        // Start production VSock server on port 5000 (inference/handshake)
        // Port 8082 is used for the KMS proxy on the host, not for incoming enclave traffic.
        let server = ProductionEnclaveServer::new(5000, attestation_provider, inference_engine);
        
        println!("Starting Production VSock Server on port 5000...");
        server.start().await?;
    }
    
    Ok(())
}
