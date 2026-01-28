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
            println!("[test] Starting REAL model load test from S3...");
            use ephemeral_ml_enclave::kms_client::KmsClient;
            use ephemeral_ml_enclave::model_loader::ModelLoader;
            use ephemeral_ml_common::model_manifest::ModelManifest;

            let kms_client = KmsClient::new(attestation_provider.clone());
            
            // Use dummy signing key just for this test
            // Note: We need to use the proxy_client from the loader or clone it
            let loader = ModelLoader::new(kms_client, [0u8; 32]);
            
            // This manifest matches the one in s3://ephemeral-ml-models-1769608207/test-model-001/
            let manifest = ModelManifest {
                model_id: "test-model-001".to_string(),
                version: "1.0.0".to_string(),
                model_hash: hex::decode("3b8e1224560b8fb840634d6fe3f67254c273f3416b7df750d02d45c42261cb7a").unwrap(),
                hash_algorithm: "sha256".to_string(),
                key_id: "test".to_string(),
                signature: vec![0u8; 64], // Placeholder - in real use we verify this
            };

            println!("[test] Requesting model weights from host proxy...");
            
            // Re-borrow proxy client from the provider/client logic
            let proxy = loader.kms_client().proxy_client();
            match proxy.fetch_model(&manifest.model_id).await {
                Ok(bytes) => {
                    println!("[test] SUCCESS: Fetched {} bytes from S3 via Host Proxy!", bytes.len());
                    println!("[test] Model hash verification starting...");
                    use sha2::{Sha256, Digest};
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    let hash = hasher.finalize();
                    if hash.as_slice() == manifest.model_hash.as_slice() {
                        println!("[test] SUCCESS: Model hash matches manifest!");
                    } else {
                        println!("[test] ERROR: Model hash mismatch!");
                    }
                },
                Err(e) => println!("[test] FAILED to fetch from S3: {:?}", e),
            }
        }
        
        // Start production VSock server on port 5000 (inference/handshake)
        // Port 8082 is used for the KMS proxy on the host, not for incoming enclave traffic.
        let server = ProductionEnclaveServer::new(5000, attestation_provider, inference_engine);
        
        println!("Starting Production VSock Server on port 5000...");
        server.start().await?;
    }
    
    Ok(())
}
