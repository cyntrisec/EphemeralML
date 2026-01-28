use ephemeral_ml_enclave::{
    DefaultAttestationProvider, CandleInferenceEngine,
    kms_client::KmsClient,
    model_loader::ModelLoader,
};
use ephemeral_ml_common::model_manifest::ModelManifest;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== EphemeralML Phase 8: Performance Benchmark ===");
    
    let provider = DefaultAttestationProvider::new()?;
    let engine = CandleInferenceEngine::new()?;
    let kms_client = KmsClient::new(provider.clone());
    let loader = ModelLoader::new(kms_client, [0u8; 32]);
    
    // Benchmark 1: S3 Connectivity & Speed (Encrypted artifact)
    let model_id = "test-model-001";
    println!("[bench] Fetching artifact: {}...", model_id);
    
    let start = Instant::now();
    let proxy = loader.kms_client().proxy_client();
    let bytes = proxy.fetch_model(model_id).await?;
    let duration = start.elapsed();
    
    println!("[bench] SUCCESS: Fetched {} bytes in {:?}", bytes.len(), duration);
    let speed = (bytes.len() as f64 / 1024.0 / 1024.0) / duration.as_secs_f64();
    println!("[bench] Download speed: {:.2} MB/s", speed);
    
    // Benchmark 3: Real Model Load (MiniLM)
    println!("\n[bench] Starting Real Model Benchmark: mini-lm-v2...");
    let proxy = loader.kms_client().proxy_client();
    
    // 1. Fetch Config
    let config_bytes = proxy.fetch_model("mini-lm-v2-config").await?;
    println!("[bench] Config loaded ({} bytes)", config_bytes.len());
    
    // 2. Fetch Tokenizer
    let tokenizer_bytes = proxy.fetch_model("mini-lm-v2-tokenizer").await?;
    println!("[bench] Tokenizer loaded ({} bytes)", tokenizer_bytes.len());
    
    // 3. Fetch & Decrypt Weights
    let start = Instant::now();
    let encrypted_weights = proxy.fetch_model("mini-lm-v2-weights").await?;
    let fetch_done = start.elapsed();
    
    let (nonce_bytes, ciphertext) = encrypted_weights.split_at(12);
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::Aead};
    let fixed_dek = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&fixed_dek));
    let weights_plaintext = cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    let decrypt_done = start.elapsed();
    
    println!("[bench] Weights ready. Fetch: {:?}, Decrypt: {:?}", fetch_done, decrypt_done - fetch_done);
    
    // 4. Register in Inference Engine
    let engine_start = Instant::now();
    engine.register_model(
        "mini-lm-v2",
        &config_bytes,
        &weights_plaintext,
        &tokenizer_bytes
    )?;
    println!("[bench] Engine registration complete in {:?}", engine_start.elapsed());
    
    // 5. Run Inference
    let input_text = "What is the capital of France?";
    println!("[bench] Running inference for: \"{}\"", input_text);
    
    let model_info = ephemeral_ml_enclave::assembly::CandleModel {
        id: "mini-lm-v2".to_string(),
        model_type: "bert".to_string(),
    };
    
    let infer_start = Instant::now();
    use ephemeral_ml_enclave::inference::InferenceEngine as _;
    let output = engine.execute(&model_info, input_text.as_bytes())?;
    let infer_duration = infer_start.elapsed();
    
    println!("[bench] SUCCESS: Inference completed in {:?}", infer_duration);
    println!("[bench] Output vector size: {}", output.len());
    println!("[bench] First 5 values: {:?}", &output[..5.min(output.len())]);

    println!("\n=== Benchmark Complete ===");
    Ok(())
}
