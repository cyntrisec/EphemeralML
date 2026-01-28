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
    
    // Benchmark 2: Model Loading (100MB Dummy)
    let model_id = "large-bench-model";
    println!("\n[bench] Starting FULL load for: {}...", model_id);
    
    let manifest = ModelManifest {
        model_id: model_id.to_string(),
        version: "1.0.0".to_string(),
        model_hash: hex::decode("65ef6bc044c8fe2552592b762eae7baa4d8d6f4b1696ef2f3f6098db27f8f240").unwrap(), // Dummy for now, will update
        hash_algorithm: "sha256".to_string(),
        key_id: "test".to_string(),
        signature: vec![0u8; 64],
    };

    // Note: We use the fixed DEK from prepare_real_model.py
    let fixed_dek = hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap();
    
    let start = Instant::now();
    // Fetch
    let encrypted_artifact = loader.kms_client().proxy_client().fetch_model(model_id).await?;
    let fetch_done = start.elapsed();
    
    // Decrypt (using our mock decrypt with fixed key)
    let (nonce_bytes, ciphertext) = encrypted_artifact.split_at(12);
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::Aead};
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&fixed_dek));
    let plaintext = cipher.decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;
    
    let load_done = start.elapsed();
    println!("[bench] Model decrypted. Size: {} bytes", plaintext.len());
    println!("[bench] Fetch: {:?}, Decrypt: {:?}", fetch_done, load_done - fetch_done);

    // Benchmark 3: Inference Latency
    // We need config and tokenizer for a real BERT run. 
    // For the benchmark baseline, we just measure the raw time.
    
    println!("\n=== Benchmark Complete ===");
    Ok(())
}
