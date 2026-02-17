use ephemeral_ml_enclave::candle_engine::CandleInferenceEngine;
use std::path::Path;

#[test]
fn test_execute_by_id_generate_rejects_bert() {
    // Load a real BERT model so execute_by_id_generate can dispatch
    let config_path = "../test_assets/minilm/config.json";
    let weights_path = "../test_assets/minilm/model.safetensors";
    let tokenizer_path = "../test_assets/minilm/tokenizer.json";

    if !Path::new(config_path).exists() || !Path::new(weights_path).exists() {
        println!("Skipping test: model assets not found (run scripts/download_model.sh)");
        return;
    }

    let engine = CandleInferenceEngine::new().expect("Failed to create engine");
    let config = std::fs::read(config_path).unwrap();
    let weights = std::fs::read(weights_path).unwrap();
    let tokenizer = std::fs::read(tokenizer_path).unwrap();
    engine
        .register_model("bert-model", &config, &weights, &tokenizer)
        .unwrap();

    let result = engine.execute_by_id_generate("bert-model", b"hello", 10, 0.7, 0.9);
    assert!(result.is_err(), "BERT should not support text generation");
    let err_msg = format!("{:?}", result.err().unwrap());
    assert!(
        err_msg.contains("not supported for BERT"),
        "Should mention BERT, got: {}",
        err_msg
    );
}

#[test]
fn test_execute_by_id_generate_unknown_model() {
    let engine = CandleInferenceEngine::new().expect("Failed to create engine");
    let result = engine.execute_by_id_generate("nonexistent", b"hello", 10, 0.7, 0.9);
    assert!(result.is_err(), "Unknown model should fail");
    let err_msg = format!("{:?}", result.err().unwrap());
    assert!(
        err_msg.contains("not loaded"),
        "Should mention model not loaded, got: {}",
        err_msg
    );
}

#[test]
fn test_register_gguf_api_plumbing() {
    let engine = CandleInferenceEngine::new().expect("Failed to create engine");

    // Minimal GGUF header to test that it at least tries to parse
    // Magic: GGUF (4 bytes)
    // Version: 2 (4 bytes, LE)
    // Tensor count: 0 (8 bytes)
    // Metadata count: 0 (8 bytes)
    let mut dummy_gguf = Vec::new();
    dummy_gguf.extend_from_slice(b"GGUF");
    dummy_gguf.extend_from_slice(&2u32.to_le_bytes());
    dummy_gguf.extend_from_slice(&0u64.to_le_bytes());
    dummy_gguf.extend_from_slice(&0u64.to_le_bytes());

    let dummy_tokenizer = b"{}";

    let result = engine.register_model_gguf("test-gguf", &dummy_gguf, dummy_tokenizer);

    // It will likely fail during ModelWeights::from_gguf because it expects specific tensors for Llama
    // but the point is to show the registration path exists.
    match result {
        Err(e) => println!(
            "Got expected error (data is incomplete for a real Llama model): {:?}",
            e
        ),
        Ok(_) => println!(
            "Successfully registered (unexpected for empty GGUF but possible if model is empty)"
        ),
    }
}

#[test]
fn test_invalid_gguf_header() {
    let engine = CandleInferenceEngine::new().expect("Failed to create engine");
    let corrupt_gguf = b"NOT_A_GGUF_FILE_FOR_SURE";
    let dummy_tokenizer = b"{}";

    let result = engine.register_model_gguf("corrupt-model", corrupt_gguf, dummy_tokenizer);
    assert!(result.is_err(), "Should fail with invalid header");
    let err_msg = format!("{:?}", result.err().unwrap());
    assert!(
        err_msg.contains("magic"),
        "Error should mention magic number mismatch: {}",
        err_msg
    );
}

#[test]
fn test_bert_compatibility() {
    let engine = CandleInferenceEngine::new().expect("Failed to create engine");

    // Minimal BERT config
    let config_json = br#"{
        "architectures": ["BertModel"],
        "attention_probs_dropout_prob": 0.1,
        "hidden_act": "gelu",
        "hidden_dropout_prob": 0.1,
        "hidden_size": 32,
        "initializer_range": 0.02,
        "intermediate_size": 64,
        "layer_norm_eps": 1e-12,
        "max_position_embeddings": 512,
        "model_type": "bert",
        "num_attention_heads": 4,
        "num_hidden_layers": 2,
        "pad_token_id": 0,
        "type_vocab_size": 2,
        "vocab_size": 100
    }"#;

    // We can't easily generate valid safetensors bytes here without external crates,
    // but we can test that the registration fails with "invalid safetensors" rather than something else,
    // or if we had a small valid one we'd use it.
    // For now, let's verify it still tries to use the Bert path.
    let weights = b"not-real-weights";
    let tokenizer = b"{}"; // Tokenizer::from_bytes({}) might fail but let's see

    let result = engine.register_model("bert-test", config_json, weights, tokenizer);
    assert!(result.is_err());
    let err_msg = format!("{:?}", result.err().unwrap());
    // Should be a Candle error related to safetensors or memory mapping
    assert!(
        err_msg.contains("CandleError") || err_msg.contains("safetensors"),
        "Expected candle/safetensors error, got: {}",
        err_msg
    );
}
