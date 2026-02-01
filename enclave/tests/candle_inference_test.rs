use ephemeral_ml_enclave::assembly::{CandleModel, ModelMetadata, TopologyKey};
use ephemeral_ml_enclave::candle_engine::CandleInferenceEngine;
use ephemeral_ml_enclave::inference::InferenceEngine;
use std::fs;
use std::path::Path;

#[test]
fn test_candle_inference_minilm() {
    // Skip if assets are missing (e.g. in CI without network)
    let config_path = "../test_assets/minilm/config.json";
    let weights_path = "../test_assets/minilm/model.safetensors";
    let tokenizer_path = "../test_assets/minilm/tokenizer.json";

    if !Path::new(config_path).exists()
        || !Path::new(weights_path).exists()
        || !Path::new(tokenizer_path).exists()
    {
        println!("Skipping test: model assets not found");
        return;
    }

    let engine = CandleInferenceEngine::new().expect("Failed to create engine");

    let config_json = fs::read(config_path).expect("Failed to read config");
    let weights_safetensors = fs::read(weights_path).expect("Failed to read weights");
    let tokenizer_json = fs::read(tokenizer_path).expect("Failed to read tokenizer");

    let model_id = "minilm-l6-v2";
    engine
        .register_model(
            model_id,
            &config_json,
            &weights_safetensors,
            &tokenizer_json,
        )
        .expect("Failed to register model");

    let model_info = CandleModel {
        id: model_id.to_string(),
        topology: TopologyKey {
            graph_id: "minilm".to_string(),
            nodes: vec![],
            edges: vec![],
            input_shapes: vec![],
            output_shapes: vec![],
            metadata: ModelMetadata {
                name: "MiniLM-L6-v2".to_string(),
                version: "v2".to_string(),
                description: None,
                created_at: 0,
                checksum: "none".to_string(),
            },
        },
        weights: vec![], // Not used by CandleInferenceEngine which uses its internal registry
    };

    let input_text = "This is a test sentence for embedding generation.";
    let input_bytes = input_text.as_bytes();

    let output = engine
        .execute(&model_info, input_bytes)
        .expect("Inference failed");

    println!("Embedding size: {}", output.len());
    assert_eq!(output.len(), 384); // MiniLM-L6-v2 has 384-dim embeddings

    // Check for non-zero values to ensure it's not returning all zeros
    let sum: f32 = output.iter().map(|x| x.abs()).sum();
    assert!(sum > 0.0);
    println!("Embedding sum of absolute values: {}", sum);
}
