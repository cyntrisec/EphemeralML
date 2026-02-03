//! Shared inference helpers for benchmark binaries.
//!
//! This module provides a single `run_single_inference` function used by both
//! `benchmark_baseline` (host) and `vsock-pingpong` (enclave) to eliminate
//! duplicated inference + mean-pooling logic.
//!
//! Gated behind the `inference` feature so that `common/` does not pull in
//! heavy ML dependencies for non-benchmark consumers.

use candle_core::{DType, Device, Tensor};
use candle_transformers::models::bert::BertModel;
use tokenizers::Tokenizer;

/// Run a single BERT embedding inference with mean pooling.
///
/// Returns the mean-pooled embedding vector (e.g. 384 dimensions for MiniLM-L6-v2).
pub fn run_single_inference(
    model: &BertModel,
    tokenizer: &Tokenizer,
    text: &str,
    device: &Device,
) -> Vec<f32> {
    let encoding = tokenizer.encode(text, true).expect("tokenization failed");
    let input_ids = encoding.get_ids();
    let token_type_ids = encoding.get_type_ids();
    let attention_mask: Vec<u32> = encoding.get_attention_mask().to_vec();

    let input_ids_t = Tensor::new(input_ids, device)
        .unwrap()
        .unsqueeze(0)
        .unwrap();
    let token_type_ids_t = Tensor::new(token_type_ids, device)
        .unwrap()
        .unsqueeze(0)
        .unwrap();

    let output = model
        .forward(&input_ids_t, &token_type_ids_t, None)
        .expect("inference failed");

    // Mean pooling over sequence dimension
    let (_batch, _seq_len, _hidden) = output.dims3().unwrap();
    let mask = Tensor::new(&attention_mask[..], device)
        .unwrap()
        .unsqueeze(0)
        .unwrap()
        .unsqueeze(2)
        .unwrap()
        .to_dtype(DType::F32)
        .unwrap();
    let masked = output.broadcast_mul(&mask).unwrap();
    let summed = masked.sum(1).unwrap();
    let count = mask.sum(1).unwrap();
    let mean_pooled = summed.broadcast_div(&count).unwrap();

    mean_pooled.squeeze(0).unwrap().to_vec1::<f32>().unwrap()
}
