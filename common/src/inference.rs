//! Shared inference helpers for benchmark binaries.
//!
//! This module provides a single `run_single_inference` function used by both
//! `benchmark_baseline` (host) and `vsock-pingpong` (enclave) to eliminate
//! duplicated inference + mean-pooling logic.
//!
//! Gated behind the `inference` feature so that `common/` does not pull in
//! heavy ML dependencies for non-benchmark consumers.

use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::BertModel;
use tokenizers::Tokenizer;

#[derive(Debug, Clone, Copy)]
pub struct BertSafetensorsNaming {
    pub has_bert_prefix: bool,
    pub uses_layernorm_beta_gamma: bool,
}

/// Detect whether a safetensors payload uses the HuggingFace BERT naming convention:
/// - tensors are prefixed with `bert.` (e.g. `bert.embeddings.*`)
/// - LayerNorm parameters are named `beta/gamma` instead of `bias/weight`
///
/// Returns `(has_bert_prefix, uses_layernorm_beta_gamma)`.
pub fn detect_bert_safetensors_naming(weights: &[u8]) -> BertSafetensorsNaming {
    // Safetensors header: [u64 header_len (LE)] + [header JSON bytes] + [tensor data...]
    if weights.len() < 8 {
        return BertSafetensorsNaming {
            has_bert_prefix: false,
            uses_layernorm_beta_gamma: false,
        };
    }

    let header_size = match weights[..8].try_into() {
        Ok(b) => u64::from_le_bytes(b) as usize,
        Err(_) => 0,
    };
    // Avoid pathological allocations if input is malformed.
    if header_size == 0 || header_size > (64 * 1024 * 1024) || weights.len() < 8 + header_size {
        return BertSafetensorsNaming {
            has_bert_prefix: false,
            uses_layernorm_beta_gamma: false,
        };
    }

    let header_json = &weights[8..8 + header_size];
    let header: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(header_json).unwrap_or_default();

    let has_bert_prefix = header.keys().any(|k| k.starts_with("bert."));
    let uses_layernorm_beta_gamma = header
        .keys()
        .any(|k| k.contains("LayerNorm.beta") || k.contains("LayerNorm.gamma"));

    BertSafetensorsNaming {
        has_bert_prefix,
        uses_layernorm_beta_gamma,
    }
}

/// Build a Candle `VarBuilder` from in-memory safetensors, with automatic compatibility for
/// HuggingFace BERT checkpoints that:
/// - use a top-level `bert.` prefix
/// - use `LayerNorm.beta/gamma` (TensorFlow naming) instead of `LayerNorm.bias/weight`
pub fn bert_var_builder_from_safetensors(
    weights_safetensors: Vec<u8>,
    dtype: DType,
    device: &Device,
) -> candle_core::Result<(VarBuilder<'_>, BertSafetensorsNaming)> {
    let naming = detect_bert_safetensors_naming(&weights_safetensors);

    let mut vb = VarBuilder::from_buffered_safetensors(weights_safetensors, dtype, device)?;

    if naming.uses_layernorm_beta_gamma {
        // Candle's `layer_norm` requests `bias`/`weight`. TF-style checkpoints store these as
        // `beta`/`gamma`, so map requested names to the stored names.
        vb = vb.rename_f(|name| {
            name.replace(".LayerNorm.weight", ".LayerNorm.gamma")
                .replace(".LayerNorm.bias", ".LayerNorm.beta")
        });
    }

    if naming.has_bert_prefix {
        vb = vb.pp("bert");
    }

    Ok((vb, naming))
}

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
