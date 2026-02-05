//! Model registry for benchmark-supported embedding models.
//!
//! Provides metadata for models used in benchmarking: parameter counts,
//! embedding dimensions, file naming conventions, and HuggingFace repo paths.

use std::collections::HashMap;

/// Metadata for a benchmark-supported model.
#[derive(Debug, Clone)]
pub struct ModelInfo {
    /// Display name (e.g., "MiniLM-L6-v2")
    pub display_name: &'static str,
    /// HuggingFace repository path
    pub hf_repo: &'static str,
    /// Total parameter count
    pub params: u64,
    /// Output embedding dimension
    pub embedding_dim: usize,
    /// Hidden layer size
    pub hidden_size: usize,
    /// Number of transformer layers
    pub num_layers: usize,
    /// Number of attention heads
    pub num_heads: usize,
    /// Approximate model file size in bytes (SafeTensors)
    pub model_size_bytes: u64,
}

impl ModelInfo {
    /// Returns the S3/local artifact key for encrypted weights
    pub fn weights_key(&self, model_id: &str) -> String {
        format!("{}-weights", model_id)
    }

    /// Returns the S3/local artifact key for config
    pub fn config_key(&self, model_id: &str) -> String {
        format!("{}-config", model_id)
    }

    /// Returns the S3/local artifact key for tokenizer
    pub fn tokenizer_key(&self, model_id: &str) -> String {
        format!("{}-tokenizer", model_id)
    }

    /// Returns the local encrypted weights filename
    pub fn weights_filename(&self, model_id: &str) -> String {
        format!("{}-weights.enc", model_id)
    }
}

/// Get model info by ID. Returns None if model is not in the registry.
pub fn get_model_info(model_id: &str) -> Option<&'static ModelInfo> {
    MODEL_REGISTRY.get(model_id).copied()
}

/// List all registered model IDs.
pub fn list_models() -> Vec<&'static str> {
    MODEL_REGISTRY.keys().copied().collect()
}

/// Get model info, falling back to MiniLM-L6 defaults if not found.
pub fn get_model_info_or_default(model_id: &str) -> &'static ModelInfo {
    get_model_info(model_id).unwrap_or(&MINILM_L6)
}

// Model definitions
static MINILM_L6: ModelInfo = ModelInfo {
    display_name: "MiniLM-L6-v2",
    hf_repo: "sentence-transformers/all-MiniLM-L6-v2",
    params: 22_700_000,
    embedding_dim: 384,
    hidden_size: 384,
    num_layers: 6,
    num_heads: 12,
    model_size_bytes: 90_900_000, // ~87 MB
};

static MINILM_L12: ModelInfo = ModelInfo {
    display_name: "MiniLM-L12-v2",
    hf_repo: "sentence-transformers/all-MiniLM-L12-v2",
    params: 33_400_000,
    embedding_dim: 384,
    hidden_size: 384,
    num_layers: 12,
    num_heads: 12,
    model_size_bytes: 134_000_000, // ~128 MB
};

static BERT_BASE: ModelInfo = ModelInfo {
    display_name: "BERT-base-uncased",
    hf_repo: "google-bert/bert-base-uncased",
    params: 110_000_000,
    embedding_dim: 768,
    hidden_size: 768,
    num_layers: 12,
    num_heads: 12,
    model_size_bytes: 440_000_000, // ~420 MB
};

lazy_static::lazy_static! {
    static ref MODEL_REGISTRY: HashMap<&'static str, &'static ModelInfo> = {
        let mut m = HashMap::new();
        m.insert("minilm-l6", &MINILM_L6);
        m.insert("minilm-l12", &MINILM_L12);
        m.insert("bert-base", &BERT_BASE);
        // Legacy alias for backwards compatibility
        m.insert("mini-lm-v2", &MINILM_L6);
        m.insert("MiniLM-L6-v2", &MINILM_L6);
        m
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_model_info() {
        let info = get_model_info("minilm-l6").unwrap();
        assert_eq!(info.display_name, "MiniLM-L6-v2");
        assert_eq!(info.params, 22_700_000);
        assert_eq!(info.embedding_dim, 384);
    }

    #[test]
    fn test_legacy_alias() {
        let info1 = get_model_info("minilm-l6").unwrap();
        let info2 = get_model_info("mini-lm-v2").unwrap();
        assert_eq!(info1.display_name, info2.display_name);
    }

    #[test]
    fn test_bert_base() {
        let info = get_model_info("bert-base").unwrap();
        assert_eq!(info.params, 110_000_000);
        assert_eq!(info.embedding_dim, 768);
        assert_eq!(info.num_layers, 12);
    }

    #[test]
    fn test_weights_filename() {
        let info = get_model_info("minilm-l6").unwrap();
        assert_eq!(info.weights_filename("minilm-l6"), "minilm-l6-weights.enc");
    }

    #[test]
    fn test_unknown_model() {
        assert!(get_model_info("unknown-model").is_none());
    }

    #[test]
    fn test_list_models() {
        let models = list_models();
        assert!(models.contains(&"minilm-l6"));
        assert!(models.contains(&"bert-base"));
    }
}
