use crate::{EnclaveError, EphemeralError, Result};
use candle_core::{Device, Tensor};
use candle_transformers::models::bert::{BertModel, Config, DTYPE};
use candle_transformers::models::quantized_llama::ModelWeights as QuantizedLlama;
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, RwLock};
use tokenizers::Tokenizer;

/// Inference engine powered by Candle for production use
#[derive(Clone)]
pub struct CandleInferenceEngine {
    device: Device,
    models: Arc<RwLock<HashMap<String, Arc<LoadedModel>>>>,
}

enum LoadedModel {
    Bert(LoadedBertModel),
    QuantizedLlama(LoadedQuantizedLlamaModel),
}

struct LoadedBertModel {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
}

struct LoadedQuantizedLlamaModel {
    model: QuantizedLlama,
    tokenizer: Tokenizer,
    device: Device,
}

impl CandleInferenceEngine {
    /// Create a new CandleInferenceEngine, detecting CUDA availability
    pub fn new() -> Result<Self> {
        let device = if cfg!(feature = "cuda") && candle_core::utils::cuda_is_available() {
            Device::new_cuda(0).map_err(|e| EnclaveError::CandleError(e.to_string()))?
        } else {
            Device::Cpu
        };
        Ok(Self {
            device,
            models: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Load and register a BERT model from configuration, weights, and tokenizer data
    pub fn register_model(
        &self,
        model_id: &str,
        config_json: &[u8],
        weights_safetensors: &[u8],
        tokenizer_json: &[u8],
    ) -> Result<()> {
        let config: Config = serde_json::from_slice(config_json).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
        })?;

        let (vb, _naming) = ephemeral_ml_common::inference::bert_var_builder_from_safetensors(
            weights_safetensors.to_vec(),
            DTYPE,
            &self.device,
        )
        .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let model =
            BertModel::load(vb, &config).map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let tokenizer = Tokenizer::from_bytes(tokenizer_json)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let loaded_model = Arc::new(LoadedModel::Bert(LoadedBertModel {
            model,
            tokenizer,
            device: self.device.clone(),
        }));
        let mut models = self.models.write().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Internal("Lock poisoned".to_string()))
        })?;
        models.insert(model_id.to_string(), loaded_model);
        Ok(())
    }

    /// Load and register a quantized GGUF model
    pub fn register_model_gguf(
        &self,
        model_id: &str,
        gguf_data: &[u8],
        tokenizer_json: &[u8],
    ) -> Result<()> {
        let mut reader = Cursor::new(gguf_data);
        let content = candle_core::quantized::gguf_file::Content::read(&mut reader)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let model = QuantizedLlama::from_gguf(content, &mut reader, &self.device)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let tokenizer = Tokenizer::from_bytes(tokenizer_json)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let loaded_model = Arc::new(LoadedModel::QuantizedLlama(LoadedQuantizedLlamaModel {
            model,
            tokenizer,
            device: self.device.clone(),
        }));

        let mut models = self.models.write().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Internal("Lock poisoned".to_string()))
        })?;
        models.insert(model_id.to_string(), loaded_model);
        Ok(())
    }

    /// Execute inference by model ID
    pub fn execute_by_id(&self, model_id: &str, input: &[u8]) -> Result<Vec<f32>> {
        let models = self.models.read().map_err(|_| {
            EnclaveError::Enclave(EphemeralError::Internal("Lock poisoned".to_string()))
        })?;
        let loaded = models.get(model_id).ok_or_else(|| {
            EnclaveError::Enclave(EphemeralError::InferenceError(format!(
                "Model {} not loaded in engine",
                model_id
            )))
        })?;

        match loaded.as_ref() {
            LoadedModel::Bert(loaded) => self.execute_bert(loaded, input),
            LoadedModel::QuantizedLlama(loaded) => self.execute_quantized_llama(loaded, input),
        }
    }

    /// Helper to get device info
    pub fn device(&self) -> &Device {
        &self.device
    }

    fn execute_bert(&self, loaded: &LoadedBertModel, input: &[u8]) -> Result<Vec<f32>> {
        let text = std::str::from_utf8(input).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::InvalidInput(format!(
                "Invalid UTF-8 input: {}",
                e
            )))
        })?;

        let tokens = loaded
            .tokenizer
            .encode(text, true)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let token_ids = tokens.get_ids();
        let attention_mask = tokens.get_attention_mask();

        let input_ids = Tensor::new(token_ids, &loaded.device)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            .unsqueeze(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let token_type_ids = Tensor::new(tokens.get_type_ids(), &loaded.device)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            .unsqueeze(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let embeddings = loaded
            .model
            .forward(&input_ids, &token_type_ids, None)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            .squeeze(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        // Mask-aware mean pooling
        let mask = Tensor::new(attention_mask, &loaded.device)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            .to_dtype(embeddings.dtype())
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let mask_expanded = mask
            .unsqueeze(1)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            .broadcast_as(embeddings.shape())
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let masked_embeddings = embeddings
            .mul(&mask_expanded)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let sum_embeddings = masked_embeddings
            .sum(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let sum_mask = mask
            .sum(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            .to_dtype(embeddings.dtype())
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let mean_embeddings = sum_embeddings
            .broadcast_div(&sum_mask)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let res = mean_embeddings
            .to_vec1::<f32>()
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        Ok(res)
    }

    fn execute_quantized_llama(
        &self,
        loaded: &LoadedQuantizedLlamaModel,
        input: &[u8],
    ) -> Result<Vec<f32>> {
        let text = std::str::from_utf8(input).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::InvalidInput(format!(
                "Invalid UTF-8 input: {}",
                e
            )))
        })?;

        let tokens = loaded
            .tokenizer
            .encode(text, true)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let token_ids = tokens.get_ids();
        let input_ids = Tensor::new(token_ids, &loaded.device)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            .unsqueeze(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let mut model = loaded.model.clone();
        let logits = model
            .forward(&input_ids, 0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let logits = logits
            .squeeze(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;
        let last_idx = logits
            .dim(0)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?
            - 1;
        let last_logits = logits
            .get(last_idx)
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        let res = last_logits
            .to_vec1::<f32>()
            .map_err(|e| EnclaveError::CandleError(e.to_string()))?;

        Ok(res)
    }
}
