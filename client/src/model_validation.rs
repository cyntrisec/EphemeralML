use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Maximum model size for embedding models (500 MB)
const MAX_EMBEDDING_MODEL_SIZE: u64 = 500 * 1024 * 1024;

/// Maximum model size for small classifiers (1 GB)
const MAX_CLASSIFIER_MODEL_SIZE: u64 = 1024 * 1024 * 1024;

/// Allowed dtypes for inference
const ALLOWED_DTYPES: &[&str] = &["BF16", "F16", "F32"];

/// Model format validation errors
#[derive(Error, Debug)]
pub enum ModelValidationError {
    #[error("Unsupported format: expected {expected}, got {got}")]
    UnsupportedFormat { expected: String, got: String },

    #[error("Unsupported dtype for tensor '{tensor_name}': {dtype} (allowed: {allowed:?})")]
    UnsupportedDtype {
        tensor_name: String,
        dtype: String,
        allowed: Vec<String>,
    },

    #[error("Model too large: {size_bytes} bytes exceeds maximum {max_bytes} bytes")]
    ModelTooLarge { size_bytes: u64, max_bytes: u64 },

    #[error("Unsupported model type: {reason}")]
    UnsupportedModelType { reason: String },

    #[error("Invalid safetensors header: {reason}")]
    InvalidHeader { reason: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Detected model type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelType {
    /// Embedding models (MiniLM, sentence-transformers, etc.)
    EmbeddingModel,
    /// Small classifiers (DistilBERT, tiny-bert, etc.)
    SmallClassifier,
}

impl ModelType {
    /// Maximum allowed file size for this model type
    pub fn max_size_bytes(&self) -> u64 {
        match self {
            ModelType::EmbeddingModel => MAX_EMBEDDING_MODEL_SIZE,
            ModelType::SmallClassifier => MAX_CLASSIFIER_MODEL_SIZE,
        }
    }
}

/// Information about a single tensor in a safetensors file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorInfo {
    pub dtype: String,
    pub shape: Vec<u64>,
    pub data_offsets: (u64, u64),
}

/// Parsed safetensors header information
#[derive(Debug, Clone)]
pub struct SafetensorsInfo {
    /// Header size in bytes
    pub header_size: u64,
    /// Map of tensor name -> tensor info
    pub tensors: HashMap<String, TensorInfo>,
    /// Total file size (if known)
    pub file_size: Option<u64>,
    /// Metadata from __metadata__ key (if present)
    pub metadata: Option<HashMap<String, String>>,
}

/// Validated model information
#[derive(Debug, Clone)]
pub struct ModelInfo {
    /// Detected model type
    pub model_type: ModelType,
    /// Safetensors header info
    pub safetensors_info: SafetensorsInfo,
    /// File size in bytes
    pub file_size: u64,
    /// Warnings (e.g., F32 dtype suggestion)
    pub warnings: Vec<String>,
}

/// Validator for model files
#[derive(Debug, Default)]
pub struct ModelValidator;

impl ModelValidator {
    /// Create a new model validator
    pub fn new() -> Self {
        Self
    }

    /// Validate a model file at the given path
    pub fn validate_model(&self, path: &Path) -> Result<ModelInfo, ModelValidationError> {
        // Check file extension
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if ext != "safetensors" {
            return Err(ModelValidationError::UnsupportedFormat {
                expected: "safetensors".to_string(),
                got: ext.to_string(),
            });
        }

        // Read the file
        let data = std::fs::read(path)?;
        let file_size = data.len() as u64;

        // Parse and validate
        let mut info = self.validate_safetensors_format(&data)?;
        info.file_size = Some(file_size);

        let mut warnings = Vec::new();
        self.validate_dtype_with_warnings(&info, &mut warnings)?;
        let model_type = self.validate_model_type(&info)?;

        // Validate size limit
        let max_size = model_type.max_size_bytes();
        if file_size > max_size {
            return Err(ModelValidationError::ModelTooLarge {
                size_bytes: file_size,
                max_bytes: max_size,
            });
        }

        Ok(ModelInfo {
            model_type,
            safetensors_info: info,
            file_size,
            warnings,
        })
    }

    /// Parse and validate safetensors format from raw bytes
    pub fn validate_safetensors_format(
        &self,
        data: &[u8],
    ) -> Result<SafetensorsInfo, ModelValidationError> {
        if data.len() < 8 {
            return Err(ModelValidationError::InvalidHeader {
                reason: "File too small: must be at least 8 bytes for header size".to_string(),
            });
        }

        // First 8 bytes: header size as u64 LE
        let header_size = u64::from_le_bytes(data[..8].try_into().map_err(|_| {
            ModelValidationError::InvalidHeader {
                reason: "Failed to read header size".to_string(),
            }
        })?);

        // Sanity check header size
        if header_size == 0 {
            return Err(ModelValidationError::InvalidHeader {
                reason: "Header size is zero".to_string(),
            });
        }

        let total_header = 8 + header_size as usize;
        if data.len() < total_header {
            return Err(ModelValidationError::InvalidHeader {
                reason: format!(
                    "File too small: expected at least {} bytes for header, got {}",
                    total_header,
                    data.len()
                ),
            });
        }

        // Parse JSON header
        let header_json: serde_json::Value = serde_json::from_slice(&data[8..total_header])
            .map_err(|e| ModelValidationError::InvalidHeader {
                reason: format!("Invalid JSON header: {}", e),
            })?;

        let header_map =
            header_json
                .as_object()
                .ok_or_else(|| ModelValidationError::InvalidHeader {
                    reason: "Header is not a JSON object".to_string(),
                })?;

        let mut tensors = HashMap::new();
        let mut metadata = None;

        for (key, value) in header_map {
            // Skip __metadata__ key
            if key == "__metadata__" {
                if let Some(obj) = value.as_object() {
                    let mut meta = HashMap::new();
                    for (mk, mv) in obj {
                        if let Some(s) = mv.as_str() {
                            meta.insert(mk.clone(), s.to_string());
                        }
                    }
                    metadata = Some(meta);
                }
                continue;
            }

            let tensor_obj =
                value
                    .as_object()
                    .ok_or_else(|| ModelValidationError::InvalidHeader {
                        reason: format!("Tensor '{}' is not a JSON object", key),
                    })?;

            let dtype = tensor_obj
                .get("dtype")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ModelValidationError::InvalidHeader {
                    reason: format!("Tensor '{}' missing 'dtype' field", key),
                })?
                .to_string();

            let shape: Vec<u64> = tensor_obj
                .get("shape")
                .and_then(|v| v.as_array())
                .ok_or_else(|| ModelValidationError::InvalidHeader {
                    reason: format!("Tensor '{}' missing 'shape' field", key),
                })?
                .iter()
                .map(|v| v.as_u64().unwrap_or(0))
                .collect();

            let data_offsets = tensor_obj
                .get("data_offsets")
                .and_then(|v| v.as_array())
                .ok_or_else(|| ModelValidationError::InvalidHeader {
                    reason: format!("Tensor '{}' missing 'data_offsets' field", key),
                })?;

            if data_offsets.len() != 2 {
                return Err(ModelValidationError::InvalidHeader {
                    reason: format!("Tensor '{}' data_offsets must have exactly 2 elements", key),
                });
            }

            let offset_start = data_offsets[0].as_u64().unwrap_or(0);
            let offset_end = data_offsets[1].as_u64().unwrap_or(0);

            tensors.insert(
                key.clone(),
                TensorInfo {
                    dtype,
                    shape,
                    data_offsets: (offset_start, offset_end),
                },
            );
        }

        if tensors.is_empty() {
            return Err(ModelValidationError::InvalidHeader {
                reason: "No tensors found in header".to_string(),
            });
        }

        Ok(SafetensorsInfo {
            header_size,
            tensors,
            file_size: None,
            metadata,
        })
    }

    /// Validate that all tensor dtypes are allowed for inference
    pub fn validate_dtype(&self, info: &SafetensorsInfo) -> Result<(), ModelValidationError> {
        let mut warnings = Vec::new();
        self.validate_dtype_with_warnings(info, &mut warnings)
    }

    /// Validate dtypes and collect warnings (e.g., F32 suggestion)
    fn validate_dtype_with_warnings(
        &self,
        info: &SafetensorsInfo,
        warnings: &mut Vec<String>,
    ) -> Result<(), ModelValidationError> {
        for (name, tensor) in &info.tensors {
            if !ALLOWED_DTYPES.contains(&tensor.dtype.as_str()) {
                return Err(ModelValidationError::UnsupportedDtype {
                    tensor_name: name.clone(),
                    dtype: tensor.dtype.clone(),
                    allowed: ALLOWED_DTYPES.iter().map(|s| s.to_string()).collect(),
                });
            }
            if tensor.dtype == "F32" {
                warnings.push(format!(
                    "Tensor '{}' uses F32 dtype — consider BF16 for better inference efficiency",
                    name
                ));
            }
        }
        Ok(())
    }

    /// Detect the model type from tensor names in the safetensors header
    pub fn validate_model_type(
        &self,
        info: &SafetensorsInfo,
    ) -> Result<ModelType, ModelValidationError> {
        let tensor_names: Vec<&str> = info.tensors.keys().map(|s| s.as_str()).collect();

        let has_classifier = tensor_names.iter().any(|n| {
            n.contains("classifier") || n.contains("qa_outputs") || n.contains("pre_classifier")
        });

        let has_encoder = tensor_names
            .iter()
            .any(|n| n.contains("encoder.layer") || n.contains("encoder.layers"));

        let has_embeddings = tensor_names.iter().any(|n| n.contains("embeddings"));

        let has_pooler = tensor_names
            .iter()
            .any(|n| n.contains("pooler") || n.contains("pooling"));

        // Classifier detection: has classifier head
        if has_classifier && (has_encoder || has_embeddings) {
            return Ok(ModelType::SmallClassifier);
        }

        // Embedding model detection: has encoder + embeddings but no classifier
        if has_encoder && has_embeddings && !has_classifier {
            return Ok(ModelType::EmbeddingModel);
        }

        // Embedding model with pooler
        if has_embeddings && has_pooler && !has_classifier {
            return Ok(ModelType::EmbeddingModel);
        }

        // If we have encoder layers only, assume embedding model
        if has_encoder {
            return Ok(ModelType::EmbeddingModel);
        }

        Err(ModelValidationError::UnsupportedModelType {
            reason: format!(
                "Could not determine model type from tensor names. \
                 Expected embedding model (encoder.layer + embeddings) or \
                 small classifier (classifier head). Found tensor names: {:?}",
                tensor_names
            ),
        })
    }
}

/// Helper: build minimal safetensors bytes from a header map (for testing)
pub fn build_safetensors_bytes(header: &serde_json::Value) -> Vec<u8> {
    let header_bytes = serde_json::to_vec(header).expect("Failed to serialize header");
    let header_size = header_bytes.len() as u64;
    let mut result = Vec::new();
    result.extend_from_slice(&header_size.to_le_bytes());
    result.extend_from_slice(&header_bytes);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Helper to create a minimal safetensors header with given tensors
    fn make_header(tensors: Vec<(&str, &str, Vec<u64>)>) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        let mut offset = 0u64;
        for (name, dtype, shape) in tensors {
            let num_elements: u64 = shape.iter().product();
            let dtype_size: u64 = match dtype {
                "BF16" | "F16" => 2,
                "F32" => 4,
                "F64" => 8,
                "I32" => 4,
                _ => 1,
            };
            let size = num_elements * dtype_size;
            map.insert(
                name.to_string(),
                json!({
                    "dtype": dtype,
                    "shape": shape,
                    "data_offsets": [offset, offset + size]
                }),
            );
            offset += size;
        }
        serde_json::Value::Object(map)
    }

    fn make_bytes(tensors: Vec<(&str, &str, Vec<u64>)>) -> Vec<u8> {
        build_safetensors_bytes(&make_header(tensors))
    }

    #[test]
    fn test_valid_safetensors_header_parsing() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![
            ("encoder.layer.0.weight", "BF16", vec![384, 384]),
            (
                "embeddings.word_embeddings.weight",
                "BF16",
                vec![30522, 384],
            ),
        ]);

        let info = validator.validate_safetensors_format(&data).unwrap();
        assert_eq!(info.tensors.len(), 2);
        assert!(info.tensors.contains_key("encoder.layer.0.weight"));
        assert_eq!(info.tensors["encoder.layer.0.weight"].dtype, "BF16");
        assert_eq!(info.tensors["encoder.layer.0.weight"].shape, vec![384, 384]);
    }

    #[test]
    fn test_dtype_bf16_ok() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![("weight", "BF16", vec![10, 10])]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        assert!(validator.validate_dtype(&info).is_ok());
    }

    #[test]
    fn test_dtype_f16_ok() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![("weight", "F16", vec![10, 10])]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        assert!(validator.validate_dtype(&info).is_ok());
    }

    #[test]
    fn test_dtype_f32_ok_with_warning() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![("weight", "F32", vec![10, 10])]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let mut warnings = Vec::new();
        validator
            .validate_dtype_with_warnings(&info, &mut warnings)
            .unwrap();
        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("BF16"));
    }

    #[test]
    fn test_dtype_f64_rejected() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![("bad_tensor", "F64", vec![10, 10])]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let result = validator.validate_dtype(&info);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::UnsupportedDtype {
                tensor_name,
                dtype,
                allowed,
            } => {
                assert_eq!(tensor_name, "bad_tensor");
                assert_eq!(dtype, "F64");
                assert!(allowed.contains(&"BF16".to_string()));
            }
            e => panic!("Expected UnsupportedDtype, got: {:?}", e),
        }
    }

    #[test]
    fn test_dtype_i32_rejected() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![("int_tensor", "I32", vec![5])]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let result = validator.validate_dtype(&info);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::UnsupportedDtype { dtype, .. } => {
                assert_eq!(dtype, "I32");
            }
            e => panic!("Expected UnsupportedDtype, got: {:?}", e),
        }
    }

    #[test]
    fn test_model_type_embedding() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![
            ("encoder.layer.0.attention.weight", "BF16", vec![384, 384]),
            (
                "embeddings.word_embeddings.weight",
                "BF16",
                vec![30522, 384],
            ),
            ("pooler.dense.weight", "BF16", vec![384, 384]),
        ]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let model_type = validator.validate_model_type(&info).unwrap();
        assert_eq!(model_type, ModelType::EmbeddingModel);
    }

    #[test]
    fn test_model_type_classifier() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![
            ("encoder.layer.0.attention.weight", "BF16", vec![768, 768]),
            (
                "embeddings.word_embeddings.weight",
                "BF16",
                vec![30522, 768],
            ),
            ("classifier.weight", "BF16", vec![2, 768]),
            ("classifier.bias", "BF16", vec![2]),
        ]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let model_type = validator.validate_model_type(&info).unwrap();
        assert_eq!(model_type, ModelType::SmallClassifier);
    }

    #[test]
    fn test_unsupported_model_type() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![("random.weight", "BF16", vec![10, 10])]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let result = validator.validate_model_type(&info);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::UnsupportedModelType { reason } => {
                assert!(reason.contains("Could not determine model type"));
            }
            e => panic!("Expected UnsupportedModelType, got: {:?}", e),
        }
    }

    #[test]
    fn test_model_size_limit_embedding() {
        let model_type = ModelType::EmbeddingModel;
        assert_eq!(model_type.max_size_bytes(), 500 * 1024 * 1024);
    }

    #[test]
    fn test_model_size_limit_classifier() {
        let model_type = ModelType::SmallClassifier;
        assert_eq!(model_type.max_size_bytes(), 1024 * 1024 * 1024);
    }

    #[test]
    fn test_unsupported_format_rejection() {
        let validator = ModelValidator::new();
        let path = Path::new("/tmp/model.bin");
        let result = validator.validate_model(path);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::UnsupportedFormat { expected, got } => {
                assert_eq!(expected, "safetensors");
                assert_eq!(got, "bin");
            }
            e => panic!("Expected UnsupportedFormat, got: {:?}", e),
        }
    }

    #[test]
    fn test_invalid_header_too_small() {
        let validator = ModelValidator::new();
        let data = vec![0u8; 4];
        let result = validator.validate_safetensors_format(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::InvalidHeader { reason } => {
                assert!(reason.contains("too small"));
            }
            e => panic!("Expected InvalidHeader, got: {:?}", e),
        }
    }

    #[test]
    fn test_invalid_header_zero_size() {
        let validator = ModelValidator::new();
        let data = vec![0u8; 8]; // header size = 0
        let result = validator.validate_safetensors_format(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::InvalidHeader { reason } => {
                assert!(reason.contains("zero"));
            }
            e => panic!("Expected InvalidHeader, got: {:?}", e),
        }
    }

    #[test]
    fn test_invalid_header_bad_json() {
        let validator = ModelValidator::new();
        let bad_json = b"not json at all!!!";
        let header_size = bad_json.len() as u64;
        let mut data = Vec::new();
        data.extend_from_slice(&header_size.to_le_bytes());
        data.extend_from_slice(bad_json);
        let result = validator.validate_safetensors_format(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::InvalidHeader { reason } => {
                assert!(reason.contains("Invalid JSON"));
            }
            e => panic!("Expected InvalidHeader, got: {:?}", e),
        }
    }

    #[test]
    fn test_no_tensors_rejected() {
        let validator = ModelValidator::new();
        // Header with only __metadata__
        let header = json!({
            "__metadata__": {"format": "pt"}
        });
        let data = build_safetensors_bytes(&header);
        let result = validator.validate_safetensors_format(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::InvalidHeader { reason } => {
                assert!(reason.contains("No tensors"));
            }
            e => panic!("Expected InvalidHeader, got: {:?}", e),
        }
    }

    #[test]
    fn test_metadata_parsed() {
        let validator = ModelValidator::new();
        let mut header = make_header(vec![("encoder.layer.0.weight", "BF16", vec![10, 10])]);
        header.as_object_mut().unwrap().insert(
            "__metadata__".to_string(),
            json!({"format": "pt", "framework": "pytorch"}),
        );
        let data = build_safetensors_bytes(&header);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let meta = info.metadata.unwrap();
        assert_eq!(meta.get("format").unwrap(), "pt");
        assert_eq!(meta.get("framework").unwrap(), "pytorch");
    }

    #[test]
    fn test_missing_dtype_field() {
        let validator = ModelValidator::new();
        let header = json!({
            "weight": {
                "shape": [10, 10],
                "data_offsets": [0, 200]
            }
        });
        let data = build_safetensors_bytes(&header);
        let result = validator.validate_safetensors_format(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::InvalidHeader { reason } => {
                assert!(reason.contains("dtype"));
            }
            e => panic!("Expected InvalidHeader, got: {:?}", e),
        }
    }

    #[test]
    fn test_missing_shape_field() {
        let validator = ModelValidator::new();
        let header = json!({
            "weight": {
                "dtype": "BF16",
                "data_offsets": [0, 200]
            }
        });
        let data = build_safetensors_bytes(&header);
        let result = validator.validate_safetensors_format(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ModelValidationError::InvalidHeader { reason } => {
                assert!(reason.contains("shape"));
            }
            e => panic!("Expected InvalidHeader, got: {:?}", e),
        }
    }

    #[test]
    fn test_build_safetensors_bytes_roundtrip() {
        let validator = ModelValidator::new();
        let tensors = vec![
            ("layer.0.weight", "BF16", vec![256, 256]),
            ("layer.0.bias", "BF16", vec![256]),
        ];
        let data = make_bytes(tensors);
        let info = validator.validate_safetensors_format(&data).unwrap();
        assert_eq!(info.tensors.len(), 2);
        assert_eq!(info.tensors["layer.0.weight"].shape, vec![256, 256]);
        assert_eq!(info.tensors["layer.0.bias"].shape, vec![256]);
    }

    #[test]
    fn test_classifier_with_pre_classifier() {
        let validator = ModelValidator::new();
        let data = make_bytes(vec![
            ("encoder.layer.0.weight", "BF16", vec![768, 768]),
            (
                "embeddings.position_embeddings.weight",
                "BF16",
                vec![512, 768],
            ),
            ("pre_classifier.weight", "BF16", vec![768, 768]),
        ]);
        let info = validator.validate_safetensors_format(&data).unwrap();
        let model_type = validator.validate_model_type(&info).unwrap();
        assert_eq!(model_type, ModelType::SmallClassifier);
    }
}
