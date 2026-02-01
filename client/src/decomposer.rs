use crate::{ClientError, EphemeralError, Result, TopologyKey, WeightArrays};
use std::path::Path;

/// Trait for model decomposition functionality
pub trait ModelDecomposer {
    /// Decompose an ONNX model into topology key and weight arrays
    fn decompose_model(&self, onnx_path: &Path) -> Result<(TopologyKey, WeightArrays)>;

    /// Validate ONNX model compatibility with the system
    fn validate_onnx_compatibility(&self, model_path: &Path) -> Result<()>;

    /// Check if all operators in the model are supported by Candle
    fn check_candle_operator_support(&self, operators: &[String]) -> Result<()>;
}

/// Default implementation of model decomposer
pub struct DefaultModelDecomposer;

impl ModelDecomposer for DefaultModelDecomposer {
    fn decompose_model(&self, _onnx_path: &Path) -> Result<(TopologyKey, WeightArrays)> {
        // Placeholder implementation - will be implemented in later tasks
        Err(ClientError::Client(EphemeralError::DecompositionError(
            "Not yet implemented".to_string(),
        )))
    }

    fn validate_onnx_compatibility(&self, _model_path: &Path) -> Result<()> {
        // Placeholder implementation - will be implemented in later tasks
        Err(ClientError::Client(EphemeralError::ValidationError(
            "Not yet implemented".to_string(),
        )))
    }

    fn check_candle_operator_support(&self, _operators: &[String]) -> Result<()> {
        // Placeholder implementation - will be implemented in later tasks
        Err(ClientError::Client(
            EphemeralError::UnsupportedOperatorError("Not yet implemented".to_string()),
        ))
    }
}
