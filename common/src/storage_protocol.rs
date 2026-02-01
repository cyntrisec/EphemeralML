use serde::{Deserialize, Serialize};

/// Request to fetch data from model storage (e.g., S3)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StorageRequest {
    pub model_id: String,
    pub part_index: u32,
}

/// Response containing model data part
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum StorageResponse {
    Data { payload: Vec<u8>, is_last: bool },
    Error { message: String },
}
