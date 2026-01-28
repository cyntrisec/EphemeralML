use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Topology key containing computation graph structure without weights
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TopologyKey {
    pub graph_id: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub input_shapes: Vec<TensorShape>,
    pub output_shapes: Vec<TensorShape>,
    pub metadata: ModelMetadata,
}

/// Graph node representing an operation in the computation graph
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GraphNode {
    pub node_id: String,
    pub operation: OperationType,
    pub parameters: HashMap<String, serde_json::Value>,
    pub weight_indices: Vec<WeightIndex>,
}

/// Edge connecting two nodes in the computation graph
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GraphEdge {
    pub from_node: String,
    pub to_node: String,
    pub tensor_shape: TensorShape,
}

/// Tensor shape specification
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TensorShape {
    pub dimensions: Vec<usize>,
}

impl TensorShape {
    /// Create a new tensor shape
    pub fn new(dimensions: Vec<usize>) -> Self {
        Self { dimensions }
    }
    
    /// Get the total number of elements in the tensor
    pub fn total_elements(&self) -> usize {
        self.dimensions.iter().product()
    }
    
    /// Check if the shape is valid (no zero dimensions)
    pub fn is_valid(&self) -> bool {
        !self.dimensions.is_empty() && self.dimensions.iter().all(|&d| d > 0)
    }
}

/// Model metadata
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ModelMetadata {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub created_at: u64, // Unix timestamp
    pub checksum: String, // SHA-256 hash of the original model
}

/// Operation types supported by the system
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum OperationType {
    // Convolution operations
    Conv2d,
    Conv1d,
    ConvTranspose2d,
    
    // Linear operations
    Linear,
    
    // Activation functions
    Relu,
    Sigmoid,
    Tanh,
    Gelu,
    Softmax,
    LogSoftmax,
    
    // Pooling operations
    MaxPool2d,
    AvgPool2d,
    AdaptiveAvgPool2d,
    
    // Normalization
    BatchNorm,
    LayerNorm,
    GroupNorm,
    
    // Regularization
    Dropout,
    
    // Element-wise operations
    Add,
    Sub,
    Mul,
    Div,
    
    // Shape operations
    Reshape,
    Flatten,
    Transpose,
    Permute,
    
    // Aggregation operations
    Sum,
    Mean,
    Max,
    Min,
    
    // Other operations
    Concat,
    Split,
    Embedding,
}

/// Weight index pointing to position in unstructured weight array
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WeightIndex {
    pub start_idx: usize,
    pub length: usize,
    pub shape: TensorShape,
    pub weight_type: WeightType,
}

impl WeightIndex {
    /// Create a new weight index
    pub fn new(start_idx: usize, length: usize, shape: TensorShape, weight_type: WeightType) -> Self {
        Self {
            start_idx,
            length,
            shape,
            weight_type,
        }
    }
    
    /// Get the end index (exclusive)
    pub fn end_idx(&self) -> usize {
        self.start_idx + self.length
    }
    
    /// Check if the weight index is valid
    pub fn is_valid(&self) -> bool {
        self.length > 0 && self.shape.is_valid() && self.shape.total_elements() == self.length
    }
}

/// Type of weight data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum WeightType {
    Weights,
    Bias,
    Scale,
    Shift,
    RunningMean,
    RunningVar,
}

/// Unstructured weight arrays with no architectural information
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WeightArrays {
    pub model_id: String,
    pub weight_data: Vec<f32>,
    pub checksum: u64,
    pub total_parameters: usize,
    pub created_at: u64, // Unix timestamp
}

impl WeightArrays {
    /// Create new weight arrays
    pub fn new(model_id: String, weight_data: Vec<f32>) -> Self {
        let total_parameters = weight_data.len();
        let checksum = Self::calculate_checksum(&weight_data);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            model_id,
            weight_data,
            checksum,
            total_parameters,
            created_at,
        }
    }
    
    /// Calculate checksum for weight data
    fn calculate_checksum(data: &[f32]) -> u64 {
        use sha2::{Sha256, Digest};
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                data.as_ptr() as *const u8,
                data.len() * std::mem::size_of::<f32>(),
            )
        };
        let hash = Sha256::digest(bytes);
        u64::from_be_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ])
    }
    
    /// Verify checksum integrity
    pub fn verify_checksum(&self) -> bool {
        self.checksum == Self::calculate_checksum(&self.weight_data)
    }
}

/// Encrypted topology key for secure transmission
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedTopologyKey {
    pub encrypted_data: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_id: String, // KMS key identifier
}

/// Encrypted tensor data
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedTensor {
    pub encrypted_data: Vec<u8>,
    pub shape: TensorShape,
    pub nonce: [u8; 12],
    pub key_id: String, // KMS key identifier
}

/// Encrypted payload for communication
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedPayload {
    pub data: Vec<u8>,
    pub nonce: [u8; 12],
    pub key_id: String, // KMS key identifier
    pub payload_type: PayloadType,
}

/// Type of encrypted payload
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PayloadType {
    TopologyKey,
    InputData,
    OutputData,
    InferenceRequest,
    InferenceResponse,
}

/// Inference request structure
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct InferenceRequest {
    pub request_id: String,
    pub topology_key: EncryptedTopologyKey,
    pub input_data: EncryptedTensor,
    pub model_id: String,
    pub nonce: [u8; 12],
    pub timestamp: u64,
}

/// Inference response structure
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct InferenceResponse {
    pub request_id: String,
    pub result: EncryptedTensor,
    pub execution_time_ms: u64,
    pub attestation_proof: AttestationDocument,
    pub timestamp: u64,
}

/// Attestation document for enclave verification
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AttestationDocument {
    pub module_id: String,
    pub digest: Vec<u8>, // SHA-384 hash (48 bytes)
    pub timestamp: u64,
    pub pcrs: PcrMeasurements,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
    pub nonce: Option<Vec<u8>>, // Optional nonce for freshness
}

/// PCR measurements for attestation
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PcrMeasurements {
    pub pcr0: Vec<u8>, // Enclave image measurement (48 bytes)
    pub pcr1: Vec<u8>, // Linux kernel measurement (48 bytes)
    pub pcr2: Vec<u8>, // Application measurement (48 bytes)
}

impl PcrMeasurements {
    /// Create new PCR measurements
    pub fn new(pcr0: Vec<u8>, pcr1: Vec<u8>, pcr2: Vec<u8>) -> Self {
        Self { pcr0, pcr1, pcr2 }
    }
    
    /// Validate PCR measurement lengths (should be 48 bytes each for SHA-384)
    pub fn is_valid(&self) -> bool {
        self.pcr0.len() == 48 && self.pcr1.len() == 48 && self.pcr2.len() == 48
    }
}

/// Secure communication channel
#[derive(Debug, Clone)]
pub struct SecureChannel {
    pub endpoint: String,
    pub session_key: Vec<u8>,
    pub attestation_verified: bool,
    pub created_at: u64,
    pub expires_at: u64,
}

impl SecureChannel {
    /// Create a new secure channel
    pub fn new(endpoint: String, session_key: Vec<u8>, ttl_seconds: u64) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        Self {
            endpoint,
            session_key,
            attestation_verified: false,
            created_at: now,
            expires_at: now + ttl_seconds,
        }
    }
    
    /// Check if the channel is expired
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }
    
    /// Mark attestation as verified
    pub fn mark_attestation_verified(&mut self) {
        self.attestation_verified = true;
    }
}

/// Session information for tracking inference sessions
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SessionInfo {
    pub session_id: String,
    pub client_id: String,
    pub model_id: String,
    pub created_at: u64,
    pub last_activity: u64,
    pub status: SessionStatus,
}

/// Status of an inference session
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum SessionStatus {
    Initializing,
    AttestationPending,
    AttestationVerified,
    InferenceInProgress,
    Completed,
    Failed,
    Expired,
}

/// Audit log entry for security events
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct AuditLogEntry {
    pub entry_id: String,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub session_id: Option<String>,
    pub client_id: Option<String>,
    pub model_id: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    pub severity: AuditSeverity,
    pub is_metric: bool,
}

/// Types of audit events
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AuditEventType {
    SessionCreated,
    AttestationRequested,
    AttestationVerified,
    AttestationFailed,
    ModelDecomposed,
    ModelAssembled,
    InferenceStarted,
    InferenceCompleted,
    InferenceFailed,
    ModelDestroyed,
    SecurityViolation,
    SystemError,
    SessionExpired,
}

/// Severity levels for audit events
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}