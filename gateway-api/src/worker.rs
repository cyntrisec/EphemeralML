//! Worker-channel abstraction for the local proxy pivot.
//!
//! The OpenAI HTTP surface terminates in the proxy. Everything beyond this
//! boundary is a worker channel that accepts internal inference requests. The
//! first implementation wraps the current `SecureEnclaveClient` path so the
//! proxy can ship before the AWS host-relay / enclave-worker split lands.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
#[cfg(not(feature = "production"))]
use confidential_ml_transport::MockVerifier;
#[cfg(feature = "production")]
use confidential_ml_transport::NitroVerifier;
use confidential_ml_transport::{
    AttestationVerifier as TransportAttestationVerifier, Error as TransportError,
    ExpectedMeasurements, Message, MockProvider, SecureChannel, SessionConfig,
};
use ephemeral_ml_client::secure_client::{InferenceHandlerInput, InferenceHandlerOutput};
use ephemeral_ml_client::{
    InferenceResult, ModelIdentity, ModelManifest, SecureClient, SecureEnclaveClient,
};
use ephemeral_ml_common::{CyntrisecPolicy, WorkerAttestationUserData, WorkerResponse};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};

use crate::config::{GatewayConfig, WorkerChannelKind};
use crate::reconnect::CONNECT_TIMEOUT;
use crate::types::{EmbeddingData, EmbeddingInput, EmbeddingRequest, EmbeddingResponse, Usage};

pub type PinnedPolicyDigest = String;
pub type PinnedManifestDigest = String;
pub type WorkerEndpointDigest = String;
pub type Timestamp = u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Verified,
    Unverified,
    NotApplicable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PreflightReport {
    pub policy_loaded: PinnedPolicyDigest,
    pub manifest_loaded: PinnedManifestDigest,
    pub attestation_status: AttestationStatus,
    pub model_identity: Option<ModelIdentity>,
    /// Lowercase hex-encoded 32-byte Ed25519 receipt-signing public key bound
    /// into the active worker attestation user_data. No `0x` prefix.
    pub receipt_signing_pubkey: Option<String>,
    pub started_at: Timestamp,
    pub worker_endpoint_digest: WorkerEndpointDigest,
    pub worker_channel_kind: WorkerChannelKind,
}

impl PreflightReport {
    pub fn build_required(
        config: &GatewayConfig,
        attestation_status: AttestationStatus,
        receipt_signing_pubkey: Option<String>,
    ) -> Result<Self, PreflightError> {
        if attestation_status != AttestationStatus::Verified {
            return Err(PreflightError::new(format!(
                "worker attestation is not verified: {attestation_status:?}"
            )));
        }

        let policy_path = config
            .preflight_policy_path
            .as_ref()
            .ok_or_else(|| PreflightError::new("CYNTRISEC_POLICY_PATH is required"))?;
        let manifest_path = config
            .preflight_manifest_path
            .as_ref()
            .ok_or_else(|| PreflightError::new("CYNTRISEC_MANIFEST_PATH is required"))?;

        let policy_bytes = read_preflight_file(policy_path, "policy")?;
        let manifest_bytes = read_preflight_file(manifest_path, "manifest")?;
        let manifest = ModelManifest::from_json(&manifest_bytes)
            .map_err(|e| PreflightError::new(format!("invalid model manifest: {e}")))?;

        Ok(Self {
            policy_loaded: sha256_uri(&policy_bytes),
            manifest_loaded: sha256_uri(&manifest_bytes),
            attestation_status,
            model_identity: manifest.model_identity,
            receipt_signing_pubkey,
            started_at: current_unix_timestamp(),
            worker_endpoint_digest: sha256_uri(config.backend_addr.as_bytes()),
            worker_channel_kind: config.worker_channel_kind,
        })
    }
}

fn read_preflight_file(path: &Path, label: &str) -> Result<Vec<u8>, PreflightError> {
    std::fs::read(path).map_err(|e| {
        PreflightError::new(format!(
            "failed to read {label} file '{}': {e}",
            path.display()
        ))
    })
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn current_unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightError {
    message: String,
}

impl PreflightError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PreflightError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerErrorKind {
    Unavailable,
    Timeout,
    Inference,
    InvalidInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerChannelErrorCode {
    Generic,
    TransportUnreachable,
    AttestationMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerChannelError {
    pub kind: WorkerErrorKind,
    pub code: WorkerChannelErrorCode,
    pub message: String,
}

impl WorkerChannelError {
    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            kind: WorkerErrorKind::Unavailable,
            code: WorkerChannelErrorCode::Generic,
            message: message.into(),
        }
    }

    fn timeout(message: impl Into<String>) -> Self {
        Self {
            kind: WorkerErrorKind::Timeout,
            code: WorkerChannelErrorCode::Generic,
            message: message.into(),
        }
    }

    fn inference(message: impl Into<String>) -> Self {
        Self {
            kind: WorkerErrorKind::Inference,
            code: WorkerChannelErrorCode::Generic,
            message: message.into(),
        }
    }

    fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            kind: WorkerErrorKind::InvalidInput,
            code: WorkerChannelErrorCode::Generic,
            message: message.into(),
        }
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self {
            kind: WorkerErrorKind::Unavailable,
            code: WorkerChannelErrorCode::Generic,
            message: message.into(),
        }
    }

    fn transport_unreachable(addr: &str, reason: impl fmt::Display) -> Self {
        Self {
            kind: WorkerErrorKind::Unavailable,
            code: WorkerChannelErrorCode::TransportUnreachable,
            message: format!("Cannot reach worker at {addr}: {reason}"),
        }
    }

    fn attestation_mismatch(reason: impl fmt::Display) -> Self {
        Self {
            kind: WorkerErrorKind::Unavailable,
            code: WorkerChannelErrorCode::AttestationMismatch,
            message: format!("Worker attestation does not match pinned policy: {reason}"),
        }
    }
}

impl fmt::Display for WorkerChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WorkerChannelError {}

#[async_trait]
pub trait WorkerChannel: Send + Sync {
    async fn establish(&self) -> Result<(), WorkerChannelError>;

    async fn inference(
        &self,
        req: InferenceHandlerInput,
    ) -> Result<InferenceHandlerOutput, WorkerChannelError>;

    async fn embedding(
        &self,
        req: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, WorkerChannelError>;

    /// Current attestation state for the active worker session.
    ///
    /// Implementations return `Unverified` before a worker handshake completes,
    /// `Verified` after the handshake has validated expected session evidence,
    /// and `NotApplicable` only for future transports that intentionally do not
    /// produce hardware attestation.
    fn attestation_status(&self) -> AttestationStatus;

    /// Receipt-signing key bound into the active worker attestation, when an
    /// attested worker session has completed. It is recorded in preflight for
    /// later bundle correlation, but v1 does not verify receipts against it
    /// until the worker-side bundle emitter lands.
    fn receipt_signing_pubkey(&self) -> Option<String> {
        None
    }
}

/// Adapter for the current backend path during the proxy migration.
///
/// This wraps `SecureEnclaveClient` today. The next implementation will keep
/// the same trait surface and swap the transport to the worker SecureChannel
/// path that talks through the AWS host relay.
pub struct HttpBackendChannel {
    client: Arc<Mutex<SecureEnclaveClient>>,
    backend_addr: String,
    connected: Arc<std::sync::atomic::AtomicBool>,
    reconnect_notify: Arc<Notify>,
    request_timeout: Duration,
}

/// Step-2b secure-worker adapter.
///
/// This preserves the `WorkerChannel` contract while swapping the inner type
/// away from the legacy HTTP backend path. The transport is intentionally
/// fail-closed until the AWS host relay and enclave worker protocol land.
pub struct SecureChannelWorker {
    inner: SecureChannelTransport,
}

/// Internal secure transport for the worker channel.
///
/// `attestation_status() == Verified` is only valid after all five checks have
/// completed: HPKE handshake, worker attestation document receipt, document and
/// certificate-chain validation, PCR0/PCR1/PCR2 plus ImageSha384 policy match,
/// and receipt-signing public key extraction from attestation user_data. This
/// scaffold does not mark the transport verified until that direct worker
/// protocol is implemented.
pub struct SecureChannelTransport {
    backend_addr: String,
    expected_measurements: Result<ExpectedMeasurements, String>,
    attestation_verifier: Result<Arc<dyn TransportAttestationVerifier>, String>,
    channel: Arc<Mutex<Option<SecureChannel<TcpStream>>>>,
    connected: Arc<std::sync::atomic::AtomicBool>,
    attestation_verified: Arc<std::sync::atomic::AtomicBool>,
    reconnect_notify: Arc<Notify>,
    receipt_signing_pubkey: Arc<std::sync::RwLock<Option<String>>>,
    handshake_lock: Arc<Mutex<()>>,
    request_timeout: Duration,
}

enum BackendCall {
    Generate { text: String, max_tokens: usize },
    Text(String),
    Tensor(Vec<f32>),
}

impl HttpBackendChannel {
    pub fn new(
        client: Arc<Mutex<SecureEnclaveClient>>,
        backend_addr: String,
        connected: Arc<std::sync::atomic::AtomicBool>,
        reconnect_notify: Arc<Notify>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            client,
            backend_addr,
            connected,
            reconnect_notify,
            request_timeout,
        }
    }

    async fn ensure_connected(&self) -> Result<(), WorkerChannelError> {
        use std::sync::atomic::Ordering;
        if self.connected.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut client = self.client.lock().await;
        if self.connected.load(Ordering::Acquire) {
            return Ok(());
        }

        tokio::time::timeout(
            CONNECT_TIMEOUT,
            client.establish_channel(&self.backend_addr),
        )
        .await
        .map_err(|_| {
            WorkerChannelError::timeout(format!(
                "worker handshake timed out after {}s",
                CONNECT_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| WorkerChannelError::unavailable(format!("worker handshake failed: {e}")))?;

        self.connected.store(true, Ordering::Release);
        tracing::info!(
            backend = %self.backend_addr,
            "Worker channel established"
        );
        Ok(())
    }

    fn mark_disconnected_if_transport_error(&self, err: &str) {
        if is_transport_error(err) {
            self.connected
                .store(false, std::sync::atomic::Ordering::Release);
            self.reconnect_notify.notify_one();
        }
    }
}

impl SecureChannelTransport {
    pub fn new(
        backend_addr: String,
        connected: Arc<std::sync::atomic::AtomicBool>,
        reconnect_notify: Arc<Notify>,
        request_timeout: Duration,
        expected_measurements: Result<ExpectedMeasurements, String>,
    ) -> Self {
        let attestation_verifier = expected_measurements
            .as_ref()
            .map(build_worker_attestation_verifier)
            .map_err(Clone::clone)
            .and_then(|result| result);
        Self {
            backend_addr,
            expected_measurements,
            attestation_verifier,
            channel: Arc::new(Mutex::new(None)),
            connected,
            attestation_verified: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            reconnect_notify,
            receipt_signing_pubkey: Arc::new(std::sync::RwLock::new(None)),
            handshake_lock: Arc::new(Mutex::new(())),
            request_timeout,
        }
    }

    async fn ensure_attested_channel(&self) -> Result<(), WorkerChannelError> {
        use std::sync::atomic::Ordering;
        if self.attestation_status() == AttestationStatus::Verified {
            return Ok(());
        }

        let _handshake = self.handshake_lock.lock().await;
        if self.attestation_status() == AttestationStatus::Verified {
            return Ok(());
        }

        let expected_measurements = self
            .expected_measurements
            .as_ref()
            .map_err(WorkerChannelError::attestation_mismatch)?
            .clone();
        let verifier = self
            .attestation_verifier
            .as_ref()
            .map_err(WorkerChannelError::attestation_mismatch)?;

        self.clear_attested_state().await;

        let connect = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.backend_addr))
            .await
            .map_err(|_| {
                WorkerChannelError::transport_unreachable(
                    &self.backend_addr,
                    format!("connect timed out after {}s", CONNECT_TIMEOUT.as_secs()),
                )
            })?;

        let stream = connect
            .map_err(|e| WorkerChannelError::transport_unreachable(&self.backend_addr, e))?;
        let session_config = SessionConfig::builder()
            .expected_measurements(expected_measurements)
            .build()
            .map_err(WorkerChannelError::attestation_mismatch)?;

        let provider = MockProvider::new();
        let channel = tokio::time::timeout(
            CONNECT_TIMEOUT,
            SecureChannel::connect_with_attestation(
                stream,
                &provider,
                verifier.as_ref(),
                session_config,
            ),
        )
        .await
        .map_err(|_| {
            WorkerChannelError::transport_unreachable(
                &self.backend_addr,
                format!("handshake timed out after {}s", CONNECT_TIMEOUT.as_secs()),
            )
        })?
        .map_err(|err| self.channel_error_for_handshake(err))?;

        let peer = channel
            .peer_attestation()
            .ok_or_else(|| WorkerChannelError::attestation_mismatch("missing peer attestation"))?;
        let user_data = peer.user_data.as_deref().ok_or_else(|| {
            WorkerChannelError::attestation_mismatch("missing worker attestation user_data")
        })?;
        let worker_user_data = WorkerAttestationUserData::from_cbor(user_data).map_err(|err| {
            WorkerChannelError::attestation_mismatch(format!(
                "invalid worker attestation user_data: {err}"
            ))
        })?;

        if let Ok(mut guard) = self.receipt_signing_pubkey.write() {
            *guard = Some(hex::encode(worker_user_data.receipt_signing_pubkey));
        }
        *self.channel.lock().await = Some(channel);
        self.connected.store(true, Ordering::Release);
        self.attestation_verified.store(true, Ordering::Release);
        tracing::info!(
            backend = %self.backend_addr,
            model_id = %worker_user_data.model_id,
            "Secure worker channel established"
        );
        Ok(())
    }

    fn current_receipt_signing_pubkey(&self) -> Option<String> {
        self.receipt_signing_pubkey
            .read()
            .ok()
            .and_then(|guard| guard.clone())
    }

    async fn clear_attested_state(&self) {
        use std::sync::atomic::Ordering;
        self.attestation_verified.store(false, Ordering::Release);
        self.connected.store(false, Ordering::Release);
        if let Ok(mut guard) = self.receipt_signing_pubkey.write() {
            *guard = None;
        }
        *self.channel.lock().await = None;
        self.reconnect_notify.notify_one();
    }

    fn mark_channel_dead(&self) {
        use std::sync::atomic::Ordering;
        self.attestation_verified.store(false, Ordering::Release);
        self.connected.store(false, Ordering::Release);
        if let Ok(mut guard) = self.receipt_signing_pubkey.write() {
            *guard = None;
        }
        self.reconnect_notify.notify_one();
    }

    fn channel_error_for_handshake(&self, err: TransportError) -> WorkerChannelError {
        match err {
            TransportError::Io(e) => {
                WorkerChannelError::transport_unreachable(&self.backend_addr, e)
            }
            other => WorkerChannelError::attestation_mismatch(other),
        }
    }

    async fn send_worker_request(
        &self,
        req: InferenceHandlerInput,
    ) -> Result<InferenceHandlerOutput, WorkerChannelError> {
        self.ensure_attested_channel().await?;
        let req_bytes = serde_json::to_vec(&req)
            .map_err(|e| WorkerChannelError::invalid_input(format!("serialize: {e}")))?;

        let mut channel_guard = self.channel.lock().await;
        let send_result = {
            let channel = channel_guard.as_mut().ok_or_else(|| {
                WorkerChannelError::transport_unreachable(
                    &self.backend_addr,
                    "channel missing after preflight",
                )
            })?;
            channel.send(Bytes::from(req_bytes)).await
        };
        if let Err(err) = send_result {
            *channel_guard = None;
            self.mark_channel_dead();
            return Err(WorkerChannelError::transport_unreachable(
                &self.backend_addr,
                err,
            ));
        }

        let response_bytes = {
            let channel = channel_guard.as_mut().ok_or_else(|| {
                WorkerChannelError::transport_unreachable(
                    &self.backend_addr,
                    "channel missing after send",
                )
            })?;
            loop {
                let recv = tokio::time::timeout(self.request_timeout, channel.recv()).await;
                let msg = match recv {
                    Ok(Ok(msg)) => msg,
                    Ok(Err(err)) => {
                        break Err(WorkerChannelError::transport_unreachable(
                            &self.backend_addr,
                            err,
                        ));
                    }
                    Err(_) => {
                        break Err(WorkerChannelError::timeout(
                            "worker inference timed out".to_string(),
                        ));
                    }
                };
                match msg {
                    Message::Heartbeat => continue,
                    Message::Data(bytes) => break Ok(bytes),
                    other => {
                        break Err(WorkerChannelError::protocol(format!(
                            "unexpected worker message: {other:?}"
                        )));
                    }
                }
            }
        };
        let response_bytes = match response_bytes {
            Ok(bytes) => bytes,
            Err(err) => {
                *channel_guard = None;
                self.mark_channel_dead();
                return Err(err);
            }
        };

        let response: WorkerResponse = match serde_json::from_slice(&response_bytes) {
            Ok(response) => response,
            Err(e) => {
                *channel_guard = None;
                self.mark_channel_dead();
                return Err(WorkerChannelError::protocol(format!(
                    "decode WorkerResponse: {e}"
                )));
            }
        };
        match response {
            WorkerResponse::Ok(output) => Ok(output),
            WorkerResponse::Err(err) => Err(WorkerChannelError::inference(format!(
                "{}: {}",
                err.code, err.message
            ))),
        }
    }
}

impl SecureChannelWorker {
    pub fn new(
        _client: Arc<Mutex<SecureEnclaveClient>>,
        backend_addr: String,
        connected: Arc<std::sync::atomic::AtomicBool>,
        reconnect_notify: Arc<Notify>,
        request_timeout: Duration,
        expected_measurements: Result<ExpectedMeasurements, String>,
    ) -> Self {
        Self {
            inner: SecureChannelTransport::new(
                backend_addr,
                connected,
                reconnect_notify,
                request_timeout,
                expected_measurements,
            ),
        }
    }
}

#[async_trait]
impl WorkerChannel for HttpBackendChannel {
    async fn establish(&self) -> Result<(), WorkerChannelError> {
        self.ensure_connected().await
    }

    async fn inference(
        &self,
        req: InferenceHandlerInput,
    ) -> Result<InferenceHandlerOutput, WorkerChannelError> {
        let (model_id, call) = normalize_inference_request(req)?;

        self.ensure_connected().await?;

        let result = {
            let mut client = self.client.lock().await;
            let backend_call = async {
                match call {
                    BackendCall::Generate { text, max_tokens } => {
                        client
                            .execute_inference_generate(&model_id, &text, max_tokens)
                            .await
                    }
                    BackendCall::Text(text) => {
                        client.execute_inference_text(&model_id, &text).await
                    }
                    BackendCall::Tensor(tensor) => {
                        client.execute_inference(&model_id, tensor).await
                    }
                }
            };
            tokio::time::timeout(self.request_timeout, backend_call).await
        };

        match result {
            Ok(Ok(result)) => Ok(inference_output_from_result(result)),
            Ok(Err(e)) => {
                let err = e.to_string();
                self.mark_disconnected_if_transport_error(&err);
                Err(WorkerChannelError::inference(err))
            }
            Err(_) => {
                self.connected
                    .store(false, std::sync::atomic::Ordering::Release);
                self.reconnect_notify.notify_one();
                Err(WorkerChannelError::timeout(
                    "worker inference timed out".to_string(),
                ))
            }
        }
    }

    async fn embedding(
        &self,
        req: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, WorkerChannelError> {
        let texts = match req.input {
            EmbeddingInput::Single(s) => vec![s],
            EmbeddingInput::Multiple(v) => v,
        };
        let mut data = Vec::with_capacity(texts.len());
        let mut total_tokens = 0;

        for (index, text) in texts.iter().enumerate() {
            let output = self
                .inference(InferenceHandlerInput {
                    model_id: req.model.clone(),
                    input_data: text.as_bytes().to_vec(),
                    input_shape: None,
                    generate: false,
                    max_tokens: None,
                    temperature: None,
                    top_p: None,
                    benchmark_mode: None,
                })
                .await?;
            total_tokens += estimate_tokens(text);
            data.push(EmbeddingData {
                object: "embedding",
                embedding: output.output_tensor,
                index,
            });
        }

        Ok(EmbeddingResponse {
            object: "list",
            data,
            model: req.model,
            usage: Usage {
                prompt_tokens: total_tokens,
                completion_tokens: 0,
                total_tokens,
            },
            metadata: None,
        })
    }

    fn attestation_status(&self) -> AttestationStatus {
        if self.connected.load(std::sync::atomic::Ordering::Acquire) {
            AttestationStatus::Verified
        } else {
            AttestationStatus::Unverified
        }
    }
}

#[async_trait]
impl WorkerChannel for SecureChannelWorker {
    async fn establish(&self) -> Result<(), WorkerChannelError> {
        self.inner.establish().await
    }

    async fn inference(
        &self,
        req: InferenceHandlerInput,
    ) -> Result<InferenceHandlerOutput, WorkerChannelError> {
        self.inner.inference(req).await
    }

    async fn embedding(
        &self,
        req: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, WorkerChannelError> {
        self.inner.embedding(req).await
    }

    fn attestation_status(&self) -> AttestationStatus {
        self.inner.attestation_status()
    }

    fn receipt_signing_pubkey(&self) -> Option<String> {
        self.inner.receipt_signing_pubkey()
    }
}

#[async_trait]
impl WorkerChannel for SecureChannelTransport {
    async fn establish(&self) -> Result<(), WorkerChannelError> {
        self.ensure_attested_channel().await
    }

    async fn inference(
        &self,
        req: InferenceHandlerInput,
    ) -> Result<InferenceHandlerOutput, WorkerChannelError> {
        self.send_worker_request(req).await
    }

    async fn embedding(
        &self,
        req: EmbeddingRequest,
    ) -> Result<EmbeddingResponse, WorkerChannelError> {
        let texts = match req.input {
            EmbeddingInput::Single(s) => vec![s],
            EmbeddingInput::Multiple(v) => v,
        };
        let mut data = Vec::with_capacity(texts.len());
        let mut total_tokens = 0;
        for text in texts {
            let output = self
                .inference(InferenceHandlerInput {
                    model_id: req.model.clone(),
                    input_data: text.as_bytes().to_vec(),
                    input_shape: None,
                    generate: false,
                    max_tokens: None,
                    temperature: None,
                    top_p: None,
                    benchmark_mode: None,
                })
                .await?;
            total_tokens += estimate_tokens(&text);
            data.push(EmbeddingData {
                object: "embedding",
                embedding: output.output_tensor,
                index: data.len(),
            });
        }
        Ok(EmbeddingResponse {
            object: "list",
            data,
            model: req.model,
            usage: Usage {
                prompt_tokens: total_tokens,
                completion_tokens: 0,
                total_tokens,
            },
            metadata: None,
        })
    }

    fn attestation_status(&self) -> AttestationStatus {
        let has_bound_receipt_key = self.current_receipt_signing_pubkey().is_some();
        if self
            .attestation_verified
            .load(std::sync::atomic::Ordering::Acquire)
            && has_bound_receipt_key
            && self.connected.load(std::sync::atomic::Ordering::Acquire)
        {
            AttestationStatus::Verified
        } else {
            AttestationStatus::Unverified
        }
    }

    fn receipt_signing_pubkey(&self) -> Option<String> {
        self.current_receipt_signing_pubkey()
    }
}

fn inference_output_from_result(result: InferenceResult) -> InferenceHandlerOutput {
    InferenceHandlerOutput {
        output_tensor: result.output_tensor,
        receipt: result.receipt,
        generated_text: result.generated_text,
        boot_attestation_b64: result.boot_attestation_b64,
        model_manifest_json: result.model_manifest_json,
        air_v1_receipt_b64: result.air_v1_receipt_b64,
        air_v1_model_hash_scheme: result.air_v1_model_hash_scheme,
        model_identity_coverage: result.model_identity_coverage,
        bundle_url: result.bundle_url,
        bundle_sha256: result.bundle_sha256,
        benchmark: result.benchmark,
    }
}

fn normalize_inference_request(
    req: InferenceHandlerInput,
) -> Result<(String, BackendCall), WorkerChannelError> {
    let model_id = req.model_id.clone();
    let call = if req.generate {
        BackendCall::Generate {
            text: String::from_utf8(req.input_data).map_err(|e| {
                WorkerChannelError::invalid_input(format!("generate input is not UTF-8: {e}"))
            })?,
            max_tokens: req.max_tokens.unwrap_or(256),
        }
    } else if req.input_shape.is_some() {
        BackendCall::Tensor(f32_tensor_from_le_bytes(&req.input_data)?)
    } else {
        BackendCall::Text(String::from_utf8(req.input_data).map_err(|e| {
            WorkerChannelError::invalid_input(format!("text input is not UTF-8: {e}"))
        })?)
    };

    Ok((model_id, call))
}

fn f32_tensor_from_le_bytes(bytes: &[u8]) -> Result<Vec<f32>, WorkerChannelError> {
    if bytes.len() % 4 != 0 {
        return Err(WorkerChannelError::invalid_input(format!(
            "tensor input has {} bytes, not a multiple of 4",
            bytes.len()
        )));
    }

    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn estimate_tokens(text: &str) -> u32 {
    if text.is_empty() {
        0
    } else {
        ((text.len() as f64 / 4.0).ceil() as u32).max(1)
    }
}

fn is_transport_error(err: &str) -> bool {
    err.contains("Transport error")
        || err.contains("Network error")
        || err.contains("Send failed")
        || err.contains("Recv failed")
        || err.contains("Channel not established")
        || err.contains("connection reset")
        || err.contains("broken pipe")
}

pub fn expected_measurements_from_policy_path(
    path: Option<&Path>,
) -> Result<ExpectedMeasurements, String> {
    let Some(path) = path else {
        return Ok(ExpectedMeasurements::new(BTreeMap::new()));
    };
    let bytes = std::fs::read(path)
        .map_err(|err| format!("failed to read policy file '{}': {err}", path.display()))?;
    let policy = CyntrisecPolicy::from_json(&bytes)
        .map_err(|err| format!("invalid cyntrisec policy '{}': {err}", path.display()))?;
    let values = policy.expected_measurement_values().map_err(|err| {
        format!(
            "invalid worker measurement policy '{}': {err}",
            path.display()
        )
    })?;
    Ok(ExpectedMeasurements::new(values))
}

fn build_worker_attestation_verifier(
    expected_measurements: &ExpectedMeasurements,
) -> Result<Arc<dyn TransportAttestationVerifier>, String> {
    #[cfg(feature = "production")]
    {
        NitroVerifier::new(expected_measurements.values.clone())
            .map(|verifier| Arc::new(verifier) as Arc<dyn TransportAttestationVerifier>)
            .map_err(|err| format!("failed to initialize Nitro verifier: {err}"))
    }
    #[cfg(not(feature = "production"))]
    {
        let _ = expected_measurements;
        Ok(Arc::new(MockVerifier::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ephemeral_ml_client::{AttestationReceipt, EnclaveMeasurements, SecurityMode};
    use ephemeral_ml_enclave::worker_server::{
        InferenceHandler as EnclaveInferenceHandler, WorkerServer as EnclaveWorkerServer,
    };
    use std::collections::BTreeMap;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;

    struct MockWorkerChannel {
        kind: WorkerChannelKind,
    }

    struct QueueInferenceHandler {
        responses: StdMutex<
            VecDeque<Result<InferenceHandlerOutput, ephemeral_ml_common::WorkerInferenceError>>,
        >,
    }

    impl QueueInferenceHandler {
        fn new(
            responses: Vec<
                Result<InferenceHandlerOutput, ephemeral_ml_common::WorkerInferenceError>,
            >,
        ) -> Self {
            Self {
                responses: StdMutex::new(VecDeque::from(responses)),
            }
        }
    }

    #[async_trait]
    impl EnclaveInferenceHandler for QueueInferenceHandler {
        async fn handle(
            &self,
            input: InferenceHandlerInput,
        ) -> Result<InferenceHandlerOutput, ephemeral_ml_common::WorkerInferenceError> {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(mock_worker_output(&input.model_id)))
        }
    }

    impl HttpBackendChannel {
        fn new_mock() -> MockWorkerChannel {
            MockWorkerChannel {
                kind: WorkerChannelKind::Http,
            }
        }
    }

    impl SecureChannelWorker {
        fn new_mock() -> MockWorkerChannel {
            MockWorkerChannel {
                kind: WorkerChannelKind::Secure,
            }
        }
    }

    #[async_trait]
    impl WorkerChannel for MockWorkerChannel {
        async fn establish(&self) -> Result<(), WorkerChannelError> {
            Ok(())
        }

        async fn inference(
            &self,
            req: InferenceHandlerInput,
        ) -> Result<InferenceHandlerOutput, WorkerChannelError> {
            let mut coverage = BTreeMap::new();
            coverage.insert("weights".to_string(), true);
            coverage.insert("erofs_root".to_string(), true);
            Ok(InferenceHandlerOutput {
                output_tensor: vec![1.0, 2.0],
                receipt: mock_receipt(&req.model_id),
                generated_text: req.generate.then(|| "mock generation".to_string()),
                boot_attestation_b64: Some("mock-attestation".to_string()),
                model_manifest_json: Some(r#"{"model_id":"mock"}"#.to_string()),
                air_v1_receipt_b64: Some("mock-air".to_string()),
                air_v1_model_hash_scheme: Some("sha256-manifest".to_string()),
                model_identity_coverage: Some(coverage),
                bundle_url: Some("s3://customer-evidence/mock.bundle.tar.gz".to_string()),
                bundle_sha256: Some("b".repeat(64)),
                benchmark: Some(serde_json::json!({
                    "worker_channel_kind": format!("{:?}", self.kind),
                })),
            })
        }

        async fn embedding(
            &self,
            req: EmbeddingRequest,
        ) -> Result<EmbeddingResponse, WorkerChannelError> {
            Ok(EmbeddingResponse {
                object: "list",
                data: vec![EmbeddingData {
                    object: "embedding",
                    embedding: vec![1.0, 2.0],
                    index: 0,
                }],
                model: req.model,
                usage: Usage {
                    prompt_tokens: 1,
                    completion_tokens: 0,
                    total_tokens: 1,
                },
                metadata: None,
            })
        }

        fn attestation_status(&self) -> AttestationStatus {
            AttestationStatus::Verified
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ContractShape {
        Ok(OutputShape),
        Err(WorkerErrorKind),
    }

    #[derive(Debug, PartialEq, Eq)]
    struct OutputShape {
        output_tensor_len: usize,
        has_generated_text: bool,
        has_boot_attestation: bool,
        has_model_manifest: bool,
        has_air_receipt: bool,
        has_model_hash_scheme: bool,
        has_identity_coverage: bool,
        has_bundle_url: bool,
        has_bundle_sha256: bool,
        has_benchmark: bool,
    }

    #[test]
    fn preflight_requires_verified_attestation() {
        let config = test_config(None, None);
        let err = PreflightReport::build_required(&config, AttestationStatus::Unverified, None)
            .expect_err("unverified attestation must fail closed");
        assert!(err.to_string().contains("not verified"));
    }

    #[test]
    fn preflight_builds_digests_and_extracts_model_identity() {
        let dir =
            std::env::temp_dir().join(format!("cyntrisec-preflight-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("cyntrisec-policy.json");
        let manifest_path = dir.join("model-manifest.json");
        std::fs::write(&policy_path, br#"{"policy":"test"}"#).unwrap();
        std::fs::write(&manifest_path, manifest_json()).unwrap();

        let config = test_config(Some(policy_path.clone()), Some(manifest_path.clone()));
        let report = PreflightReport::build_required(&config, AttestationStatus::Verified, None)
            .expect("valid preflight inputs should build");

        assert!(report.policy_loaded.starts_with("sha256:"));
        assert!(report.manifest_loaded.starts_with("sha256:"));
        assert!(report.worker_endpoint_digest.starts_with("sha256:"));
        assert_eq!(report.worker_channel_kind, WorkerChannelKind::Http);
        assert!(report.receipt_signing_pubkey.is_none());
        let identity = report.model_identity.expect("manifest identity extracted");
        assert_eq!(identity.erofs_root.as_deref(), Some("sha256:erofs-root"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn worker_impls_share_route_contract() {
        let http_out = HttpBackendChannel::new_mock()
            .inference(sample_inference_input())
            .await;
        let secure_out = SecureChannelWorker::new_mock()
            .inference(sample_inference_input())
            .await;

        assert_eq!(shape_of(http_out), shape_of(secure_out));
    }

    #[test]
    fn preflight_reports_secure_channel_kind() {
        let dir = std::env::temp_dir().join(format!(
            "cyntrisec-preflight-secure-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("cyntrisec-policy.json");
        let manifest_path = dir.join("model-manifest.json");
        std::fs::write(&policy_path, br#"{"policy":"test"}"#).unwrap();
        std::fs::write(&manifest_path, manifest_json()).unwrap();

        let mut config = test_config(Some(policy_path), Some(manifest_path));
        config.worker_channel_kind = WorkerChannelKind::Secure;
        let pubkey_hex = "aa".repeat(32);
        let report = PreflightReport::build_required(
            &config,
            AttestationStatus::Verified,
            Some(pubkey_hex.clone()),
        )
        .expect("secure preflight inputs should build");

        assert_eq!(report.worker_channel_kind, WorkerChannelKind::Secure);
        assert_eq!(
            report.receipt_signing_pubkey.as_deref(),
            Some(pubkey_hex.as_str())
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn secure_channel_transport_fails_closed_when_unreachable() {
        let transport = SecureChannelTransport::new(
            "127.0.0.1:9".to_string(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(Notify::new()),
            Duration::from_millis(100),
            Ok(ExpectedMeasurements::new(BTreeMap::new())),
        );

        let err = transport
            .establish()
            .await
            .expect_err("secure transport must fail closed without a worker");

        assert_eq!(err.kind, WorkerErrorKind::Unavailable);
        assert!(
            matches!(
                err.code,
                WorkerChannelErrorCode::TransportUnreachable
                    | WorkerChannelErrorCode::AttestationMismatch
            ),
            "unexpected code: {:?}",
            err.code
        );
        assert!(
            err.message.starts_with("Cannot reach worker at ")
                || err
                    .message
                    .starts_with("Worker attestation does not match pinned policy: "),
            "unexpected error: {}",
            err.message
        );
        assert_eq!(
            transport.attestation_status(),
            AttestationStatus::Unverified
        );
    }

    #[tokio::test]
    async fn secure_channel_transport_roundtrips_against_worker_server() {
        let (transport, server_task) = match start_secure_worker(vec![Ok(mock_worker_output(
            "stage-0",
        ))])
        .await
        {
            Ok(pair) => pair,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping secure_channel_transport_roundtrips_against_worker_server: loopback bind not permitted: {err}");
                return;
            }
            Err(err) => panic!("loopback worker should start: {err}"),
        };

        transport
            .establish()
            .await
            .expect("secure worker handshake should complete");
        assert_eq!(transport.attestation_status(), AttestationStatus::Verified);
        let expected_pubkey = "ab".repeat(32);
        assert_eq!(
            transport.receipt_signing_pubkey().as_deref(),
            Some(expected_pubkey.as_str())
        );

        let dir = std::env::temp_dir().join(format!(
            "cyntrisec-secure-preflight-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let policy_path = dir.join("cyntrisec-policy.json");
        let manifest_path = dir.join("model-manifest.json");
        std::fs::write(&policy_path, br#"{"policy":"test"}"#).unwrap();
        std::fs::write(&manifest_path, manifest_json()).unwrap();
        let mut config = test_config(Some(policy_path), Some(manifest_path));
        config.worker_channel_kind = WorkerChannelKind::Secure;
        let report = PreflightReport::build_required(
            &config,
            transport.attestation_status(),
            transport.receipt_signing_pubkey(),
        )
        .expect("preflight report should include secure worker pubkey");
        assert_eq!(
            report.receipt_signing_pubkey.as_deref(),
            Some(expected_pubkey.as_str())
        );

        let output = transport
            .inference(sample_inference_input())
            .await
            .expect("worker response should roundtrip");
        assert_eq!(output.output_tensor, vec![9.0, 8.0]);

        let _ = std::fs::remove_dir_all(&dir);
        server_task.abort();
    }

    #[tokio::test]
    async fn secure_channel_worker_error_keeps_channel_verified() {
        let (transport, server_task) = match start_secure_worker(vec![
            Err(ephemeral_ml_common::WorkerInferenceError::new(
                "model_oom",
                "not enough memory",
            )),
            Ok(mock_worker_output("stage-0")),
        ])
        .await
        {
            Ok(pair) => pair,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping secure_channel_worker_error_keeps_channel_verified: loopback bind not permitted: {err}");
                return;
            }
            Err(err) => panic!("loopback worker should start: {err}"),
        };

        let err = transport
            .inference(sample_inference_input())
            .await
            .expect_err("worker inference error should surface");
        assert_eq!(err.kind, WorkerErrorKind::Inference);
        assert!(err.message.contains("model_oom: not enough memory"));
        assert_eq!(transport.attestation_status(), AttestationStatus::Verified);
        let expected_pubkey = "ab".repeat(32);
        assert_eq!(
            transport.receipt_signing_pubkey().as_deref(),
            Some(expected_pubkey.as_str())
        );

        let output = transport
            .inference(sample_inference_input())
            .await
            .expect("session should remain usable after worker inference error");
        assert_eq!(output.output_tensor, vec![9.0, 8.0]);

        server_task.abort();
    }

    async fn start_secure_worker(
        responses: Vec<Result<InferenceHandlerOutput, ephemeral_ml_common::WorkerInferenceError>>,
    ) -> std::io::Result<(SecureChannelTransport, tokio::task::JoinHandle<()>)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let worker = EnclaveWorkerServer::with_worker_identity(
            Arc::new(QueueInferenceHandler::new(responses)),
            Arc::new(confidential_ml_transport::MockProvider::new()),
            Arc::new(confidential_ml_transport::MockVerifier::new()),
            [0xAB; 32],
            "stage-0",
            [0xCD; 32],
            SessionConfig::development(),
        )
        .expect("worker identity should encode");

        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept worker client");
            let _ = worker.accept_stream(stream).await;
        });

        let transport = SecureChannelTransport::new(
            addr.to_string(),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(Notify::new()),
            Duration::from_secs(2),
            Ok(ExpectedMeasurements::new(BTreeMap::new())),
        );
        Ok((transport, server_task))
    }

    fn test_config(policy_path: Option<PathBuf>, manifest_path: Option<PathBuf>) -> GatewayConfig {
        GatewayConfig {
            backend_addr: "127.0.0.1:9000".to_string(),
            default_model: "stage-0".to_string(),
            api_key: None,
            host: "127.0.0.1".to_string(),
            port: 4000,
            request_timeout_secs: 120,
            include_metadata_json: false,
            receipt_header_full: false,
            model_capabilities: "chat".to_string(),
            embedding_backend_addr: None,
            embedding_model: None,
            max_concurrent_requests: 50,
            rate_limit_per_ip: 60,
            rate_limit_global: 0,
            trust_proxy_headers: false,
            reconnect_enabled: true,
            reconnect_backoff_base_ms: 100,
            reconnect_backoff_cap_ms: 30000,
            reconnect_health_interval_secs: 5,
            worker_channel_kind: WorkerChannelKind::Http,
            preflight_policy_path: policy_path,
            preflight_manifest_path: manifest_path,
            preflight_required: true,
        }
    }

    fn manifest_json() -> Vec<u8> {
        let manifest = ModelManifest {
            model_id: "test-model".to_string(),
            version: "v1".to_string(),
            model_hash: vec![0xAB; 32],
            hash_algorithm: "sha256".to_string(),
            key_id: "kms-key".to_string(),
            tokenizer_hash: None,
            config_hash: None,
            gcs_uris: BTreeMap::new(),
            created_at: "2026-05-11T00:00:00Z".to_string(),
            model_identity: Some(ModelIdentity {
                erofs_root: Some("sha256:erofs-root".to_string()),
                dm_verity_root: None,
                hf_commit: None,
                excluded_files: vec![],
            }),
            signature: vec![0; 64],
        };
        serde_json::to_vec(&manifest).unwrap()
    }

    fn sample_inference_input() -> InferenceHandlerInput {
        InferenceHandlerInput {
            model_id: "stage-0".to_string(),
            input_data: b"user: hello".to_vec(),
            input_shape: None,
            generate: true,
            max_tokens: Some(16),
            temperature: None,
            top_p: None,
            benchmark_mode: Some("development".to_string()),
        }
    }

    fn mock_worker_output(model_id: &str) -> InferenceHandlerOutput {
        InferenceHandlerOutput {
            output_tensor: vec![9.0, 8.0],
            receipt: mock_receipt(model_id),
            generated_text: Some("worker ok".to_string()),
            boot_attestation_b64: Some("mock-attestation".to_string()),
            model_manifest_json: Some(r#"{"model_id":"stage-0"}"#.to_string()),
            air_v1_receipt_b64: Some("mock-air".to_string()),
            air_v1_model_hash_scheme: Some("sha256-manifest".to_string()),
            model_identity_coverage: None,
            bundle_url: Some("s3://customer-evidence/worker-test.bundle.tar.gz".to_string()),
            bundle_sha256: Some("c".repeat(64)),
            benchmark: None,
        }
    }

    fn shape_of(result: Result<InferenceHandlerOutput, WorkerChannelError>) -> ContractShape {
        match result {
            Ok(output) => ContractShape::Ok(OutputShape {
                output_tensor_len: output.output_tensor.len(),
                has_generated_text: output.generated_text.is_some(),
                has_boot_attestation: output.boot_attestation_b64.is_some(),
                has_model_manifest: output.model_manifest_json.is_some(),
                has_air_receipt: output.air_v1_receipt_b64.is_some(),
                has_model_hash_scheme: output.air_v1_model_hash_scheme.is_some(),
                has_identity_coverage: output.model_identity_coverage.is_some(),
                has_bundle_url: output.bundle_url.is_some(),
                has_bundle_sha256: output.bundle_sha256.is_some(),
                has_benchmark: output.benchmark.is_some(),
            }),
            Err(err) => ContractShape::Err(err.kind),
        }
    }

    fn mock_receipt(model_id: &str) -> AttestationReceipt {
        AttestationReceipt::new(
            model_id.to_string(),
            1,
            SecurityMode::GatewayOnly,
            EnclaveMeasurements::new(vec![0u8; 48], vec![0u8; 48], vec![0u8; 48]),
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            "mock".to_string(),
            ephemeral_ml_client::current_timestamp().unwrap_or(0),
            model_id.to_string(),
            "mock".to_string(),
            0,
            0,
        )
    }
}
