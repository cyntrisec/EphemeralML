//! Attested worker protocol carried over `confidential-ml-transport`.
//!
//! Wire format v1 is JSON inside SecureChannel `Data` messages. Schema version
//! is implicit in the SecureChannel handshake parameters; future CBOR versions
//! should be negotiated at handshake time, not by adding in-frame magic bytes.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex};

use crate::bundle_emit::BundleAssembler;
use async_trait::async_trait;
use bytes::Bytes;
use confidential_ml_transport::error::AttestError;
use confidential_ml_transport::{
    AttestationDocument, AttestationProvider as TransportAttestationProvider,
    AttestationVerifier as TransportAttestationVerifier, Error as TransportError, Message,
    SecureChannel, SessionConfig,
};
use ephemeral_ml_common::{
    InferenceHandlerInput, InferenceHandlerOutput, WorkerAttestationUserData, WorkerInferenceError,
    WorkerResponse,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite};

const MAX_INPUT_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
const DEFAULT_MAX_TOKENS: usize = 256;
const MAX_TOKENS_LIMIT: usize = 4096;
const DEFAULT_TEMPERATURE: f64 = 0.7;
const DEFAULT_TOP_P: f64 = 0.9;

pub type WorkerServerResult<T> = std::result::Result<T, WorkerServerError>;

#[derive(Debug)]
pub enum WorkerServerError {
    AttestationUserData(String),
    Channel(TransportError),
    Io(std::io::Error),
    PayloadDecode(serde_json::Error),
    ResponseEncode(serde_json::Error),
    Protocol(String),
}

impl fmt::Display for WorkerServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttestationUserData(err) => write!(f, "attestation user_data error: {err}"),
            Self::Channel(err) => write!(f, "secure channel error: {err}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::PayloadDecode(err) => write!(f, "worker payload decode error: {err}"),
            Self::ResponseEncode(err) => write!(f, "worker response encode error: {err}"),
            Self::Protocol(err) => write!(f, "worker protocol error: {err}"),
        }
    }
}

impl std::error::Error for WorkerServerError {}

impl From<TransportError> for WorkerServerError {
    fn from(err: TransportError) -> Self {
        Self::Channel(err)
    }
}

impl From<std::io::Error> for WorkerServerError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[async_trait]
pub trait InferenceHandler: Send + Sync {
    async fn handle(
        &self,
        input: InferenceHandlerInput,
    ) -> std::result::Result<InferenceHandlerOutput, WorkerInferenceError>;
}

#[derive(Clone, Debug, Default)]
pub struct WorkerEvidence {
    pub boot_attestation_bytes: Option<Vec<u8>>,
    pub model_manifest_json: Option<String>,
    pub model_hash: Option<[u8; 32]>,
    pub model_hash_scheme: Option<String>,
    pub model_identity_coverage: Option<BTreeMap<String, bool>>,
    pub platform_evidence_hash: Option<[u8; 32]>,
    pub receipt_issuer: String,
}

pub struct CandleWorkerHandler<P: crate::attestation::AttestationProvider> {
    engine: crate::candle_engine::CandleInferenceEngine,
    attestation_provider: P,
    state: Mutex<ephemeral_ml_common::transport_types::ConnectionState>,
    evidence: WorkerEvidence,
}

impl<P: crate::attestation::AttestationProvider> CandleWorkerHandler<P> {
    pub fn new(
        engine: crate::candle_engine::CandleInferenceEngine,
        attestation_provider: P,
        receipt_key: ephemeral_ml_common::ReceiptSigningKey,
        boot_attestation_hash: [u8; 32],
        evidence: WorkerEvidence,
    ) -> Self {
        let receipt_pk = receipt_key.public_key_bytes();
        let session_id = hex::encode(&receipt_pk[..16]);
        let state = ephemeral_ml_common::transport_types::ConnectionState::new(
            session_id,
            receipt_key,
            boot_attestation_hash,
            "worker".to_string(),
            1,
        )
        .with_platform_evidence_hash_opt(evidence.platform_evidence_hash);
        Self {
            engine,
            attestation_provider,
            state: Mutex::new(state),
            evidence,
        }
    }
}

#[async_trait]
impl<P> InferenceHandler for CandleWorkerHandler<P>
where
    P: crate::attestation::AttestationProvider + Send + Sync,
{
    async fn handle(
        &self,
        input: InferenceHandlerInput,
    ) -> std::result::Result<InferenceHandlerOutput, WorkerInferenceError> {
        self.handle_inner(input)
            .map_err(|err| WorkerInferenceError::new("inference.failed", err))
    }
}

impl<P> CandleWorkerHandler<P>
where
    P: crate::attestation::AttestationProvider + Send + Sync,
{
    fn handle_inner(&self, input: InferenceHandlerInput) -> Result<InferenceHandlerOutput, String> {
        if input.input_data.is_empty() {
            return Err("input payload is empty".to_string());
        }
        if input.input_data.len() > MAX_INPUT_PAYLOAD_SIZE {
            return Err(format!(
                "input payload too large: {} bytes (max {MAX_INPUT_PAYLOAD_SIZE})",
                input.input_data.len()
            ));
        }

        let request_bytes =
            serde_json::to_vec(&input).map_err(|err| format!("request encode failed: {err}"))?;
        let request_hash: [u8; 32] = Sha256::digest(&request_bytes).into();
        let started = std::time::Instant::now();
        let (output_tensor, generated_text) = if input.generate {
            let max_tokens = input
                .max_tokens
                .unwrap_or(DEFAULT_MAX_TOKENS)
                .min(MAX_TOKENS_LIMIT);
            let temperature = input.temperature.unwrap_or(DEFAULT_TEMPERATURE);
            let top_p = input.top_p.unwrap_or(DEFAULT_TOP_P);
            if temperature < 0.0 {
                return Err(format!("temperature must be >= 0, got {temperature}"));
            }
            if !(0.0..=1.0).contains(&top_p) {
                return Err(format!("top_p must be in [0.0, 1.0], got {top_p}"));
            }

            let generated = self
                .engine
                .execute_by_id_generate(
                    &input.model_id,
                    &input.input_data,
                    max_tokens,
                    temperature,
                    top_p,
                )
                .map_err(|err| err.to_string())?;
            let token_floats = generated
                .token_ids
                .iter()
                .map(|token| *token as f32)
                .collect();
            (token_floats, Some(generated.text))
        } else {
            let output = self
                .engine
                .execute_by_id(&input.model_id, &input.input_data)
                .map_err(|err| err.to_string())?;
            (output, None)
        };
        let inference_ms = started.elapsed().as_millis() as u64;
        let output_bytes: Vec<u8> = output_tensor
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        let response_hash: [u8; 32] = Sha256::digest(&output_bytes).into();

        let (receipt_model_id, receipt_model_version) = if let Some(manifest_json) =
            self.evidence.model_manifest_json.as_ref()
        {
            let manifest = ephemeral_ml_common::ModelManifest::from_json(manifest_json.as_bytes())
                .map_err(|err| format!("model manifest present but failed to parse: {err}"))?;
            (manifest.model_id, manifest.version)
        } else {
            (input.model_id.clone(), "1.0".to_string())
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| "worker receipt state lock poisoned".to_string())?;
        state.model_id = receipt_model_id.clone();
        let mut receipt = crate::receipt::ReceiptBuilder::build_with_hashes(
            &mut state,
            &self.attestation_provider,
            request_hash,
            response_hash,
            receipt_model_id,
            receipt_model_version,
            inference_ms,
            0,
        )
        .map_err(|err| format!("receipt build failed: {err}"))?;
        receipt.destroy_evidence = Some(ephemeral_ml_common::DestroyEvidence {
            timestamp: ephemeral_ml_common::current_timestamp()
                .map_err(|err| format!("destroy evidence timestamp failed: {err}"))?,
            actions: vec![
                ephemeral_ml_common::DestroyAction {
                    target: "worker_output_bytes".to_string(),
                    mechanism: "drop_on_scope_exit".to_string(),
                },
                ephemeral_ml_common::DestroyAction {
                    target: "secure_channel_session".to_string(),
                    mechanism: "rekeyed_per_session".to_string(),
                },
            ],
        });
        receipt
            .sign(&state.receipt_signing_key)
            .map_err(|err| format!("receipt sign failed: {err}"))?;

        let air_v1_receipt_b64 = if let Some(model_hash) = self.evidence.model_hash {
            match ephemeral_ml_common::air_receipt::AirReceiptClaims::from_legacy_with_scheme(
                &receipt,
                self.evidence.receipt_issuer.clone(),
                model_hash,
                self.evidence.model_hash_scheme.clone(),
            )
            .and_then(|claims| {
                ephemeral_ml_common::air_receipt::build_air_v1(&claims, &state.receipt_signing_key)
            }) {
                Ok(bytes) => {
                    use base64::Engine as _;
                    Some(base64::engine::general_purpose::STANDARD.encode(bytes))
                }
                Err(err) => {
                    tracing::warn!(error = %err, "AIR v1 receipt build failed for worker response");
                    None
                }
            }
        } else {
            None
        };
        drop(state);

        let boot_attestation_b64 = self.evidence.boot_attestation_bytes.as_ref().map(|bytes| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(bytes)
        });

        Ok(InferenceHandlerOutput {
            output_tensor,
            receipt,
            generated_text,
            boot_attestation_b64,
            model_manifest_json: self.evidence.model_manifest_json.clone(),
            air_v1_receipt_b64,
            air_v1_model_hash_scheme: self.evidence.model_hash_scheme.clone(),
            model_identity_coverage: self.evidence.model_identity_coverage.clone(),
            bundle_url: None,
            bundle_sha256: None,
            benchmark: None,
        })
    }
}

#[derive(Clone)]
pub struct WorkerServer {
    handler: Arc<dyn InferenceHandler>,
    bundle_assembler: Option<Arc<BundleAssembler>>,
    attestation_provider: Arc<dyn TransportAttestationProvider>,
    attestation_verifier: Arc<dyn TransportAttestationVerifier>,
    user_data: Arc<Vec<u8>>,
    session_config: SessionConfig,
}

impl WorkerServer {
    pub fn new(
        handler: Arc<dyn InferenceHandler>,
        attestation_provider: Arc<dyn TransportAttestationProvider>,
        attestation_verifier: Arc<dyn TransportAttestationVerifier>,
        user_data: Vec<u8>,
        session_config: SessionConfig,
    ) -> Self {
        Self {
            handler,
            bundle_assembler: None,
            attestation_provider,
            attestation_verifier,
            user_data: Arc::new(user_data),
            session_config,
        }
    }

    pub fn with_bundle_assembler(mut self, bundle_assembler: Arc<BundleAssembler>) -> Self {
        self.bundle_assembler = Some(bundle_assembler);
        self
    }

    pub fn with_worker_identity(
        handler: Arc<dyn InferenceHandler>,
        attestation_provider: Arc<dyn TransportAttestationProvider>,
        attestation_verifier: Arc<dyn TransportAttestationVerifier>,
        receipt_signing_pubkey: [u8; 32],
        model_id: impl Into<String>,
        model_hash: [u8; 32],
        session_config: SessionConfig,
    ) -> WorkerServerResult<Self> {
        let user_data =
            WorkerAttestationUserData::new(receipt_signing_pubkey, model_id.into(), model_hash)
                .to_cbor()
                .map_err(|err| WorkerServerError::AttestationUserData(err.to_string()))?;
        Ok(Self::new(
            handler,
            attestation_provider,
            attestation_verifier,
            user_data,
            session_config,
        ))
    }

    pub async fn accept_stream<S>(&self, stream: S) -> WorkerServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let provider = FixedUserDataProvider {
            inner: Arc::clone(&self.attestation_provider),
            user_data: Arc::clone(&self.user_data),
        };

        let channel = SecureChannel::accept_with_attestation(
            stream,
            &provider,
            self.attestation_verifier.as_ref(),
            self.session_config.clone(),
        )
        .await?;

        self.handle_session(channel).await
    }

    pub async fn serve_accept_loop<F, Fut, S>(&self, mut accept_next: F) -> WorkerServerResult<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = std::io::Result<S>>,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        loop {
            let stream = accept_next().await?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(err) = server.accept_stream(stream).await {
                    tracing::warn!(error = %err, "worker session closed");
                }
            });
        }
    }

    pub async fn handle_session<S>(&self, mut channel: SecureChannel<S>) -> WorkerServerResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let message = channel.recv().await?;
            match message {
                Message::Data(frame) => {
                    let input: InferenceHandlerInput =
                        serde_json::from_slice(&frame).map_err(WorkerServerError::PayloadDecode)?;
                    let response = match self.handler.handle(input).await {
                        Ok(mut output) => {
                            self.attach_bundle_metadata(&mut output).await;
                            WorkerResponse::Ok(output)
                        }
                        Err(err) => WorkerResponse::Err(err),
                    };
                    let response_bytes =
                        serde_json::to_vec(&response).map_err(WorkerServerError::ResponseEncode)?;
                    channel.send(Bytes::from(response_bytes)).await?;
                }
                Message::Heartbeat => continue,
                Message::Shutdown => return Ok(()),
                Message::Tensor(_) => {
                    return Err(WorkerServerError::Protocol(
                        "worker protocol expects Data frames, received Tensor".to_string(),
                    ));
                }
                Message::Error(err) => {
                    return Err(WorkerServerError::Protocol(format!(
                        "peer sent channel error: {err}"
                    )));
                }
            }
        }
    }

    async fn attach_bundle_metadata(&self, output: &mut InferenceHandlerOutput) {
        if let Some(bundle_assembler) = &self.bundle_assembler {
            match bundle_assembler.emit(output).await {
                Ok(emission) => {
                    output.bundle_url = Some(emission.bundle_url);
                    output.bundle_sha256 = Some(emission.bundle_sha256);
                }
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        receipt_id = %output.receipt.receipt_id,
                        "receipt bundle emission failed; returning inference response without bundle"
                    );
                }
            }
        }
    }
}

struct FixedUserDataProvider {
    inner: Arc<dyn TransportAttestationProvider>,
    user_data: Arc<Vec<u8>>,
}

#[async_trait]
impl TransportAttestationProvider for FixedUserDataProvider {
    async fn attest(
        &self,
        _user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> std::result::Result<AttestationDocument, AttestError> {
        self.inner
            .attest(Some(self.user_data.as_ref().as_slice()), nonce, public_key)
            .await
    }
}

#[cfg(all(test, feature = "mock"))]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, VecDeque};
    use std::sync::Mutex;
    use std::time::Duration;

    use crate::bundle_emit::{BundleAssembler, BundleAssemblerConfig};
    use base64::Engine;
    use confidential_ml_transport::{MockProvider, MockVerifier};
    use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
    use ephemeral_ml_common::egress_client::mock::MockEgressClient;
    use ephemeral_ml_common::{
        AttestationReceipt, EgressClient, EgressError, EnclaveMeasurements, KmsDecryptRequest,
        ModelManifest, ReceiptSigningKey, S3PutObjectRequest, S3PutObjectResponse, SecurityMode,
    };

    struct FailingEgressClient;

    #[async_trait]
    impl EgressClient for FailingEgressClient {
        async fn kms_decrypt(
            &self,
            _req: KmsDecryptRequest,
        ) -> std::result::Result<Vec<u8>, EgressError> {
            Err(EgressError::new("kms.unexpected", "not used in this test"))
        }

        async fn s3_put_object(
            &self,
            _req: S3PutObjectRequest,
        ) -> std::result::Result<S3PutObjectResponse, EgressError> {
            Err(EgressError::new("s3.access_denied", "mock denied"))
        }
    }

    struct QueueHandler {
        responses:
            Mutex<VecDeque<std::result::Result<InferenceHandlerOutput, WorkerInferenceError>>>,
    }

    impl QueueHandler {
        fn new(
            responses: Vec<std::result::Result<InferenceHandlerOutput, WorkerInferenceError>>,
        ) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from(responses)),
            }
        }
    }

    #[async_trait]
    impl InferenceHandler for QueueHandler {
        async fn handle(
            &self,
            input: InferenceHandlerInput,
        ) -> std::result::Result<InferenceHandlerOutput, WorkerInferenceError> {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Ok(sample_output(&input.model_id)))
        }
    }

    fn sample_input() -> InferenceHandlerInput {
        InferenceHandlerInput {
            model_id: "model-a".to_string(),
            input_data: b"hello".to_vec(),
            input_shape: None,
            generate: false,
            max_tokens: None,
            temperature: None,
            top_p: None,
            benchmark_mode: None,
        }
    }

    fn sample_output(model_id: &str) -> InferenceHandlerOutput {
        InferenceHandlerOutput {
            output_tensor: vec![1.0, 2.0, 3.0],
            receipt: AttestationReceipt::new(
                "receipt-1".to_string(),
                1,
                SecurityMode::GatewayOnly,
                EnclaveMeasurements::new(vec![0; 48], vec![1; 48], vec![2; 48]),
                [0; 32],
                [1; 32],
                [2; 32],
                "v1".to_string(),
                0,
                model_id.to_string(),
                "v1".to_string(),
                0,
                0,
            ),
            generated_text: Some("ok".to_string()),
            boot_attestation_b64: None,
            model_manifest_json: None,
            air_v1_receipt_b64: None,
            air_v1_model_hash_scheme: None,
            model_identity_coverage: None,
            bundle_url: None,
            bundle_sha256: None,
            benchmark: None,
        }
    }

    fn sample_bundle_output(model_id: &str) -> InferenceHandlerOutput {
        let key = ReceiptSigningKey::generate().unwrap();
        let model_hash = [0xDD; 32];
        let mut output = sample_output(model_id);
        output.receipt.receipt_id = uuid::Uuid::new_v4().to_string();
        output.receipt.model_id = model_id.to_string();
        output.receipt.sign(&key).unwrap();
        let claims = AirReceiptClaims::from_legacy_with_scheme(
            &output.receipt,
            "issuer.test".to_string(),
            model_hash,
            Some("sha256-manifest".to_string()),
        )
        .unwrap();
        let manifest = ModelManifest {
            model_id: model_id.to_string(),
            version: "v1".to_string(),
            model_hash: model_hash.to_vec(),
            hash_algorithm: "sha256".to_string(),
            key_id: "alias/model".to_string(),
            tokenizer_hash: None,
            config_hash: None,
            gcs_uris: BTreeMap::new(),
            created_at: "2026-05-12T00:00:00Z".to_string(),
            model_identity: None,
            signature: vec![0; 64],
        };
        output.boot_attestation_b64 =
            Some(base64::engine::general_purpose::STANDARD.encode(b"attestation-cbor"));
        output.model_manifest_json = Some(serde_json::to_string(&manifest).unwrap());
        output.air_v1_receipt_b64 = Some(
            base64::engine::general_purpose::STANDARD.encode(build_air_v1(&claims, &key).unwrap()),
        );
        output.air_v1_model_hash_scheme = Some("sha256-manifest".to_string());
        output
    }

    fn test_server(handler: Arc<dyn InferenceHandler>) -> WorkerServer {
        WorkerServer::with_worker_identity(
            handler,
            Arc::new(MockProvider::new()),
            Arc::new(MockVerifier::new()),
            [7; 32],
            "model-a",
            [8; 32],
            SessionConfig::development(),
        )
        .unwrap()
    }

    fn failing_bundle_assembler() -> Arc<BundleAssembler> {
        Arc::new(BundleAssembler::new(
            Arc::new(FailingEgressClient),
            BundleAssemblerConfig {
                bucket: "customer-evidence".to_string(),
                key_prefix: None,
                tenant_id: "tenant-a".to_string(),
                session_id: "session-a".to_string(),
                policy_json: br#"{"PCR0":"00"}"#.to_vec(),
                runtime_passport_json: br#"{"schema_version":"1","passport_id":"rpass-test"}"#
                    .to_vec(),
                fallback_model_manifest_json: None,
                kms_key_arn: None,
            },
        ))
    }

    fn bundle_assembler(egress: Arc<dyn EgressClient>) -> Arc<BundleAssembler> {
        Arc::new(BundleAssembler::new(
            egress,
            BundleAssemblerConfig {
                bucket: "customer-evidence".to_string(),
                key_prefix: Some("bundles".to_string()),
                tenant_id: "tenant-a".to_string(),
                session_id: "session-a".to_string(),
                policy_json: br#"{"PCR0":"00"}"#.to_vec(),
                runtime_passport_json: br#"{"schema_version":"1","passport_id":"rpass-test"}"#
                    .to_vec(),
                fallback_model_manifest_json: None,
                kms_key_arn: None,
            },
        ))
    }

    async fn connect_pair(
        server: WorkerServer,
    ) -> (
        SecureChannel<tokio::io::DuplexStream>,
        tokio::task::JoinHandle<WorkerServerResult<()>>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move { server.accept_stream(server_io).await });
        let channel = SecureChannel::connect_with_attestation(
            client_io,
            &MockProvider::new(),
            &MockVerifier::new(),
            SessionConfig::development(),
        )
        .await
        .unwrap();
        (channel, server_task)
    }

    async fn send_request(channel: &mut SecureChannel<tokio::io::DuplexStream>) -> WorkerResponse {
        let bytes = serde_json::to_vec(&sample_input()).unwrap();
        channel.send(Bytes::from(bytes)).await.unwrap();
        match channel.recv().await.unwrap() {
            Message::Data(data) => serde_json::from_slice(&data).unwrap(),
            other => panic!("expected Data response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn worker_session_roundtrips_request_and_user_data() {
        let server = test_server(Arc::new(QueueHandler::new(vec![Ok(sample_output(
            "model-a",
        ))])));
        let (mut channel, server_task) = connect_pair(server).await;

        let user_data = channel
            .peer_attestation()
            .and_then(|attestation| attestation.user_data.as_deref())
            .expect("server attestation should carry worker user_data");
        let decoded = WorkerAttestationUserData::from_cbor(user_data).unwrap();
        assert_eq!(decoded.receipt_signing_pubkey, [7; 32]);
        assert_eq!(decoded.model_id, "model-a");
        assert_eq!(decoded.model_hash, [8; 32]);

        match send_request(&mut channel).await {
            WorkerResponse::Ok(output) => {
                assert_eq!(output.output_tensor, vec![1.0, 2.0, 3.0]);
                assert_eq!(output.generated_text.as_deref(), Some("ok"));
            }
            WorkerResponse::Err(err) => panic!("unexpected inference error: {err:?}"),
        }

        channel.shutdown().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn inference_error_returns_response_and_keeps_session_open() {
        let server = test_server(Arc::new(QueueHandler::new(vec![
            Err(WorkerInferenceError::new("oom", "model ran out of memory")),
            Ok(sample_output("model-a")),
        ])));
        let (mut channel, server_task) = connect_pair(server).await;

        match send_request(&mut channel).await {
            WorkerResponse::Err(err) => {
                assert_eq!(err.code, "oom");
                assert_eq!(err.message, "model ran out of memory");
            }
            WorkerResponse::Ok(_) => panic!("expected inference error response"),
        }

        match send_request(&mut channel).await {
            WorkerResponse::Ok(output) => assert_eq!(output.output_tensor, vec![1.0, 2.0, 3.0]),
            WorkerResponse::Err(err) => {
                panic!("session should stay open after inference error: {err:?}")
            }
        }

        channel.shutdown().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn bundle_egress_error_returns_inference_without_bundle() {
        let server = test_server(Arc::new(QueueHandler::new(vec![Ok(sample_bundle_output(
            "model-a",
        ))])))
        .with_bundle_assembler(failing_bundle_assembler());
        let (mut channel, server_task) = connect_pair(server).await;

        match send_request(&mut channel).await {
            WorkerResponse::Ok(output) => {
                assert_eq!(output.output_tensor, vec![1.0, 2.0, 3.0]);
                assert!(output.bundle_url.is_none());
                assert!(output.bundle_sha256.is_none());
            }
            WorkerResponse::Err(err) => {
                panic!("bundle egress failure must not fail inference: {err:?}")
            }
        }

        channel.shutdown().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn bundle_success_adds_metadata_to_worker_response() {
        let egress = Arc::new(MockEgressClient::default());
        let server = test_server(Arc::new(QueueHandler::new(vec![Ok(sample_bundle_output(
            "model-a",
        ))])))
        .with_bundle_assembler(bundle_assembler(egress.clone()));
        let (mut channel, server_task) = connect_pair(server).await;

        match send_request(&mut channel).await {
            WorkerResponse::Ok(output) => {
                assert!(output
                    .bundle_url
                    .as_deref()
                    .unwrap()
                    .starts_with("s3://customer-evidence/bundles/tenant=tenant-a/"));
                assert_eq!(output.bundle_sha256.as_ref().unwrap().len(), 64);
            }
            WorkerResponse::Err(err) => panic!("unexpected inference error: {err:?}"),
        }
        assert_eq!(egress.s3_requests.lock().unwrap().len(), 1);

        channel.shutdown().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn malformed_payload_closes_session() {
        let server = test_server(Arc::new(QueueHandler::new(vec![])));
        let (mut channel, server_task) = connect_pair(server).await;

        channel
            .send(Bytes::from_static(b"{not valid json"))
            .await
            .unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(WorkerServerError::PayloadDecode(_))));
    }
}
