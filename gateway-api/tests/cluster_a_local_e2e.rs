//! Local end-to-end test for the worker pivot.
//!
//! This runs the protocol surface without AWS credentials: OpenAI-compatible
//! HTTP enters the gateway, the secure worker channel reaches a loopback
//! WorkerServer, bundle emission speaks the CBOR egress protocol to a
//! relay-egress handler, and the final response exposes the bundle URL/hash.

#![cfg(feature = "mock")]

use std::collections::BTreeMap;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use confidential_ml_transport::{MockProvider, MockVerifier, SessionConfig};
use cyntrisec_relay_egress::backend::{AwsBackend, AwsBackendFuture, PutObjectResult};
use cyntrisec_relay_egress::{handle_stream, EgressAllowlist};
use ephemeral_ml_client::SecureEnclaveClient;
use ephemeral_ml_common::air_receipt::{build_air_v1, AirReceiptClaims};
use ephemeral_ml_common::{
    AttestationReceipt, EgressClient, EgressError, EgressOkResponse, EgressRequest, EgressResponse,
    EnclaveMeasurements, InferenceHandlerInput, InferenceHandlerOutput, ModelManifest,
    ReceiptSigningKey, S3PutObjectRequest, S3PutObjectResponse, SecurityMode, WorkerInferenceError,
};
use ephemeral_ml_enclave::bundle_emit::{BundleAssembler, BundleAssemblerConfig};
use ephemeral_ml_enclave::egress_vsock_client::send_request_over_stream;
use ephemeral_ml_enclave::worker_server::{InferenceHandler, WorkerServer};
use ephemeralml_gateway::config::{GatewayConfig, WorkerChannelKind};
use ephemeralml_gateway::state::AppState;
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream};
use tower::ServiceExt;

#[derive(Default)]
struct CapturingAwsBackend {
    s3_requests: Mutex<Vec<S3PutObjectRequest>>,
}

impl AwsBackend for CapturingAwsBackend {
    fn kms_decrypt<'a>(
        &'a self,
        _req: ephemeral_ml_common::KmsDecryptRequest,
    ) -> AwsBackendFuture<'a, Vec<u8>> {
        Box::pin(async move { Ok(b"plaintext".to_vec()) })
    }

    fn s3_put_object<'a>(
        &'a self,
        req: S3PutObjectRequest,
    ) -> AwsBackendFuture<'a, PutObjectResult> {
        Box::pin(async move {
            self.s3_requests.lock().unwrap().push(req);
            Ok(PutObjectResult {
                etag: "\"local-e2e\"".to_string(),
                version_id: Some("local-version".to_string()),
            })
        })
    }
}

#[derive(Clone)]
struct TcpEgressClient {
    addr: SocketAddr,
}

impl TcpEgressClient {
    async fn send(&self, request: EgressRequest) -> Result<EgressResponse, EgressError> {
        let stream = TcpStream::connect(self.addr).await.map_err(|err| {
            EgressError::new(
                "egress.transport_unreachable",
                format!("failed to connect to local relay-egress stub: {err}"),
            )
        })?;
        send_request_over_stream(stream, request, 2 * 1024 * 1024, Duration::from_secs(2)).await
    }
}

#[async_trait]
impl EgressClient for TcpEgressClient {
    async fn kms_decrypt(
        &self,
        req: ephemeral_ml_common::KmsDecryptRequest,
    ) -> Result<Vec<u8>, EgressError> {
        match self.send(EgressRequest::KmsDecrypt(req)).await? {
            EgressResponse::Ok(EgressOkResponse::KmsDecrypt(resp)) => Ok(resp.plaintext),
            EgressResponse::Ok(other) => Err(EgressError::new(
                "egress.protocol",
                format!("unexpected local KMS response: {other:?}"),
            )),
            EgressResponse::Err(err) => Err(err),
        }
    }

    async fn s3_put_object(
        &self,
        req: S3PutObjectRequest,
    ) -> Result<S3PutObjectResponse, EgressError> {
        match self.send(EgressRequest::S3PutObject(req)).await? {
            EgressResponse::Ok(EgressOkResponse::S3PutObject(resp)) => Ok(resp),
            EgressResponse::Ok(other) => Err(EgressError::new(
                "egress.protocol",
                format!("unexpected local S3 response: {other:?}"),
            )),
            EgressResponse::Err(err) => Err(err),
        }
    }
}

struct LocalInferenceHandler;

#[async_trait]
impl InferenceHandler for LocalInferenceHandler {
    async fn handle(
        &self,
        input: InferenceHandlerInput,
    ) -> Result<InferenceHandlerOutput, WorkerInferenceError> {
        Ok(test_output(&input.model_id))
    }
}

#[tokio::test]
async fn local_proxy_worker_egress_bundle_e2e() {
    let (egress_addr, backend, egress_task) = match start_relay_egress_stub().await {
        Ok(parts) => parts,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping local_proxy_worker_egress_bundle_e2e: loopback bind not permitted: {err}"
            );
            return;
        }
        Err(err) => panic!("failed to start relay-egress stub: {err}"),
    };

    let (worker_addr, worker_task) = match start_worker(egress_addr).await {
        Ok(parts) => parts,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping local_proxy_worker_egress_bundle_e2e: loopback bind not permitted: {err}"
            );
            egress_task.abort();
            return;
        }
        Err(err) => panic!("failed to start worker: {err}"),
    };

    let app = test_router(worker_addr);
    let response = app
        .oneshot(json_request(
            "/v1/chat/completions",
            serde_json::json!({
                "model": "gpt-4",
                "messages": [{"role": "user", "content": "prove the bundle path"}],
                "max_tokens": 16
            }),
        ))
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let headers = response.headers().clone();
    let body = body_json(response).await;
    assert_eq!(body["choices"][0]["message"]["content"], "local e2e ok");

    let bundle_url = headers
        .get("x-cyntrisec-bundle-url")
        .expect("bundle URL header")
        .to_str()
        .unwrap()
        .to_string();
    let bundle_sha256 = headers
        .get("x-cyntrisec-bundle-sha256")
        .expect("bundle sha header")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(bundle_sha256.len(), 64);
    assert!(bundle_sha256.chars().all(|c| c.is_ascii_hexdigit()));

    let requests = backend.s3_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let s3 = &requests[0];
    assert_eq!(s3.bucket, "customer-evidence");
    assert!(s3.key.starts_with("bundles/tenant=tenant-a/"));
    assert_eq!(bundle_url, format!("s3://customer-evidence/{}", s3.key));
    assert_eq!(bundle_sha256, hex::encode(Sha256::digest(&s3.body)));

    let files = unpack_bundle(&s3.body);
    let names = files
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "air.cbor",
            "attestation.cbor",
            "cyntrisec-policy.json",
            "model-manifest.json",
            "runtime-passport.json",
            "verification-report.json",
            "vendor-evidence/aws-nitro-attestation.cbor",
            "SHA256SUMS",
        ]
    );
    let sums = String::from_utf8(find_file(&files, "SHA256SUMS").to_vec()).unwrap();
    for (name, bytes) in files.iter().filter(|(name, _)| name != "SHA256SUMS") {
        let expected_line = format!("{}  {name}\n", hex::encode(Sha256::digest(bytes)));
        assert!(
            sums.contains(&expected_line),
            "missing SHA256SUMS line for {name}"
        );
    }

    worker_task.abort();
    egress_task.abort();
}

async fn start_relay_egress_stub() -> std::io::Result<(
    SocketAddr,
    Arc<CapturingAwsBackend>,
    tokio::task::JoinHandle<()>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let backend = Arc::new(CapturingAwsBackend::default());
    let allowlist = EgressAllowlist::new(
        ["customer-evidence".to_string()].into_iter().collect(),
        ["arn:aws:kms:us-east-1:111122223333:key/evidence".to_string()]
            .into_iter()
            .collect(),
    );

    let task_backend = backend.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("accept egress request");
            let backend: Arc<dyn AwsBackend> = task_backend.clone();
            let allowlist = allowlist.clone();
            tokio::spawn(async move {
                handle_stream(
                    stream,
                    backend,
                    allowlist,
                    2 * 1024 * 1024,
                    Duration::from_secs(2),
                )
                .await
                .expect("relay-egress handler should complete");
            });
        }
    });
    Ok((addr, backend, task))
}

async fn start_worker(
    egress_addr: SocketAddr,
) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let egress = Arc::new(TcpEgressClient { addr: egress_addr });
    let bundle_assembler = Arc::new(BundleAssembler::new(
        egress,
        BundleAssemblerConfig {
            bucket: "customer-evidence".to_string(),
            key_prefix: Some("bundles".to_string()),
            tenant_id: "tenant-a".to_string(),
            session_id: "session-local".to_string(),
            policy_json: br#"{"PCR0":"00","PCR1":"11","PCR2":"22"}"#.to_vec(),
            runtime_passport_json: br#"{"schema_version":"1","passport_id":"local-e2e"}"#.to_vec(),
            fallback_model_manifest_json: None,
            kms_key_arn: Some("arn:aws:kms:us-east-1:111122223333:key/evidence".to_string()),
        },
    ));
    let worker = WorkerServer::with_worker_identity(
        Arc::new(LocalInferenceHandler),
        Arc::new(MockProvider::new()),
        Arc::new(MockVerifier::new()),
        [0xAB; 32],
        "stage-0",
        [0xCD; 32],
        SessionConfig::development(),
    )
    .unwrap()
    .with_bundle_assembler(bundle_assembler);

    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept worker channel");
        let _ = worker.accept_stream(stream).await;
    });
    Ok((addr, task))
}

fn test_router(worker_addr: SocketAddr) -> axum::Router {
    let config = GatewayConfig {
        backend_addr: worker_addr.to_string(),
        default_model: "stage-0".to_string(),
        api_key: None,
        host: "127.0.0.1".to_string(),
        port: 0,
        request_timeout_secs: 5,
        include_metadata_json: true,
        receipt_header_full: false,
        model_capabilities: "chat".to_string(),
        embedding_backend_addr: None,
        embedding_model: None,
        reconnect_enabled: false,
        reconnect_backoff_base_ms: 100,
        reconnect_backoff_cap_ms: 30_000,
        reconnect_health_interval_secs: 5,
        worker_channel_kind: WorkerChannelKind::Secure,
        preflight_policy_path: None,
        preflight_manifest_path: None,
        preflight_required: false,
        max_concurrent_requests: 50,
        rate_limit_per_ip: 0,
        rate_limit_global: 0,
        trust_proxy_headers: false,
        cors_origins: vec![],
    };
    let client = SecureEnclaveClient::new("local-e2e".to_string());
    let state = AppState::new(client, config, None);
    ephemeralml_gateway::build_router(state)
}

fn json_request(uri: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

async fn body_json(response: axum::http::Response<axum::body::Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn test_output(model_id: &str) -> InferenceHandlerOutput {
    let key = ReceiptSigningKey::generate().unwrap();
    let mut receipt = AttestationReceipt::new(
        uuid::Uuid::new_v4().to_string(),
        42,
        SecurityMode::GatewayOnly,
        EnclaveMeasurements::new(vec![0; 48], vec![1; 48], vec![2; 48]),
        [0xAA; 32],
        [0xBB; 32],
        [0xCC; 32],
        "v1".to_string(),
        1_700_000_000,
        model_id.to_string(),
        "v1".to_string(),
        7,
        16,
    );
    receipt.attestation_source = Some("nitro-pcr".to_string());
    receipt.sign(&key).unwrap();

    let model_hash = [0xDD; 32];
    let air_claims = AirReceiptClaims::from_legacy_with_scheme(
        &receipt,
        "issuer.test".to_string(),
        model_hash,
        Some("sha256-manifest".to_string()),
    )
    .unwrap();
    let air_cbor = build_air_v1(&air_claims, &key).unwrap();
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

    InferenceHandlerOutput {
        output_tensor: vec![1.0, 2.0],
        receipt,
        generated_text: Some("local e2e ok".to_string()),
        boot_attestation_b64: Some(
            base64::engine::general_purpose::STANDARD.encode(b"attestation-cbor"),
        ),
        model_manifest_json: Some(serde_json::to_string(&manifest).unwrap()),
        air_v1_receipt_b64: Some(base64::engine::general_purpose::STANDARD.encode(air_cbor)),
        air_v1_model_hash_scheme: Some("sha256-manifest".to_string()),
        model_identity_coverage: None,
        bundle_url: None,
        bundle_sha256: None,
        benchmark: None,
    }
}

fn unpack_bundle(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let decoder = GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut files = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().to_string();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        files.push((name, bytes));
    }
    files
}

fn find_file<'a>(files: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
    files
        .iter()
        .find(|(path, _)| path == name)
        .map(|(_, bytes)| bytes.as_slice())
        .unwrap()
}
