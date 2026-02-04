use crate::{
    inference_handler::InferenceHandler, session_manager::SessionManager, AttestationProvider,
    InferenceEngine,
};
use std::sync::Arc;

#[cfg(feature = "production")]
use crate::{session_manager::EnclaveSession, EnclaveError, EphemeralError, Result};
#[cfg(feature = "production")]
use ephemeral_ml_common::protocol::{ClientHello, ServerHello, PROTOCOL_VERSION_V1};
#[cfg(feature = "production")]
use ephemeral_ml_common::{HPKESession, MessageType, VSockMessage};
#[cfg(feature = "production")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(feature = "production")]
use sha2::Digest;
#[cfg(feature = "production")]
use tokio_vsock::{VsockListener, VsockStream};

#[allow(dead_code)]
pub struct ProductionEnclaveServer<
    A: AttestationProvider + Clone + Send + Sync + 'static,
    I: InferenceEngine + Clone + Send + Sync + 'static,
> {
    port: u32,
    session_manager: SessionManager,
    attestation_provider: A,
    inference_handler: Arc<InferenceHandler<A, I>>,
}

impl<
        A: AttestationProvider + Clone + Send + Sync + 'static,
        I: InferenceEngine + Clone + Send + Sync + 'static,
    > ProductionEnclaveServer<A, I>
{
    pub fn new(port: u32, attestation_provider: A, inference_engine: I) -> Self {
        let session_manager = SessionManager::new(100); // Support up to 100 concurrent sessions
        let inference_handler = Arc::new(InferenceHandler::new(
            session_manager.clone(),
            attestation_provider.clone(),
            inference_engine,
        ));

        Self {
            port,
            session_manager,
            attestation_provider,
            inference_handler,
        }
    }

    #[cfg(feature = "production")]
    pub async fn start(&self) -> Result<()> {
        let mut listener = VsockListener::bind(libc::VMADDR_CID_ANY, self.port).map_err(|e| {
            EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                "Failed to bind VSock: {}",
                e
            )))
        })?;

        println!("[server] listening on VSock port {}", self.port);

        loop {
            let (stream, addr) = listener.accept().await.map_err(|e| {
                EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                    "Failed to accept connection: {}",
                    e
                )))
            })?;

            println!("[server] accepted connection from CID {}", addr.cid());

            let handler = Arc::clone(&self.inference_handler);
            let provider = self.attestation_provider.clone();
            let sm = self.session_manager.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, handler, provider, sm).await {
                    eprintln!("[server] connection error: {}", e);
                }
            });
        }
    }

    #[cfg(feature = "production")]
    async fn handle_connection(
        mut stream: VsockStream,
        handler: Arc<InferenceHandler<A, I>>,
        provider: A,
        session_manager: SessionManager,
    ) -> Result<()> {
        loop {
            // 1. Read message length
            let mut len_buf = [0u8; 4];
            if let Err(e) = stream.read_exact(&mut len_buf).await {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break; // Connection closed
                }
                return Err(EnclaveError::Enclave(EphemeralError::NetworkError(
                    format!("Read length failed: {}", e),
                )));
            }
            let len = u32::from_be_bytes(len_buf) as usize;

            // 2. Read message body
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.map_err(|e| {
                EnclaveError::Enclave(EphemeralError::NetworkError(format!(
                    "Read body failed: {}",
                    e
                )))
            })?;

            // 3. Decode VSock message
            let mut full_buf = len_buf.to_vec();
            full_buf.extend_from_slice(&body);
            let msg = VSockMessage::decode(&full_buf)?;

            // 4. Dispatch by type
            match msg.msg_type {
                MessageType::Hello => {
                    let client_hello: ClientHello =
                        serde_json::from_slice(&msg.payload).map_err(|e| {
                            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                        })?;

                    client_hello.validate()?;

                    // Generate fresh ephemeral keypair for this session (forward secrecy)
                    let session_keypair = provider.generate_ephemeral_keypair();
                    let ephemeral_public_key = session_keypair.public_key;

                    // Generate per-session receipt signing key BEFORE attestation,
                    // so its public key can be embedded in the attestation user_data
                    let receipt_key = ephemeral_ml_common::ReceiptSigningKey::generate()?;
                    let receipt_pk = receipt_key.public_key_bytes();

                    let attestation =
                        provider.generate_attestation(&client_hello.client_nonce, receipt_pk)?;

                    // Establish HPKE session
                    let mut hasher = sha2::Sha256::new();
                    sha2::Digest::update(&mut hasher, &attestation.signature);
                    let attestation_hash: [u8; 32] = hasher.finalize().into();

                    let mut hpke = HPKESession::new(
                        ephemeral_ml_common::generate_id(),
                        PROTOCOL_VERSION_V1,
                        attestation_hash,
                        ephemeral_public_key,
                        client_hello.ephemeral_public_key, // peer
                        client_hello.client_nonce,
                        3600,
                    )
                    .map_err(|e| EnclaveError::Enclave(e))?;

                    // Use the per-session ephemeral private key, then zeroize it
                    hpke.establish(&session_keypair.private_key)
                        .map_err(|e| EnclaveError::Enclave(e))?;
                    drop(session_keypair);

                    let session = EnclaveSession::new(
                        hpke.session_id.clone(),
                        hpke,
                        receipt_key,
                        attestation_hash,
                        client_hello.client_id.clone(),
                    );

                    let session_id = session.hpke.session_id.clone();
                    session_manager.add_session(session)?;

                    let server_hello = ServerHello::new(
                        session_id,
                        vec!["gateway".to_string()],
                        attestation.signature, // Real attestation bytes
                        ephemeral_public_key.to_vec(),
                        receipt_pk.to_vec(),
                    )?;

                    let resp_payload = serde_json::to_vec(&server_hello).map_err(|e| {
                        EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                    })?;

                    let resp_msg =
                        VSockMessage::new(MessageType::Hello, msg.sequence, resp_payload)?;
                    stream.write_all(&resp_msg.encode()).await.map_err(|e| {
                        EnclaveError::Enclave(EphemeralError::NetworkError(e.to_string()))
                    })?;
                }
                MessageType::Data => {
                    let encrypted_req: ephemeral_ml_common::EncryptedMessage =
                        serde_json::from_slice(&msg.payload).map_err(|e| {
                            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                        })?;

                    let encrypted_resp = handler.handle_request(&encrypted_req).await?;

                    let resp_payload = serde_json::to_vec(&encrypted_resp).map_err(|e| {
                        EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                    })?;

                    let resp_msg =
                        VSockMessage::new(MessageType::Data, msg.sequence, resp_payload)?;
                    stream.write_all(&resp_msg.encode()).await.map_err(|e| {
                        EnclaveError::Enclave(EphemeralError::NetworkError(e.to_string()))
                    })?;
                }
                MessageType::Ping => {
                    let encrypted_req: ephemeral_ml_common::EncryptedMessage =
                        serde_json::from_slice(&msg.payload).map_err(|e| {
                            EnclaveError::Enclave(EphemeralError::SerializationError(e.to_string()))
                        })?;

                    let session_id = &encrypted_req.session_id;
                    let ping_result = session_manager.with_session(session_id, |session| {
                        let plaintext = session.decrypt(&encrypted_req)?;
                        let encrypted_resp = session.encrypt(&plaintext)?;
                        Ok(encrypted_resp)
                    });

                    match ping_result {
                        Ok(encrypted_resp) => {
                            let resp_payload =
                                serde_json::to_vec(&encrypted_resp).map_err(|e| {
                                    EnclaveError::Enclave(EphemeralError::SerializationError(
                                        e.to_string(),
                                    ))
                                })?;
                            let resp_msg =
                                VSockMessage::new(MessageType::Ping, msg.sequence, resp_payload)?;
                            stream.write_all(&resp_msg.encode()).await.map_err(|e| {
                                EnclaveError::Enclave(EphemeralError::NetworkError(e.to_string()))
                            })?;
                        }
                        Err(e) => {
                            eprintln!("[server] Ping error: {}", e);
                            let err_payload = format!("Ping error: {}", e).into_bytes();
                            let err_msg =
                                VSockMessage::new(MessageType::Error, msg.sequence, err_payload)?;
                            stream.write_all(&err_msg.encode()).await.map_err(|e| {
                                EnclaveError::Enclave(EphemeralError::NetworkError(e.to_string()))
                            })?;
                        }
                    }
                }
                MessageType::KmsProxy => {
                    // Enclave initiates KMS Proxy requests, usually doesn't receive them as a server.
                }
                _ => {
                    eprintln!("[server] unhandled message type: {:?}", msg.msg_type);
                }
            }
        }
        Ok(())
    }
}
