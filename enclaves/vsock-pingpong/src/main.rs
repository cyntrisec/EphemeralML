use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{FromRawFd, RawFd};
use std::process;
use std::time::Instant;

use ephemeral_ml_common::metrics;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Basic,
    Vsock,
    Attestation,
    Kms,
    KmsAudit,
    Benchmark,
}

fn parse_mode() -> Mode {
    let args: Vec<String> = std::env::args().collect();
    eprintln!("[enclave] debug: raw args: {:?}", args);
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--mode" && i + 1 < args.len() {
            let v = &args[i + 1];
            return match v.as_str() {
                "basic" => Mode::Basic,
                "vsock" => Mode::Vsock,
                "attestation" => Mode::Attestation,
                "kms" => Mode::Kms,
                "kms-audit" => Mode::KmsAudit,
                "benchmark" => Mode::Benchmark,
                _ => Mode::Vsock,
            };
        }
        i += 1;
    }
    Mode::Vsock
}

// AF_VSOCK server: listen on port 5000; reply "pong" when receiving "ping".
// Parent connects to CID 16 / port 5000.

const PORT: u32 = 5000;

// Linux sockaddr_vm (from <linux/vm_sockets.h>)
#[repr(C)]
#[derive(Copy, Clone)]
struct SockAddrVm {
    svm_family: libc::sa_family_t,
    svm_reserved1: libc::c_ushort,
    svm_port: libc::c_uint,
    svm_cid: libc::c_uint,
    svm_zero: [libc::c_uchar; 4],
}

fn die(msg: &str) -> ! {
    // In Nitro Enclaves, failures can be hard to diagnose if the process exits instantly
    // (the enclave disappears before we can attach `nitro-cli console`).
    // So we log the error and then sleep forever to keep the enclave alive for debugging.
    let e = std::io::Error::last_os_error();
    eprintln!("{}: {}", msg, e);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

fn cvt(ret: libc::c_int, msg: &str) -> libc::c_int {
    if ret < 0 {
        die(msg);
    }
    ret
}

fn make_listener(port: u32) -> RawFd {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        die("socket(AF_VSOCK)");
    }

    // Allow fast restart.
    let optval: libc::c_int = 1;
    unsafe {
        cvt(
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &optval as *const _ as *const c_void,
                mem::size_of_val(&optval) as libc::socklen_t,
            ),
            "setsockopt(SO_REUSEADDR)",
        );
    }

    let addr = SockAddrVm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        // Bind to any CID inside the enclave.
        svm_cid: libc::VMADDR_CID_ANY,
        svm_zero: [0; 4],
    };

    unsafe {
        cvt(
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<SockAddrVm>() as libc::socklen_t,
            ),
            "bind(vsock)",
        );
        cvt(libc::listen(fd, 16), "listen");
    }

    fd
}

fn run(mode: Mode) {
    match mode {
        Mode::Basic => {
            eprintln!("[enclave] basic mode: alive; sleeping forever");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        Mode::Attestation => {
            eprintln!("[enclave] attestation mode: fetching PCRs");
            let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
            if nsm_fd < 0 {
                eprintln!("[enclave] ERROR: Failed to initialize NSM driver");
                process::exit(1);
            }

            for i in 0..16 {
                let request = aws_nitro_enclaves_nsm_api::api::Request::DescribePCR { index: i };
                let response =
                    aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
                match response {
                    aws_nitro_enclaves_nsm_api::api::Response::DescribePCR { data, .. } => {
                        eprintln!("PCR {}: {}", i, hex::encode(data));
                    }
                    _ => {
                        eprintln!("[enclave] ERROR: Failed to describe PCR {}", i);
                    }
                }
            }

            // Also try to get an attestation document with a dummy nonce
            let nonce = vec![1u8, 2, 3, 4];
            let request = aws_nitro_enclaves_nsm_api::api::Request::Attestation {
                user_data: None,
                nonce: Some(serde_bytes::ByteBuf::from(nonce)),
                public_key: None,
            };
            let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
            match response {
                aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => {
                    eprintln!(
                        "[enclave] successfully generated attestation document ({} bytes)",
                        document.len()
                    );
                }
                _ => {
                    eprintln!("[enclave] ERROR: Failed to generate attestation document");
                }
            }

            aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);
            eprintln!("[enclave] attestation validation complete; sleeping");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        Mode::Kms => {
            eprintln!("[enclave] KMS mode: testing KMS data key generation and decryption");

            // We use tokio for the KMS test
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                use ephemeral_ml_common::{
                    KmsRequest, KmsResponse, MessageType, VSockMessage,
                    KmsProxyRequestEnvelope, KmsProxyResponseEnvelope,
                    generate_id,
                };

                // 1. Generate an RSA keypair and request an attestation document that embeds the recipient public key.
                // KMS requires the enclave public key to be present in the attestation doc when using RecipientInfo.
                use rand::rngs::OsRng;
                use rsa::{RsaPrivateKey, pkcs8::EncodePublicKey};

                eprintln!("[enclave] generating RSA keypair for KMS RecipientInfo...");
                let mut rng = OsRng;
                let rsa_priv = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen failed");
                let rsa_pub = rsa_priv.to_public_key();
                // Encode as SubjectPublicKeyInfo (PKCS#8/SPKI) DER. KMS expects a valid RSA public key.
                let rsa_pub_der = rsa_pub.to_public_key_der().expect("rsa pub der").to_vec();

                // 2. Get attestation document
                let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
                let request = aws_nitro_enclaves_nsm_api::api::Request::Attestation {
                    user_data: None,
                    nonce: None,
                    public_key: Some(serde_bytes::ByteBuf::from(rsa_pub_der)),
                };
                let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
                let attestation_doc = match response {
                    aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => document,
                    _ => die("Failed to get attestation doc"),
                };
                aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);
                eprintln!("[enclave] generated attestation doc ({} bytes)", attestation_doc.len());

                // 2. Connect to Host KMS Proxy (Port 8082)
                let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
                let addr = SockAddrVm {
                    svm_family: libc::AF_VSOCK as libc::sa_family_t,
                    svm_reserved1: 0,
                    svm_port: 8082,
                    svm_cid: 3, // Parent
                    svm_zero: [0; 4],
                };
                let res = unsafe {
                    libc::connect(fd, &addr as *const _ as *const libc::sockaddr, mem::size_of::<SockAddrVm>() as libc::socklen_t)
                };
                if res < 0 {
                    die("connect to host KMS proxy failed");
                }

                let mut stream = unsafe { std::fs::File::from_raw_fd(fd) };

                // 3. Send GenerateDataKey request (wrapped in Envelope)
                let kms_req = KmsRequest::GenerateDataKey {
                    key_id: "alias/ephemeral-ml-test".to_string(),
                    key_spec: "AES_256".to_string(),
                    encryption_context: None,
                    recipient: None,
                };
                let req_env = KmsProxyRequestEnvelope {
                    request_id: generate_id(),
                    trace_id: Some("diag10-test-gen".to_string()),
                    request: kms_req,
                };
                let payload = serde_json::to_vec(&req_env).unwrap();
                let msg = VSockMessage::new(MessageType::KmsProxy, 0, payload).unwrap();
                stream.write_all(&msg.encode()).unwrap();

                // 4. Read response
                let mut len_buf = [0u8; 4];
                stream.read_exact(&mut len_buf).unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                stream.read_exact(&mut body).unwrap();

                let mut full_msg = len_buf.to_vec();
                full_msg.extend_from_slice(&body);
                let msg = VSockMessage::decode(&full_msg).unwrap();

                if msg.msg_type == MessageType::Error {
                    die(&format!("KMS proxy returned error message: {}", String::from_utf8_lossy(&msg.payload)));
                }

                let resp_env: KmsProxyResponseEnvelope = serde_json::from_slice(&msg.payload).unwrap();
                let kms_resp = resp_env.response;

                match kms_resp {
                    KmsResponse::GenerateDataKey { key_id, ciphertext_blob, .. } => {
                        eprintln!("[enclave] successfully generated data key for {}", key_id);

                        // 5. Test Decryption with Attestation
                        let decrypt_req = KmsRequest::Decrypt {
                            ciphertext_blob,
                            key_id: Some(key_id),
                            encryption_context: None,
                            grant_tokens: None,
                            recipient: Some(attestation_doc),
                        };
                        let decrypt_env = KmsProxyRequestEnvelope {
                            request_id: generate_id(),
                            trace_id: Some("diag10-test-decrypt".to_string()),
                            request: decrypt_req,
                        };

                        // Connect again (simple sequential test)
                        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
                        unsafe {
                            libc::connect(fd, &addr as *const _ as *const libc::sockaddr, mem::size_of::<SockAddrVm>() as libc::socklen_t);
                        }
                        let mut stream = unsafe { std::fs::File::from_raw_fd(fd) };

                        let payload = serde_json::to_vec(&decrypt_env).unwrap();
                        let msg = VSockMessage::new(MessageType::KmsProxy, 1, payload).unwrap();
                        stream.write_all(&msg.encode()).unwrap();

                        let mut len_buf = [0u8; 4];
                        stream.read_exact(&mut len_buf).unwrap();
                        let len = u32::from_be_bytes(len_buf) as usize;
                        let mut body = vec![0u8; len];
                        stream.read_exact(&mut body).unwrap();

                        let mut full_msg = len_buf.to_vec();
                        full_msg.extend_from_slice(&body);
                        let msg = VSockMessage::decode(&full_msg).unwrap();

                        if msg.msg_type == MessageType::Error {
                            die(&format!("KMS proxy returned error message for decrypt: {}", String::from_utf8_lossy(&msg.payload)));
                        }

                        let resp_env: KmsProxyResponseEnvelope = serde_json::from_slice(&msg.payload).unwrap();
                        let decrypt_resp = resp_env.response;

                        match decrypt_resp {
                            KmsResponse::Decrypt { ciphertext_for_recipient, .. } => {
                                if ciphertext_for_recipient.is_some() {
                                    eprintln!("[enclave] SUCCESS: received wrapped key from KMS");
                                } else {
                                    eprintln!("[enclave] FAILED: KMS did not return wrapped key (policy issue?)");
                                }
                            }
                            KmsResponse::Error { code, message } => eprintln!("[enclave] KMS Decrypt Error ({:?}): {}", code, message),
                            _ => eprintln!("[enclave] Unexpected response from KMS"),
                        }
                    }
                    KmsResponse::Error { code, message } => eprintln!("[enclave] KMS GenerateDataKey Error ({:?}): {}", code, message),
                    _ => eprintln!("[enclave] Unexpected response from KMS"),
                }
            });

            eprintln!("[enclave] KMS test complete; sleeping");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        Mode::KmsAudit => {
            eprintln!("[enclave] kms-audit mode: testing KMS attestation enforcement");

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async {
                run_kms_audit().await;
            });

            eprintln!("[enclave] kms-audit complete; sleeping");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        Mode::Benchmark => {
            eprintln!("[enclave] benchmark mode: starting benchmark suite");
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                run_benchmark().await;
            });
            eprintln!("[enclave] benchmark complete; sleeping");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
            }
        }
        Mode::Vsock => {
            eprintln!(
                "[enclave] vsock mode: starting vsock server on port {}",
                PORT
            );

            let listen_fd = make_listener(PORT);

            loop {
                let client_fd =
                    unsafe { libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut()) };
                if client_fd < 0 {
                    die("accept");
                }

                // Wrap the client fd in a File for plain read/write.
                let mut stream = unsafe { std::fs::File::from_raw_fd(client_fd) };

                let mut buf = [0u8; 16];
                let n = match stream.read(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("[enclave] read error: {e}");
                        continue;
                    }
                };

                let msg = &buf[..n];
                eprintln!(
                    "[enclave] received: {:?}",
                    std::str::from_utf8(msg).unwrap_or("<non-utf8>")
                );

                let reply: &[u8] = if msg == b"ping" { b"pong" } else { b"unknown" };

                if let Err(e) = stream.write_all(reply) {
                    eprintln!("[enclave] write error: {e}");
                }
                // drop(stream) closes the connection
            }
        }
    }
}

// ─── KMS Audit helpers ───────────────────────────────────────────────

/// Send a KMS request via VSock and return the response envelope.
fn kms_roundtrip(
    req_env: &ephemeral_ml_common::KmsProxyRequestEnvelope,
) -> std::result::Result<ephemeral_ml_common::KmsProxyResponseEnvelope, String> {
    use ephemeral_ml_common::{MessageType, VSockMessage};

    let payload = serde_json::to_vec(req_env).map_err(|e| format!("serialize: {e}"))?;
    let msg =
        VSockMessage::new(MessageType::KmsProxy, 0, payload).map_err(|e| format!("msg: {e}"))?;

    let mut stream = vsock_connect(8082);
    stream
        .write_all(&msg.encode())
        .map_err(|e| format!("write: {e}"))?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("read len: {e}"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("read body: {e}"))?;

    let mut full_msg = len_buf.to_vec();
    full_msg.extend_from_slice(&body);
    let resp_msg = VSockMessage::decode(&full_msg).map_err(|e| format!("decode: {e}"))?;

    if resp_msg.msg_type == MessageType::Error {
        return Err(format!(
            "proxy error: {}",
            String::from_utf8_lossy(&resp_msg.payload)
        ));
    }

    serde_json::from_slice(&resp_msg.payload).map_err(|e| format!("deserialize: {e}"))
}

/// Generate an RSA keypair and NSM attestation document with the public key embedded.
/// Returns `(rsa_private_key, attestation_document_bytes)`.
fn generate_attested_keypair() -> (rsa::RsaPrivateKey, Vec<u8>) {
    use rand::rngs::OsRng;
    use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey};

    let rsa_priv = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen failed");
    let rsa_pub_der = rsa_priv
        .to_public_key()
        .to_public_key_der()
        .expect("rsa pub der")
        .to_vec();

    let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
    if nsm_fd < 0 {
        die("kms-audit: NSM driver not available (must run inside Nitro Enclave)");
    }

    let request = aws_nitro_enclaves_nsm_api::api::Request::Attestation {
        user_data: None,
        nonce: Some(serde_bytes::ByteBuf::from(vec![1u8; 32])),
        public_key: Some(serde_bytes::ByteBuf::from(rsa_pub_der)),
    };
    let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
    let attestation_doc = match response {
        aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => document,
        _ => die("kms-audit: failed to get attestation document"),
    };
    aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);

    (rsa_priv, attestation_doc)
}

async fn run_kms_audit() {
    use ephemeral_ml_common::{generate_id, KmsProxyRequestEnvelope, KmsRequest, KmsResponse};

    let key_alias = std::env::var("KMS_AUDIT_KEY_ALIAS")
        .unwrap_or_else(|_| "alias/ephemeral-ml-attest-test".to_string());
    eprintln!("[kms-audit] using key: {}", key_alias);

    let (_rsa_priv, attestation_doc) = generate_attested_keypair();
    eprintln!(
        "[kms-audit] generated attestation doc ({} bytes)",
        attestation_doc.len()
    );

    let mut results: Vec<serde_json::Value> = Vec::new();

    // ── Test 1: Attested GenerateDataKey (should succeed) ──
    {
        eprintln!("[kms-audit] Test 1: Attested GenerateDataKey");
        let start = Instant::now();
        let req_env = KmsProxyRequestEnvelope {
            request_id: generate_id(),
            trace_id: Some("kms-audit-test1".to_string()),
            request: KmsRequest::GenerateDataKey {
                key_id: key_alias.clone(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: Some(attestation_doc.clone()),
            },
        };
        let result = kms_roundtrip(&req_env);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let (actual, error_code, cfr_present, pt_present, kms_req_id) = match result {
            Ok(env) => match &env.response {
                KmsResponse::GenerateDataKey {
                    ciphertext_for_recipient,
                    plaintext,
                    ..
                } => (
                    "success",
                    serde_json::Value::Null,
                    ciphertext_for_recipient.is_some(),
                    plaintext.is_some(),
                    env.kms_request_id.clone(),
                ),
                KmsResponse::Error { code, message } => (
                    "error",
                    serde_json::json!(format!("{:?}: {}", code, message)),
                    false,
                    false,
                    env.kms_request_id.clone(),
                ),
                _ => ("unexpected", serde_json::Value::Null, false, false, None),
            },
            Err(e) => ("transport_error", serde_json::json!(e), false, false, None),
        };
        let entry = serde_json::json!({
            "test_id": "attested_generate_data_key",
            "test_num": 1,
            "expected": "success",
            "actual": actual,
            "error_code": error_code,
            "kms_request_id": kms_req_id,
            "latency_ms": round2(latency_ms),
            "ciphertext_for_recipient_present": cfr_present,
            "plaintext_present": pt_present
        });
        eprintln!("[kms-audit] Test 1 result: {}", actual);
        results.push(entry);
    }

    // ── Test 2: Unattested GenerateDataKey (no RecipientInfo) ──
    {
        eprintln!("[kms-audit] Test 2: Unattested GenerateDataKey");
        let start = Instant::now();
        let req_env = KmsProxyRequestEnvelope {
            request_id: generate_id(),
            trace_id: Some("kms-audit-test2".to_string()),
            request: KmsRequest::GenerateDataKey {
                key_id: key_alias.clone(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: None,
            },
        };
        let result = kms_roundtrip(&req_env);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let (actual, error_code, cfr_present, pt_present, kms_req_id) = match result {
            Ok(env) => match &env.response {
                KmsResponse::GenerateDataKey {
                    ciphertext_for_recipient,
                    plaintext,
                    ..
                } => (
                    "success",
                    serde_json::Value::Null,
                    ciphertext_for_recipient.is_some(),
                    plaintext.is_some(),
                    env.kms_request_id.clone(),
                ),
                KmsResponse::Error { code, message } => (
                    "error",
                    serde_json::json!(format!("{:?}: {}", code, message)),
                    false,
                    false,
                    env.kms_request_id.clone(),
                ),
                _ => ("unexpected", serde_json::Value::Null, false, false, None),
            },
            Err(e) => ("transport_error", serde_json::json!(e), false, false, None),
        };
        let entry = serde_json::json!({
            "test_id": "unattested_generate_data_key",
            "test_num": 2,
            "expected": "access_denied",
            "actual": actual,
            "error_code": error_code,
            "kms_request_id": kms_req_id,
            "latency_ms": round2(latency_ms),
            "ciphertext_for_recipient_present": cfr_present,
            "plaintext_present": pt_present
        });
        eprintln!("[kms-audit] Test 2 result: {}", actual);
        results.push(entry);
    }

    // ── Test 3: Malformed RecipientInfo (random bytes) ──
    {
        eprintln!("[kms-audit] Test 3: Malformed RecipientInfo");
        let start = Instant::now();
        let malformed_doc = [0xDEu8, 0xAD, 0xBE, 0xEF]
            .iter()
            .cycle()
            .take(256)
            .copied()
            .collect::<Vec<u8>>();
        let req_env = KmsProxyRequestEnvelope {
            request_id: generate_id(),
            trace_id: Some("kms-audit-test3".to_string()),
            request: KmsRequest::GenerateDataKey {
                key_id: key_alias.clone(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: Some(malformed_doc),
            },
        };
        let result = kms_roundtrip(&req_env);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let (actual, error_code, kms_req_id) = match result {
            Ok(env) => match &env.response {
                KmsResponse::Error { code, message } => (
                    "error",
                    serde_json::json!(format!("{:?}: {}", code, message)),
                    env.kms_request_id.clone(),
                ),
                KmsResponse::GenerateDataKey { .. } => (
                    "unexpected_success",
                    serde_json::Value::Null,
                    env.kms_request_id.clone(),
                ),
                _ => ("unexpected", serde_json::Value::Null, None),
            },
            Err(e) => ("transport_error", serde_json::json!(e), None),
        };
        let entry = serde_json::json!({
            "test_id": "malformed_recipient_info",
            "test_num": 3,
            "expected": "error",
            "actual": actual,
            "error_code": error_code,
            "kms_request_id": kms_req_id,
            "latency_ms": round2(latency_ms),
            "ciphertext_for_recipient_present": false,
            "plaintext_present": false
        });
        eprintln!("[kms-audit] Test 3 result: {}", actual);
        results.push(entry);
    }

    // ── Test 4: Attested Decrypt (need a ciphertext_blob from GenerateDataKey first) ──
    {
        eprintln!("[kms-audit] Test 4: Attested Decrypt");
        // Generate a data key WITH attestation to get a ciphertext_blob
        // (unattested GenerateDataKey is denied by the strict key policy)
        let gen_env = KmsProxyRequestEnvelope {
            request_id: generate_id(),
            trace_id: Some("kms-audit-test4-setup".to_string()),
            request: KmsRequest::GenerateDataKey {
                key_id: key_alias.clone(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: Some(attestation_doc.clone()),
            },
        };
        let gen_result = kms_roundtrip(&gen_env);

        let ciphertext_blob = match gen_result {
            Ok(env) => match env.response {
                KmsResponse::GenerateDataKey {
                    ciphertext_blob, ..
                } => Some(ciphertext_blob),
                _ => None,
            },
            Err(_) => None,
        };

        if let Some(ct_blob) = ciphertext_blob {
            let start = Instant::now();
            let req_env = KmsProxyRequestEnvelope {
                request_id: generate_id(),
                trace_id: Some("kms-audit-test4".to_string()),
                request: KmsRequest::Decrypt {
                    ciphertext_blob: ct_blob,
                    key_id: Some(key_alias.clone()),
                    encryption_context: None,
                    grant_tokens: None,
                    recipient: Some(attestation_doc.clone()),
                },
            };
            let result = kms_roundtrip(&req_env);
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let (actual, error_code, cfr_present, pt_present, kms_req_id) = match result {
                Ok(env) => match &env.response {
                    KmsResponse::Decrypt {
                        ciphertext_for_recipient,
                        plaintext,
                        ..
                    } => (
                        "success",
                        serde_json::Value::Null,
                        ciphertext_for_recipient.is_some(),
                        plaintext.is_some(),
                        env.kms_request_id.clone(),
                    ),
                    KmsResponse::Error { code, message } => (
                        "error",
                        serde_json::json!(format!("{:?}: {}", code, message)),
                        false,
                        false,
                        env.kms_request_id.clone(),
                    ),
                    _ => ("unexpected", serde_json::Value::Null, false, false, None),
                },
                Err(e) => ("transport_error", serde_json::json!(e), false, false, None),
            };
            let entry = serde_json::json!({
                "test_id": "attested_decrypt",
                "test_num": 4,
                "expected": "success",
                "actual": actual,
                "error_code": error_code,
                "kms_request_id": kms_req_id,
                "latency_ms": round2(latency_ms),
                "ciphertext_for_recipient_present": cfr_present,
                "plaintext_present": pt_present
            });
            eprintln!("[kms-audit] Test 4 result: {}", actual);
            results.push(entry);
        } else {
            eprintln!("[kms-audit] Test 4: SKIPPED (could not generate data key for setup)");
            results.push(serde_json::json!({
                "test_id": "attested_decrypt",
                "test_num": 4,
                "expected": "success",
                "actual": "skipped",
                "error_code": "setup_failed",
                "kms_request_id": null,
                "latency_ms": 0.0,
                "ciphertext_for_recipient_present": false,
                "plaintext_present": false
            }));
        }
    }

    // ── Test 5: Unattested Decrypt (no RecipientInfo) ──
    {
        eprintln!("[kms-audit] Test 5: Unattested Decrypt");
        // Generate a data key WITH attestation to get a ciphertext_blob
        // (unattested GenerateDataKey is denied by the strict key policy)
        let gen_env = KmsProxyRequestEnvelope {
            request_id: generate_id(),
            trace_id: Some("kms-audit-test5-setup".to_string()),
            request: KmsRequest::GenerateDataKey {
                key_id: key_alias.clone(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: Some(attestation_doc.clone()),
            },
        };
        let gen_result = kms_roundtrip(&gen_env);

        let ciphertext_blob = match gen_result {
            Ok(env) => match env.response {
                KmsResponse::GenerateDataKey {
                    ciphertext_blob, ..
                } => Some(ciphertext_blob),
                _ => None,
            },
            Err(_) => None,
        };

        if let Some(ct_blob) = ciphertext_blob {
            let start = Instant::now();
            let req_env = KmsProxyRequestEnvelope {
                request_id: generate_id(),
                trace_id: Some("kms-audit-test5".to_string()),
                request: KmsRequest::Decrypt {
                    ciphertext_blob: ct_blob,
                    key_id: Some(key_alias.clone()),
                    encryption_context: None,
                    grant_tokens: None,
                    recipient: None,
                },
            };
            let result = kms_roundtrip(&req_env);
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            let (actual, error_code, cfr_present, pt_present, kms_req_id) = match result {
                Ok(env) => match &env.response {
                    KmsResponse::Decrypt {
                        ciphertext_for_recipient,
                        plaintext,
                        ..
                    } => (
                        "success",
                        serde_json::Value::Null,
                        ciphertext_for_recipient.is_some(),
                        plaintext.is_some(),
                        env.kms_request_id.clone(),
                    ),
                    KmsResponse::Error { code, message } => (
                        "error",
                        serde_json::json!(format!("{:?}: {}", code, message)),
                        false,
                        false,
                        env.kms_request_id.clone(),
                    ),
                    _ => ("unexpected", serde_json::Value::Null, false, false, None),
                },
                Err(e) => ("transport_error", serde_json::json!(e), false, false, None),
            };
            let entry = serde_json::json!({
                "test_id": "unattested_decrypt",
                "test_num": 5,
                "expected": "access_denied",
                "actual": actual,
                "error_code": error_code,
                "kms_request_id": kms_req_id,
                "latency_ms": round2(latency_ms),
                "ciphertext_for_recipient_present": cfr_present,
                "plaintext_present": pt_present
            });
            eprintln!("[kms-audit] Test 5 result: {}", actual);
            results.push(entry);
        } else {
            eprintln!("[kms-audit] Test 5: SKIPPED (could not generate data key for setup)");
            results.push(serde_json::json!({
                "test_id": "unattested_decrypt",
                "test_num": 5,
                "expected": "access_denied",
                "actual": "skipped",
                "error_code": "setup_failed",
                "kms_request_id": null,
                "latency_ms": 0.0,
                "ciphertext_for_recipient_present": false,
                "plaintext_present": false
            }));
        }
    }

    // ── Test 6: Bit-flipped attestation doc (1 byte changed in real doc) ──
    {
        eprintln!("[kms-audit] Test 6: Bit-flipped attestation doc");
        let mut flipped_doc = attestation_doc.clone();
        // Flip one byte near the middle of the attestation document
        if flipped_doc.len() > 100 {
            flipped_doc[100] ^= 0xFF;
        }
        let start = Instant::now();
        let req_env = KmsProxyRequestEnvelope {
            request_id: generate_id(),
            trace_id: Some("kms-audit-test6".to_string()),
            request: KmsRequest::GenerateDataKey {
                key_id: key_alias.clone(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: Some(flipped_doc),
            },
        };
        let result = kms_roundtrip(&req_env);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let (actual, error_code, cfr_present, pt_present, kms_req_id) = match result {
            Ok(env) => match &env.response {
                KmsResponse::GenerateDataKey {
                    ciphertext_for_recipient,
                    plaintext,
                    ..
                } => (
                    "success",
                    serde_json::Value::Null,
                    ciphertext_for_recipient.is_some(),
                    plaintext.as_ref().is_some_and(|p| !p.is_empty()),
                    env.kms_request_id.clone(),
                ),
                KmsResponse::Error { code, message } => (
                    "error",
                    serde_json::json!(format!("{:?}: {}", code, message)),
                    false,
                    false,
                    env.kms_request_id.clone(),
                ),
                _ => ("unexpected", serde_json::Value::Null, false, false, None),
            },
            Err(e) => ("transport_error", serde_json::json!(e), false, false, None),
        };
        eprintln!("[kms-audit] Test 6 result: {}", actual);
        results.push(serde_json::json!({
            "test_id": "bitflipped_attestation_doc",
            "test_num": 6,
            "expected": "error",
            "actual": actual,
            "error_code": error_code,
            "kms_request_id": kms_req_id,
            "latency_ms": round2(latency_ms),
            "ciphertext_for_recipient_present": cfr_present,
            "plaintext_present": pt_present
        }));
    }

    // ── Test 7: Replay previously used attestation doc ──
    // Re-send the same attestation doc that was used in Test 1 (minutes later)
    {
        eprintln!("[kms-audit] Test 7: Replay attestation doc (same doc as Test 1)");
        let start = Instant::now();
        let req_env = KmsProxyRequestEnvelope {
            request_id: generate_id(),
            trace_id: Some("kms-audit-test7-replay".to_string()),
            request: KmsRequest::GenerateDataKey {
                key_id: key_alias.clone(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: Some(attestation_doc.clone()),
            },
        };
        let result = kms_roundtrip(&req_env);
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

        let (actual, error_code, cfr_present, pt_present, kms_req_id) = match result {
            Ok(env) => match &env.response {
                KmsResponse::GenerateDataKey {
                    ciphertext_for_recipient,
                    plaintext,
                    ..
                } => (
                    "success",
                    serde_json::Value::Null,
                    ciphertext_for_recipient.is_some(),
                    plaintext.as_ref().is_some_and(|p| !p.is_empty()),
                    env.kms_request_id.clone(),
                ),
                KmsResponse::Error { code, message } => (
                    "error",
                    serde_json::json!(format!("{:?}: {}", code, message)),
                    false,
                    false,
                    env.kms_request_id.clone(),
                ),
                _ => ("unexpected", serde_json::Value::Null, false, false, None),
            },
            Err(e) => ("transport_error", serde_json::json!(e), false, false, None),
        };
        eprintln!("[kms-audit] Test 7 result: {}", actual);
        results.push(serde_json::json!({
            "test_id": "replay_attestation_doc",
            "test_num": 7,
            "expected": "success_or_error",
            "actual": actual,
            "error_code": error_code,
            "kms_request_id": kms_req_id,
            "latency_ms": round2(latency_ms),
            "ciphertext_for_recipient_present": cfr_present,
            "plaintext_present": pt_present,
            "note": "Replay of same attestation doc used in Test 1"
        }));
    }

    // ── Output structured results ──
    let output = serde_json::json!({
        "audit_type": "kms_attestation_enforcement",
        "key_alias": key_alias,
        "timestamp": chrono_now_iso(),
        "commit": option_env!("GIT_COMMIT").unwrap_or("unknown"),
        "hardware": option_env!("INSTANCE_TYPE").unwrap_or("unknown"),
        "tests": results,
        "summary": {
            "total": results.len(),
            "passed": results.iter().filter(|r| {
                let actual = r["actual"].as_str().unwrap_or("");
                let expected = r["expected"].as_str().unwrap_or("");
                match expected {
                    "success" => actual == "success",
                    "error" => actual == "error",
                    "access_denied" => actual == "error",
                    _ => false,
                }
            }).count(),
            "failed": results.iter().filter(|r| {
                let actual = r["actual"].as_str().unwrap_or("");
                let expected = r["expected"].as_str().unwrap_or("");
                let passed = match expected {
                    "success" => actual == "success",
                    "error" => actual == "error",
                    "access_denied" => actual == "error",
                    _ => false,
                };
                !passed
            }).count(),
        }
    });

    let json_str = serde_json::to_string_pretty(&output).unwrap();
    eprintln!("KMS_AUDIT_JSON_BEGIN");
    eprintln!("{}", json_str);
    eprintln!("KMS_AUDIT_JSON_END");
}

// ─── Benchmark helpers ───────────────────────────────────────────────

const BENCHMARK_INPUT_TEXTS: &[&str] = &[
    "What is the capital of France?",
    "Machine learning enables computers to learn from data.",
    "The quick brown fox jumps over the lazy dog.",
    "Confidential computing protects data in use.",
    "Rust provides memory safety without garbage collection.",
];

const NUM_WARMUP: usize = 3;
const NUM_ITERATIONS: usize = 100;

fn get_peak_rss_mb() -> (f64, &'static str) {
    metrics::peak_rss_mb_with_source()
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    metrics::percentile_nearest(sorted, p)
}

fn vsock_connect(port: u32) -> std::fs::File {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        die("benchmark: socket(AF_VSOCK)");
    }
    let addr = SockAddrVm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: 3, // Parent
        svm_zero: [0; 4],
    };
    let res = unsafe {
        libc::connect(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            mem::size_of::<SockAddrVm>() as libc::socklen_t,
        )
    };
    if res < 0 {
        die("benchmark: connect to host proxy failed");
    }
    unsafe { std::fs::File::from_raw_fd(fd) }
}

fn fetch_artifact(model_key: &str) -> Vec<u8> {
    use ephemeral_ml_common::{
        storage_protocol::{StorageRequest, StorageResponse},
        MessageType, VSockMessage,
    };

    let storage_req = StorageRequest {
        model_id: model_key.to_string(),
        part_index: 0,
    };
    let payload = serde_json::to_vec(&storage_req).unwrap();
    let msg = VSockMessage::new(MessageType::Storage, 0, payload).unwrap();

    let mut stream = vsock_connect(8082);
    stream.write_all(&msg.encode()).unwrap();

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).unwrap();

    let mut full_msg = len_buf.to_vec();
    full_msg.extend_from_slice(&body);
    let resp_msg = VSockMessage::decode(&full_msg).unwrap();

    if resp_msg.msg_type == MessageType::Error {
        die(&format!(
            "fetch_artifact({}): proxy error: {}",
            model_key,
            String::from_utf8_lossy(&resp_msg.payload)
        ));
    }

    let resp: StorageResponse = serde_json::from_slice(&resp_msg.payload).unwrap();
    match resp {
        StorageResponse::Data { payload, .. } => payload,
        StorageResponse::Error { message } => {
            die(&format!(
                "fetch_artifact({}): storage error: {}",
                model_key, message
            ));
        }
    }
}

/// Measure VSock round-trip time using a Storage request.
///
/// We send a StorageRequest for a non-existent key with a dummy payload padded
/// to the desired size. The host proxy will return a StorageResponse::Error,
/// which is fine — we're measuring the transport RTT, not the S3 fetch.
/// We repeat `ROUNDS` times and return the median.
fn measure_vsock_rtt(payload_size: usize) -> f64 {
    use ephemeral_ml_common::{
        audit::AuditLogRequest, AuditEventType, AuditLogEntry, AuditSeverity, MessageType,
        VSockMessage,
    };

    const ROUNDS: usize = 10;
    const WARMUP: usize = 3;
    let mut samples = Vec::with_capacity(ROUNDS);

    // Use Audit messages for RTT measurement — they're lightweight, always get a response,
    // and don't trigger S3 lookups. Pad the details field to approximate desired payload size.
    let padding = "x".repeat(payload_size.saturating_sub(200)); // subtract base JSON overhead
    let entry = AuditLogEntry {
        entry_id: "bench-rtt".to_string(),
        timestamp: 0,
        event_type: AuditEventType::InferenceCompleted,
        session_id: None,
        client_id: None,
        model_id: None,
        details: {
            let mut m = std::collections::HashMap::new();
            m.insert("padding".to_string(), serde_json::Value::String(padding));
            m
        },
        severity: AuditSeverity::Info,
        is_metric: true,
    };
    let req = AuditLogRequest { entry };
    let req_payload = serde_json::to_vec(&req).unwrap();
    eprintln!(
        "[bench] RTT payload_size={} actual_json_len={}",
        payload_size,
        req_payload.len()
    );
    let msg = VSockMessage::new(MessageType::Audit, 0, req_payload).unwrap();
    let encoded = msg.encode();

    // Warmup rounds (not counted)
    for _ in 0..WARMUP {
        let Ok(mut stream) = std::panic::catch_unwind(|| vsock_connect(8082)).map_err(|_| ())
        else {
            return 0.0;
        };
        let _ = stream.write_all(&encoded);
        let mut len_buf = [0u8; 4];
        let _ = stream.read_exact(&mut len_buf);
        let len = u32::from_be_bytes(len_buf);
        let mut body = vec![0u8; len as usize];
        let _ = stream.read_exact(&mut body);
    }

    for _ in 0..ROUNDS {
        let Ok(mut stream) = std::panic::catch_unwind(|| vsock_connect(8082)).map_err(|_| ())
        else {
            eprintln!("[bench] vsock_connect failed for RTT measurement");
            return 0.0;
        };
        let start = Instant::now();
        if stream.write_all(&encoded).is_err() {
            eprintln!("[bench] RTT write failed");
            continue;
        }

        // Read response
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).is_err() {
            eprintln!("[bench] RTT read len failed");
            continue;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 10 * 1024 * 1024 {
            eprintln!("[bench] RTT response too large: {}", len);
            continue;
        }
        let mut body = vec![0u8; len];
        if stream.read_exact(&mut body).is_err() {
            eprintln!("[bench] RTT read body failed");
            continue;
        }

        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    if samples.is_empty() {
        return 0.0;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    // Return median
    samples[samples.len() / 2]
}

async fn run_benchmark() {
    use candle_core::Device;
    use candle_nn::VarBuilder;
    use candle_transformers::models::bert::{BertModel, Config as BertConfig};
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};

    let total_start = Instant::now();
    let device = Device::Cpu;

    // ── Stage 1: Attestation + KMS key release timing ──
    // We measure both together: RSA keygen + NSM attestation doc + KMS GenerateDataKey +
    // KMS Decrypt with RecipientInfo (the real attestation-bound key release flow).
    eprintln!("[bench] Stage 1: Attestation document generation");
    let attest_start = Instant::now();
    let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
    if nsm_fd < 0 {
        eprintln!("[bench] WARNING: NSM driver not available (running outside enclave?)");
    }

    // These will hold the real measured DEK (or fallback to hardcoded if KMS unavailable)
    let mut attestation_ms: f64 = 0.0;
    let mut kms_key_release_ms: f64 = 0.0;

    // Try to get a real DEK via the KMS flow; fall back to hardcoded if NSM/KMS unavailable.
    let fixed_dek = if nsm_fd >= 0 {
        use ephemeral_ml_common::{
            generate_id, KmsProxyRequestEnvelope, KmsProxyResponseEnvelope, KmsRequest,
            KmsResponse, MessageType, VSockMessage,
        };
        use rand::rngs::OsRng;
        use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey};

        // 1a. Generate RSA keypair for RecipientInfo
        let rsa_priv = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let rsa_pub_der = rsa_priv
            .to_public_key()
            .to_public_key_der()
            .expect("rsa pub der")
            .to_vec();

        // 1b. Get attestation document with embedded public key
        let request = aws_nitro_enclaves_nsm_api::api::Request::Attestation {
            user_data: None,
            nonce: Some(serde_bytes::ByteBuf::from(vec![1u8; 32])),
            public_key: Some(serde_bytes::ByteBuf::from(rsa_pub_der)),
        };
        let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
        let attestation_doc = match response {
            aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => document,
            _ => {
                eprintln!(
                    "[bench] WARNING: failed to get attestation doc, falling back to hardcoded DEK"
                );
                aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);
                attestation_ms = attest_start.elapsed().as_secs_f64() * 1000.0;
                hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                    .unwrap()
            }
        };

        // If we got the attestation doc, proceed with real KMS round-trip
        if attestation_doc.len() > 100 {
            aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);
            attestation_ms = attest_start.elapsed().as_secs_f64() * 1000.0;
            eprintln!(
                "[bench] attestation_ms = {:.2} (doc {} bytes)",
                attestation_ms,
                attestation_doc.len()
            );

            // 2. KMS GenerateDataKey with RecipientInfo (single attested call)
            eprintln!("[bench] Stage 2: KMS key release (attested GenerateDataKey)");
            let kms_start = Instant::now();

            let gen_req = KmsRequest::GenerateDataKey {
                key_id: "alias/ephemeral-ml-test".to_string(),
                key_spec: "AES_256".to_string(),
                encryption_context: None,
                recipient: Some(attestation_doc),
            };
            let gen_env = KmsProxyRequestEnvelope {
                request_id: generate_id(),
                trace_id: Some("bench-genkey".to_string()),
                request: gen_req,
            };
            let payload = serde_json::to_vec(&gen_env).unwrap();
            let msg = VSockMessage::new(MessageType::KmsProxy, 0, payload).unwrap();
            let mut stream = vsock_connect(8082);
            stream.write_all(&msg.encode()).unwrap();

            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).unwrap();
            let mut full_msg = len_buf.to_vec();
            full_msg.extend_from_slice(&body);
            let resp_msg = VSockMessage::decode(&full_msg).unwrap();
            let resp_env: KmsProxyResponseEnvelope =
                serde_json::from_slice(&resp_msg.payload).unwrap();

            match resp_env.response {
                KmsResponse::GenerateDataKey {
                    key_id,
                    ciphertext_for_recipient,
                    ..
                } => {
                    if ciphertext_for_recipient.is_some() {
                        eprintln!(
                            "[bench] Attested GenerateDataKey OK for {}: SUCCESS",
                            key_id
                        );
                    } else {
                        eprintln!(
                            "[bench] GenerateDataKey for {}: no wrapped key returned (policy issue?)",
                            key_id
                        );
                    }
                }
                KmsResponse::Error { code, message } => {
                    eprintln!(
                        "[bench] KMS GenerateDataKey Error ({:?}): {}",
                        code, message
                    );
                }
                _ => {
                    eprintln!("[bench] KMS GenerateDataKey: unexpected response");
                }
            }

            kms_key_release_ms = kms_start.elapsed().as_secs_f64() * 1000.0;
            eprintln!("[bench] kms_key_release_ms = {:.2}", kms_key_release_ms);

            // Use the fixed DEK for model decryption (the KMS-returned key is for
            // the benchmark key, not the model encryption key)
            hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap()
        } else {
            attestation_doc // This branch shouldn't happen but satisfies the type system
        }
    } else {
        eprintln!("[bench] NSM unavailable — skipping attestation & KMS, using hardcoded DEK");
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").unwrap()
    };
    eprintln!("[bench] attestation_ms = {:.2}", attestation_ms);
    eprintln!("[bench] kms_key_release_ms = {:.2}", kms_key_release_ms);

    // ── Stage 3: Model fetch via VSock ──
    eprintln!("[bench] Stage 3: Fetching model artifacts via VSock");
    let fetch_start = Instant::now();
    let config_bytes = fetch_artifact("mini-lm-v2-config");
    let tokenizer_bytes = fetch_artifact("mini-lm-v2-tokenizer");
    let encrypted_weights = fetch_artifact("mini-lm-v2-weights");
    let model_fetch_ms = fetch_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "[bench] model_fetch_ms = {:.2} (config={}B, tokenizer={}B, weights={}B)",
        model_fetch_ms,
        config_bytes.len(),
        tokenizer_bytes.len(),
        encrypted_weights.len()
    );

    // ── Stage 4: Decrypt weights ──
    eprintln!("[bench] Stage 4: Decrypting model weights");
    let decrypt_start = Instant::now();
    let (nonce_bytes, ciphertext) = encrypted_weights.split_at(12);
    let key = Key::from_slice(&fixed_dek);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let weights_plaintext = cipher
        .decrypt(nonce, ciphertext)
        .expect("weight decryption failed");
    let model_decrypt_ms = decrypt_start.elapsed().as_secs_f64() * 1000.0;
    let plaintext_size = weights_plaintext.len();
    eprintln!(
        "[bench] model_decrypt_ms = {:.2} (plaintext={}B)",
        model_decrypt_ms, plaintext_size
    );

    // ── Stage 5: Model deserialization (safetensors → Candle BertModel) ──
    eprintln!("[bench] Stage 5: Loading model into Candle BertModel");
    let load_start = Instant::now();
    let config: BertConfig =
        serde_json::from_slice(&config_bytes).expect("failed to parse config.json");
    let vb =
        VarBuilder::from_buffered_safetensors(weights_plaintext, candle_core::DType::F32, &device)
            .expect("failed to build VarBuilder from safetensors");
    let model = BertModel::load(vb, &config).expect("failed to load BertModel");
    let model_load_ms = load_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[bench] model_load_ms = {:.2}", model_load_ms);

    // ── Stage 6: Tokenizer setup ──
    let tokenizer_start = Instant::now();
    let tokenizer =
        tokenizers::Tokenizer::from_bytes(&tokenizer_bytes).expect("failed to load tokenizer");
    let tokenizer_setup_ms = tokenizer_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[bench] tokenizer_setup_ms = {:.2}", tokenizer_setup_ms);

    // cold_start_total_ms includes everything up to "ready to serve first inference"
    let cold_start_total_ms = total_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[bench] cold_start_total_ms = {:.2}", cold_start_total_ms);

    // ── Stage 6b: Capture reference embedding for quality verification ──
    // Run inference on the first input text and store the embedding vector.
    // This allows cosine similarity comparison between bare-metal and enclave outputs.
    let reference_embedding =
        run_single_inference(&model, &tokenizer, BENCHMARK_INPUT_TEXTS[0], &device);
    eprintln!(
        "[bench] reference_embedding: dim={}, first_5={:?}",
        reference_embedding.len(),
        &reference_embedding[..5.min(reference_embedding.len())]
    );

    // ── Stage 7: Warmup inferences ──
    eprintln!("[bench] Stage 7: Warmup ({} iterations)", NUM_WARMUP);
    for i in 0..NUM_WARMUP {
        let text = BENCHMARK_INPUT_TEXTS[i % BENCHMARK_INPUT_TEXTS.len()];
        let _ = run_single_inference(&model, &tokenizer, text, &device);
    }

    // ── Stage 8: Timed inference iterations ──
    eprintln!(
        "[bench] Stage 8: Running {} inference iterations",
        NUM_ITERATIONS
    );
    let mut latencies_ms: Vec<f64> = Vec::with_capacity(NUM_ITERATIONS);
    for i in 0..NUM_ITERATIONS {
        let text = BENCHMARK_INPUT_TEXTS[i % BENCHMARK_INPUT_TEXTS.len()];
        let start = Instant::now();
        let _ = run_single_inference(&model, &tokenizer, text, &device);
        latencies_ms.push(start.elapsed().as_secs_f64() * 1000.0);
    }

    latencies_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = latencies_ms.iter().sum::<f64>() / latencies_ms.len() as f64;
    let p50 = percentile(&latencies_ms, 50.0);
    let p95 = percentile(&latencies_ms, 95.0);
    let p99 = percentile(&latencies_ms, 99.0);
    let min_val = latencies_ms.first().copied().unwrap_or(0.0);
    let max_val = latencies_ms.last().copied().unwrap_or(0.0);
    let throughput = if mean > 0.0 { 1000.0 / mean } else { 0.0 };

    // ── Stage 9: VSock RTT measurement ──
    // Note: RTT measures send(payload_size) + recv(small error response).
    // This captures transport latency at each payload size accurately.
    // Upload throughput is derived from 1MB RTT (upload direction only).
    eprintln!("[bench] Stage 9: VSock RTT measurements");
    let rtt_64b = measure_vsock_rtt(64);
    let rtt_1kb = measure_vsock_rtt(1024);
    let rtt_64kb = measure_vsock_rtt(64 * 1024);
    let rtt_1mb = measure_vsock_rtt(1024 * 1024);
    // Upload throughput: payload_bytes / rtt_seconds
    let vsock_upload_throughput_mbps = if rtt_1mb > 0.0 {
        (1024.0 * 1024.0) / (rtt_1mb / 1000.0) / (1024.0 * 1024.0) // MB/s
    } else {
        0.0
    };

    // ── Stage 10: Memory measurement ──
    let (peak_rss_mb, peak_rss_source) = get_peak_rss_mb();
    let peak_vmsize_mb = metrics::peak_vmsize_mb();
    let model_size_mb = plaintext_size as f64 / (1024.0 * 1024.0);

    // ── Get commit hash ──
    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");

    // ── Output structured JSON results to stderr (captured by nitro-cli console) ──
    let results = serde_json::json!({
        "environment": "enclave",
        "model": "MiniLM-L6-v2",
        "model_params": 22_700_000,
        "hardware": option_env!("INSTANCE_TYPE").unwrap_or("unknown"),
        "timestamp": chrono_now_iso(),
        "commit": commit,
        "stages": {
            "attestation_ms": round2(attestation_ms),
            "kms_key_release_ms": round2(kms_key_release_ms),
            "model_fetch_ms": round2(model_fetch_ms),
            "model_decrypt_ms": round2(model_decrypt_ms),
            "model_load_ms": round2(model_load_ms),
            "tokenizer_setup_ms": round2(tokenizer_setup_ms),
            "cold_start_total_ms": round2(cold_start_total_ms)
        },
        "inference": {
            "input_texts": BENCHMARK_INPUT_TEXTS,
            "num_iterations": NUM_ITERATIONS,
            "latency_ms": {
                "mean": round2(mean),
                "p50": round2(p50),
                "p95": round2(p95),
                "p99": round2(p99),
                "min": round2(min_val),
                "max": round2(max_val)
            },
            "throughput_inferences_per_sec": round2(throughput)
        },
        "memory": {
            "peak_rss_mb": round2(peak_rss_mb),
            "peak_rss_source": peak_rss_source,
            "peak_vmsize_mb": round2(peak_vmsize_mb),
            "model_size_mb": round2(model_size_mb)
        },
        "vsock": {
            "rtt_64b_ms": round2(rtt_64b),
            "rtt_1kb_ms": round2(rtt_1kb),
            "rtt_64kb_ms": round2(rtt_64kb),
            "rtt_1mb_ms": round2(rtt_1mb),
            "upload_throughput_mb_per_sec": round2(vsock_upload_throughput_mbps)
        },
        "quality": {
            "reference_text": BENCHMARK_INPUT_TEXTS[0],
            "embedding_dim": reference_embedding.len(),
            "embedding_first_8": &reference_embedding[..8.min(reference_embedding.len())],
            "embedding_sha256": metrics::sha256_f32_le(&reference_embedding),
            "embedding": reference_embedding
        }
    });

    let json_str = serde_json::to_string_pretty(&results).unwrap();
    eprintln!("BENCHMARK_RESULTS_JSON_BEGIN");
    eprintln!("{}", json_str);
    eprintln!("BENCHMARK_RESULTS_JSON_END");
}

use ephemeral_ml_common::inference::run_single_inference;

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn chrono_now_iso() -> String {
    // Simple ISO-8601 without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}Z", secs)
}

fn main() {
    let mode = parse_mode();
    eprintln!("[enclave] mode={mode:?}");

    // If the enclave panics and exits immediately, we lose all visibility.
    // Catch panics, log them, then sleep forever so `nitro-cli console` (or attach-console) can inspect.
    let res = std::panic::catch_unwind(|| run(mode));
    if res.is_err() {
        eprintln!("[enclave] PANIC: caught unwind; sleeping forever for debugging");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}
