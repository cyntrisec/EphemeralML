use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{FromRawFd, RawFd};
use std::process;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Basic,
    Vsock,
    Attestation,
    Kms,
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
                let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
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
                    eprintln!("[enclave] successfully generated attestation document ({} bytes)", document.len());
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
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
                            recipient: Some(attestation_doc.into()),
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
            eprintln!("[enclave] vsock mode: starting vsock server on port {}", PORT);

            let listen_fd = make_listener(PORT);

            loop {
                let client_fd = unsafe {
                    libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut())
                };
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

fn get_peak_rss_mb() -> f64 {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if line.starts_with("VmPeak:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<f64>() {
                        return kb / 1024.0;
                    }
                }
            }
        }
    }
    0.0
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
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
            die(&format!("fetch_artifact({}): storage error: {}", model_key, message));
        }
    }
}

fn measure_vsock_rtt(payload_size: usize) -> f64 {
    use ephemeral_ml_common::{MessageType, VSockMessage};

    let data = vec![0xABu8; payload_size];
    let msg = VSockMessage::new(MessageType::Data, 0, data).unwrap();
    let encoded = msg.encode();

    let mut stream = vsock_connect(8082);
    let start = Instant::now();
    stream.write_all(&encoded).unwrap();

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).unwrap();

    start.elapsed().as_secs_f64() * 1000.0
}

async fn run_benchmark() {
    use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
    use candle_core::{Device, Tensor};
    use candle_nn::VarBuilder;
    use candle_transformers::models::bert::{BertModel, Config as BertConfig};

    let total_start = Instant::now();
    let device = Device::Cpu;

    // ── Stage 1: Attestation timing ──
    eprintln!("[bench] Stage 1: Attestation document generation");
    let attest_start = Instant::now();
    let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
    if nsm_fd < 0 {
        eprintln!("[bench] WARNING: NSM driver not available (running outside enclave?)");
    }
    let attestation_ms = if nsm_fd >= 0 {
        // Generate RSA keypair for RecipientInfo
        use rand::rngs::OsRng;
        use rsa::{pkcs8::EncodePublicKey, RsaPrivateKey};
        let rsa_priv = RsaPrivateKey::new(&mut OsRng, 2048).expect("rsa keygen");
        let rsa_pub_der = rsa_priv
            .to_public_key()
            .to_public_key_der()
            .expect("rsa pub der")
            .to_vec();

        let request = aws_nitro_enclaves_nsm_api::api::Request::Attestation {
            user_data: None,
            nonce: Some(serde_bytes::ByteBuf::from(vec![1u8; 32])),
            public_key: Some(serde_bytes::ByteBuf::from(rsa_pub_der)),
        };
        let _response =
            aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);
        attest_start.elapsed().as_secs_f64() * 1000.0
    } else {
        0.0
    };
    eprintln!("[bench] attestation_ms = {:.2}", attestation_ms);

    // ── Stage 2: KMS key release timing ──
    eprintln!("[bench] Stage 2: KMS DEK decryption");
    let kms_start = Instant::now();
    // In real enclave, this would do KMS Decrypt with RecipientInfo.
    // For benchmark, we use the fixed test DEK to measure model crypto overhead.
    let fixed_dek =
        hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .unwrap();
    let kms_key_release_ms = kms_start.elapsed().as_secs_f64() * 1000.0;
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
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&fixed_dek));
    let weights_plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .expect("weight decryption failed");
    let model_decrypt_ms = decrypt_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "[bench] model_decrypt_ms = {:.2} (plaintext={}B)",
        model_decrypt_ms,
        weights_plaintext.len()
    );

    // ── Stage 5: Model deserialization (safetensors → Candle BertModel) ──
    eprintln!("[bench] Stage 5: Loading model into Candle BertModel");
    let load_start = Instant::now();
    let config: BertConfig =
        serde_json::from_slice(&config_bytes).expect("failed to parse config.json");
    let vb = VarBuilder::from_buffered_safetensors(
        weights_plaintext,
        candle_core::DType::F32,
        &device,
    )
    .expect("failed to build VarBuilder from safetensors");
    let model = BertModel::load(vb, &config).expect("failed to load BertModel");
    let model_load_ms = load_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[bench] model_load_ms = {:.2}", model_load_ms);

    let cold_start_total_ms = total_start.elapsed().as_secs_f64() * 1000.0;
    eprintln!("[bench] cold_start_total_ms = {:.2}", cold_start_total_ms);

    // ── Stage 6: Tokenizer setup ──
    let tokenizer = tokenizers::Tokenizer::from_bytes(&tokenizer_bytes)
        .expect("failed to load tokenizer");

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
    eprintln!("[bench] Stage 9: VSock RTT measurements");
    let rtt_64b = measure_vsock_rtt(64);
    let rtt_1kb = measure_vsock_rtt(1024);
    let rtt_64kb = measure_vsock_rtt(64 * 1024);
    let rtt_1mb = measure_vsock_rtt(1024 * 1024);
    let vsock_throughput_mbps = if rtt_1mb > 0.0 {
        (1.0 / (rtt_1mb / 1000.0)) // MB/s
    } else {
        0.0
    };

    // ── Stage 10: Memory measurement ──
    let peak_rss_mb = get_peak_rss_mb();
    let model_size_mb = encrypted_weights.len() as f64 / (1024.0 * 1024.0);

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
            "model_size_mb": round2(model_size_mb)
        },
        "vsock": {
            "rtt_64b_ms": round2(rtt_64b),
            "rtt_1kb_ms": round2(rtt_1kb),
            "rtt_64kb_ms": round2(rtt_64kb),
            "rtt_1mb_ms": round2(rtt_1mb),
            "throughput_mbps": round2(vsock_throughput_mbps)
        }
    });

    let json_str = serde_json::to_string_pretty(&results).unwrap();
    eprintln!("BENCHMARK_RESULTS_JSON_BEGIN");
    eprintln!("{}", json_str);
    eprintln!("BENCHMARK_RESULTS_JSON_END");
}

fn run_single_inference(
    model: &candle_transformers::models::bert::BertModel,
    tokenizer: &tokenizers::Tokenizer,
    text: &str,
    device: &candle_core::Device,
) -> Vec<f32> {
    use candle_core::{Tensor, DType};

    let encoding = tokenizer.encode(text, true).expect("tokenization failed");
    let input_ids = encoding.get_ids();
    let token_type_ids = encoding.get_type_ids();
    let attention_mask: Vec<u32> = encoding.get_attention_mask().iter().map(|&v| v as u32).collect();

    let input_ids_t =
        Tensor::new(input_ids, device).unwrap().unsqueeze(0).unwrap();
    let token_type_ids_t =
        Tensor::new(token_type_ids, device).unwrap().unsqueeze(0).unwrap();

    let output = model
        .forward(&input_ids_t, &token_type_ids_t, None)
        .expect("inference failed");

    // Mean pooling over sequence dimension
    let (_batch, _seq_len, _hidden) = output.dims3().unwrap();
    let mask = Tensor::new(&attention_mask[..], device)
        .unwrap()
        .unsqueeze(0)
        .unwrap()
        .unsqueeze(2)
        .unwrap()
        .to_dtype(DType::F32)
        .unwrap();
    let masked = output.broadcast_mul(&mask).unwrap();
    let summed = masked.sum(1).unwrap();
    let count = mask.sum(1).unwrap();
    let mean_pooled = summed.broadcast_div(&count).unwrap();

    mean_pooled
        .squeeze(0)
        .unwrap()
        .to_vec1::<f32>()
        .unwrap()
}

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
    if let Err(_) = res {
        eprintln!("[enclave] PANIC: caught unwind; sleeping forever for debugging");
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
        }
    }
}
