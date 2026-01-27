use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{FromRawFd, RawFd};
use std::process;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Basic,
    Vsock,
    Attestation,
    Kms,
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
                use ephemeral_ml_common::{KmsRequest, KmsResponse, MessageType, VSockMessage};
                use tokio::io::{AsyncReadExt, AsyncWriteExt};

                // 1. Generate an RSA keypair and request an attestation document that embeds the recipient public key.
                // KMS requires the enclave public key to be present in the attestation doc when using RecipientInfo.
                use rand::rngs::OsRng;
                use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPublicKey};

                let mut rng = OsRng;
                let rsa_priv = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen failed");
                let rsa_pub = rsa_priv.to_public_key();
                // Encode as PKCS#1 DER; this is acceptable for KMS recipient public key embedding.
                let rsa_pub_der = rsa_pub.to_pkcs1_der().expect("rsa pub der").as_bytes().to_vec();

                // 2. Get attestation document
                let nsm_fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
                let request = aws_nitro_enclaves_nsm_api::api::Request::Attestation {
                    user_data: None,
                    nonce: None,
                    public_key: Some(rsa_pub_der.into()),
                };
                let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(nsm_fd, request);
                let attestation_doc = match response {
                    aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => document,
                    _ => die("Failed to get attestation doc"),
                };
                aws_nitro_enclaves_nsm_api::driver::nsm_exit(nsm_fd);
                eprintln!("[enclave] generated attestation doc ({} bytes)", attestation_doc.len());

                // 2. Connect to Host KMS Proxy (Port 8082)
                // We use raw libc since tokio-vsock isn't in our minimal enclave crate deps yet (or we can add it)
                // Actually I added tokio to Cargo.toml, so I can use std::os::unix::net or similar if I had vsock support.
                // For simplicity, let's use the libc socket we already have.
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

                // 3. Send GenerateDataKey request
                let kms_req = KmsRequest::GenerateDataKey {
                    key_id: "alias/ephemeral-ml-test".to_string(),
                    key_spec: "AES_256".to_string(),
                };
                let payload = serde_json::to_vec(&kms_req).unwrap();
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
                let kms_resp: KmsResponse = serde_json::from_slice(&msg.payload).unwrap();
                
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

                        // Connect again (simple sequential test)
                        let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
                        unsafe {
                            libc::connect(fd, &addr as *const _ as *const libc::sockaddr, mem::size_of::<SockAddrVm>() as libc::socklen_t);
                        }
                        let mut stream = unsafe { std::fs::File::from_raw_fd(fd) };

                        let payload = serde_json::to_vec(&decrypt_req).unwrap();
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
                        let decrypt_resp: KmsResponse = serde_json::from_slice(&msg.payload).unwrap();

                        match decrypt_resp {
                            KmsResponse::Decrypt { ciphertext_for_recipient, .. } => {
                                if ciphertext_for_recipient.is_some() {
                                    eprintln!("[enclave] SUCCESS: received wrapped key from KMS");
                                } else {
                                    eprintln!("[enclave] FAILED: KMS did not return wrapped key (policy issue?)");
                                }
                            }
                            KmsResponse::Error(e) => eprintln!("[enclave] KMS Decrypt Error: {}", e),
                            _ => eprintln!("[enclave] Unexpected response from KMS"),
                        }
                    }
                    KmsResponse::Error(e) => eprintln!("[enclave] KMS GenerateDataKey Error: {}", e),
                    _ => eprintln!("[enclave] Unexpected response from KMS"),
                }
            });
            
            eprintln!("[enclave] KMS test complete; sleeping");
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
