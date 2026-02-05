//! COSE attestation verification benchmark for EphemeralML.
//!
//! Benchmarks the client-side cost of verifying a COSE_Sign1 attestation
//! document with a certificate chain, as produced by AWS Nitro Enclaves NSM.
//!
//! Generates a structurally identical COSE_Sign1 document using a test CA
//! (same crypto operations as the real AWS Nitro root CA: ECDSA P-384 + SHA-384).
//! The computational cost of signature verification and certificate chain walking
//! is identical regardless of which root CA is used.
//!
//! The benchmark matches the production verification path in `attestation_verifier.rs`:
//! - Leaf cert extracted from CBOR payload `certificate` field (not COSE x5chain header)
//! - Sig_structure computed via coset `verify_signature()` callback
//! - ECDSA signature stored as raw (r||s) and converted to DER for OpenSSL verification

use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use openssl::x509::extension::{BasicConstraints, SubjectKeyIdentifier};
use openssl::x509::{X509Builder, X509NameBuilder, X509};
use std::time::Instant;

const NUM_WARMUP: usize = 3;
const NUM_ITERATIONS: usize = 100;

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = (p / 100.0 * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

fn latency_stats(sorted: &[f64]) -> serde_json::Value {
    let mean = sorted.iter().sum::<f64>() / sorted.len() as f64;
    serde_json::json!({
        "mean": round4(mean),
        "p50": round4(percentile(sorted, 50.0)),
        "p95": round4(percentile(sorted, 95.0)),
        "p99": round4(percentile(sorted, 99.0)),
        "min": round4(sorted.first().copied().unwrap_or(0.0)),
        "max": round4(sorted.last().copied().unwrap_or(0.0))
    })
}

/// Convert raw ECDSA signature (r || s) to DER-encoded SEQUENCE { INTEGER r, INTEGER s }.
/// Mirrors `ecdsa_raw_to_der` in `attestation_verifier.rs`.
fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, String> {
    if !raw.len().is_multiple_of(2) || raw.is_empty() {
        return Err(format!(
            "Invalid ECDSA signature length: {} (expected even)",
            raw.len()
        ));
    }

    let half = raw.len() / 2;
    let r = &raw[..half];
    let s = &raw[half..];

    fn encode_integer(bytes: &[u8]) -> Vec<u8> {
        let stripped = match bytes.iter().position(|&b| b != 0) {
            Some(pos) => &bytes[pos..],
            None => &[0u8],
        };
        if stripped[0] & 0x80 != 0 {
            let mut result = vec![0x02, (stripped.len() + 1) as u8, 0x00];
            result.extend_from_slice(stripped);
            result
        } else {
            let mut result = vec![0x02, stripped.len() as u8];
            result.extend_from_slice(stripped);
            result
        }
    }

    let r_der = encode_integer(r);
    let s_der = encode_integer(s);

    let total_len = r_der.len() + s_der.len();
    let mut der = vec![0x30]; // SEQUENCE tag
    if total_len < 128 {
        der.push(total_len as u8);
    } else {
        der.push(0x81);
        der.push(total_len as u8);
    }
    der.extend_from_slice(&r_der);
    der.extend_from_slice(&s_der);

    Ok(der)
}

/// Convert DER-encoded ECDSA signature to raw (r || s) format, each component
/// zero-padded to `component_len` bytes. For P-384, component_len = 48.
fn ecdsa_der_to_raw(der: &[u8], component_len: usize) -> Result<Vec<u8>, String> {
    if der.len() < 6 || der[0] != 0x30 {
        return Err("Not a DER SEQUENCE".into());
    }

    // Skip SEQUENCE tag + length
    let mut pos = 1;
    if der[pos] & 0x80 != 0 {
        let len_bytes = (der[pos] & 0x7f) as usize;
        pos += 1 + len_bytes;
    } else {
        pos += 1;
    }

    // Parse first INTEGER (r)
    if der[pos] != 0x02 {
        return Err("Expected INTEGER tag for r".into());
    }
    pos += 1;
    let r_len = der[pos] as usize;
    pos += 1;
    let r_bytes = &der[pos..pos + r_len];
    pos += r_len;

    // Parse second INTEGER (s)
    if der[pos] != 0x02 {
        return Err("Expected INTEGER tag for s".into());
    }
    pos += 1;
    let s_len = der[pos] as usize;
    pos += 1;
    let s_bytes = &der[pos..pos + s_len];

    // Strip leading zero padding and right-align into component_len bytes
    fn pad_component(bytes: &[u8], len: usize) -> Vec<u8> {
        // Strip leading zeros added for ASN.1 sign bit
        let stripped = match bytes.iter().position(|&b| b != 0) {
            Some(p) => &bytes[p..],
            None => &[0u8],
        };
        let mut out = vec![0u8; len];
        let offset = len.saturating_sub(stripped.len());
        out[offset..].copy_from_slice(stripped);
        out
    }

    let mut raw = pad_component(r_bytes, component_len);
    raw.extend_from_slice(&pad_component(s_bytes, component_len));
    Ok(raw)
}

/// Generate a test certificate chain: Root CA → Intermediate → Leaf
/// Uses P-384 (secp384r1) + SHA-384, same as AWS Nitro root CA.
fn generate_test_cert_chain() -> (Vec<Vec<u8>>, PKey<openssl::pkey::Private>) {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();

    // Root CA
    let root_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut root_name = X509NameBuilder::new().unwrap();
    root_name
        .append_entry_by_text("CN", "Test Nitro Root CA")
        .unwrap();
    root_name.append_entry_by_text("O", "Test").unwrap();
    let root_name = root_name.build();

    let mut root_builder = X509Builder::new().unwrap();
    root_builder.set_version(2).unwrap();
    root_builder
        .set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    root_builder.set_subject_name(&root_name).unwrap();
    root_builder.set_issuer_name(&root_name).unwrap();
    root_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    root_builder
        .set_not_after(&Asn1Time::days_from_now(3650).unwrap())
        .unwrap();
    root_builder.set_pubkey(&root_key).unwrap();
    root_builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    let ski = SubjectKeyIdentifier::new()
        .build(&root_builder.x509v3_context(None, None))
        .unwrap();
    root_builder.append_extension(ski).unwrap();
    root_builder
        .sign(&root_key, MessageDigest::sha384())
        .unwrap();
    let root_cert = root_builder.build();

    // Intermediate CA
    let inter_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut inter_name = X509NameBuilder::new().unwrap();
    inter_name
        .append_entry_by_text("CN", "Test Nitro Intermediate")
        .unwrap();
    let inter_name = inter_name.build();

    let mut inter_builder = X509Builder::new().unwrap();
    inter_builder.set_version(2).unwrap();
    inter_builder
        .set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    inter_builder.set_subject_name(&inter_name).unwrap();
    inter_builder.set_issuer_name(&root_name).unwrap();
    inter_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    inter_builder
        .set_not_after(&Asn1Time::days_from_now(3650).unwrap())
        .unwrap();
    inter_builder.set_pubkey(&inter_key).unwrap();
    inter_builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    let ski = SubjectKeyIdentifier::new()
        .build(&inter_builder.x509v3_context(Some(&root_cert), None))
        .unwrap();
    inter_builder.append_extension(ski).unwrap();
    inter_builder
        .sign(&root_key, MessageDigest::sha384())
        .unwrap();
    let inter_cert = inter_builder.build();

    // Leaf certificate (enclave signing key)
    let leaf_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut leaf_name = X509NameBuilder::new().unwrap();
    leaf_name
        .append_entry_by_text("CN", "Test Enclave")
        .unwrap();
    let leaf_name = leaf_name.build();

    let mut leaf_builder = X509Builder::new().unwrap();
    leaf_builder.set_version(2).unwrap();
    leaf_builder
        .set_serial_number(&BigNum::from_u32(3).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf_builder.set_subject_name(&leaf_name).unwrap();
    leaf_builder.set_issuer_name(&inter_name).unwrap();
    leaf_builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf_builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    leaf_builder.set_pubkey(&leaf_key).unwrap();
    leaf_builder
        .sign(&inter_key, MessageDigest::sha384())
        .unwrap();
    let leaf_cert = leaf_builder.build();

    // Return DER-encoded certs: [leaf, intermediate, root] (NSM ordering)
    let chain = vec![
        leaf_cert.to_der().unwrap(),
        inter_cert.to_der().unwrap(),
        root_cert.to_der().unwrap(),
    ];

    (chain, leaf_key)
}

/// Build a COSE_Sign1 message with the given payload and signing key.
/// Mirrors the structure produced by AWS NSM: leaf cert in CBOR payload
/// `certificate` field, signature in raw (r||s) format.
/// Uses coset's CoseSign1Builder to ensure tbs_data matches verify_signature().
fn build_cose_sign1(payload: &[u8], signing_key: &PKey<openssl::pkey::Private>) -> Vec<u8> {
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::ES384)
        .build();

    // Use coset's builder + create_signature so tbs_data is computed identically
    // during both signing and verification (avoids serde_cbor vs ciborium divergence).
    let cose = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload.to_vec())
        .create_signature(&[], |tbs_data| {
            // Sign with ECDSA P-384 + SHA-384 (OpenSSL produces DER)
            let mut signer = Signer::new(MessageDigest::sha384(), signing_key).unwrap();
            signer.update(tbs_data).unwrap();
            let der_signature = signer.sign_to_vec().unwrap();

            // Convert DER → raw (r||s) to match NSM output. P-384 = 48 bytes per component.
            ecdsa_der_to_raw(&der_signature, 48).unwrap()
        })
        .build();

    cose.to_vec().unwrap()
}

/// Extract leaf certificate DER from CBOR payload's `certificate` field.
fn extract_leaf_cert_from_payload(payload_bytes: &[u8]) -> Vec<u8> {
    let val: serde_cbor::Value = serde_cbor::from_slice(payload_bytes).unwrap();
    if let serde_cbor::Value::Map(map) = val {
        for (k, v) in &map {
            if let serde_cbor::Value::Text(key) = k {
                if key == "certificate" {
                    if let serde_cbor::Value::Bytes(b) = v {
                        return b.clone();
                    }
                }
            }
        }
    }
    panic!("certificate field not found in CBOR payload");
}

/// Benchmark COSE_Sign1 signature verification (parse + verify).
/// Matches production path: extract leaf cert from payload, use coset's
/// verify_signature() with ecdsa_raw_to_der() conversion.
fn bench_cose_signature_verify(cose_bytes: &[u8]) -> Vec<f64> {
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    for i in 0..(NUM_WARMUP + NUM_ITERATIONS) {
        let start = Instant::now();

        // Parse COSE_Sign1
        let cose_sign1 = CoseSign1::from_slice(cose_bytes).unwrap();

        // Extract leaf cert from CBOR payload's "certificate" field
        let payload_bytes = cose_sign1.payload.as_deref().unwrap();
        let leaf_der = extract_leaf_cert_from_payload(payload_bytes);
        let leaf_cert = X509::from_der(&leaf_der).unwrap();
        let pubkey = leaf_cert.public_key().unwrap();

        // Verify signature using coset's tbs_data computation + raw-to-DER conversion
        cose_sign1
            .verify_signature(&[], |sig, tbs_data| {
                let der_sig = ecdsa_raw_to_der(sig).map_err(|e| e.to_string())?;
                let mut verifier =
                    Verifier::new(MessageDigest::sha384(), &pubkey).map_err(|e| e.to_string())?;
                verifier.update(tbs_data).map_err(|e| e.to_string())?;
                if !verifier.verify(&der_sig).unwrap_or(false) {
                    return Err("COSE signature verification failed".to_string());
                }
                Ok(())
            })
            .unwrap();

        let ms = start.elapsed().as_secs_f64() * 1000.0;
        if i >= NUM_WARMUP {
            latencies.push(ms);
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    latencies
}

/// Benchmark certificate chain validation (3-cert chain: leaf → intermediate → root)
fn bench_cert_chain_verify(cert_chain: &[Vec<u8>], root_ca_der: &[u8]) -> Vec<f64> {
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    for i in 0..(NUM_WARMUP + NUM_ITERATIONS) {
        let start = Instant::now();

        // Load root CA
        let root_ca = X509::from_der(root_ca_der).unwrap();

        // Walk chain in reverse (root → intermediate → leaf), verifying each
        let mut last_cert = root_ca;
        for idx in (0..cert_chain.len()).rev() {
            let cert = X509::from_der(&cert_chain[idx]).unwrap();
            let pubkey = last_cert.public_key().unwrap();
            assert!(cert.verify(&pubkey).unwrap());
            last_cert = cert;
        }

        let ms = start.elapsed().as_secs_f64() * 1000.0;
        if i >= NUM_WARMUP {
            latencies.push(ms);
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    latencies
}

/// Benchmark CBOR attestation payload parsing
fn bench_payload_parse(cose_bytes: &[u8]) -> Vec<f64> {
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);
    let cose_sign1 = CoseSign1::from_slice(cose_bytes).unwrap();
    let payload_bytes = cose_sign1.payload.unwrap();

    for i in 0..(NUM_WARMUP + NUM_ITERATIONS) {
        let start = Instant::now();

        let _val: serde_cbor::Value = serde_cbor::from_slice(&payload_bytes).unwrap();

        let ms = start.elapsed().as_secs_f64() * 1000.0;
        if i >= NUM_WARMUP {
            latencies.push(ms);
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    latencies
}

/// Benchmark full verification pipeline (COSE verify + chain walk + payload parse).
/// Matches production path: cert from payload, coset verify_signature(), raw-to-DER.
fn bench_full_verification(
    cose_bytes: &[u8],
    cert_chain: &[Vec<u8>],
    root_ca_der: &[u8],
) -> Vec<f64> {
    let mut latencies = Vec::with_capacity(NUM_ITERATIONS);

    for i in 0..(NUM_WARMUP + NUM_ITERATIONS) {
        let start = Instant::now();

        // 1. Parse COSE_Sign1
        let cose_sign1 = CoseSign1::from_slice(cose_bytes).unwrap();

        // 2. Extract leaf cert from payload and verify signature
        let payload_bytes = cose_sign1.payload.as_deref().unwrap();
        let leaf_der = extract_leaf_cert_from_payload(payload_bytes);
        let leaf_cert = X509::from_der(&leaf_der).unwrap();
        let pubkey = leaf_cert.public_key().unwrap();

        cose_sign1
            .verify_signature(&[], |sig, tbs_data| {
                let der_sig = ecdsa_raw_to_der(sig).map_err(|e| e.to_string())?;
                let mut verifier =
                    Verifier::new(MessageDigest::sha384(), &pubkey).map_err(|e| e.to_string())?;
                verifier.update(tbs_data).map_err(|e| e.to_string())?;
                if !verifier.verify(&der_sig).unwrap_or(false) {
                    return Err("COSE signature verification failed".to_string());
                }
                Ok(())
            })
            .unwrap();

        // 3. Validate certificate chain
        let root_ca = X509::from_der(root_ca_der).unwrap();
        let mut last_cert = root_ca;
        for idx in (0..cert_chain.len()).rev() {
            let cert = X509::from_der(&cert_chain[idx]).unwrap();
            let pk = last_cert.public_key().unwrap();
            assert!(cert.verify(&pk).unwrap());
            last_cert = cert;
        }

        // 4. Parse CBOR payload
        let _payload: serde_cbor::Value = serde_cbor::from_slice(payload_bytes).unwrap();

        let ms = start.elapsed().as_secs_f64() * 1000.0;
        if i >= NUM_WARMUP {
            latencies.push(ms);
        }
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    latencies
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let instance_type = args
        .iter()
        .position(|a| a == "--instance-type")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or("unknown");

    eprintln!("[cose] Starting COSE attestation verification benchmark");
    eprintln!(
        "[cose] Iterations: {}, Warmup: {}",
        NUM_ITERATIONS, NUM_WARMUP
    );

    // Generate test PKI (P-384, same curve as AWS Nitro root CA)
    eprintln!("[cose] Generating P-384 test certificate chain (Root → Intermediate → Leaf)...");
    let (cert_chain, leaf_key) = generate_test_cert_chain();
    let root_ca_der = cert_chain.last().unwrap().clone();

    eprintln!(
        "[cose] Chain: {} certs, root={} bytes, leaf={} bytes",
        cert_chain.len(),
        root_ca_der.len(),
        cert_chain[0].len()
    );

    // Build attestation payload (CBOR, mimics NSM output).
    // Includes `certificate` field with leaf cert DER (matching real NSM documents).
    let user_data = serde_json::json!({
        "hpke_public_key": vec![1u8; 32],
        "receipt_signing_key": vec![2u8; 32],
        "protocol_version": 1,
        "supported_features": ["gateway"]
    });
    let user_data_bytes = serde_json::to_vec(&user_data)?;

    let payload_map = serde_cbor::Value::Map(
        vec![
            (
                serde_cbor::Value::Text("module_id".into()),
                serde_cbor::Value::Text("i-XXXXXXXXXXXXXXXXX-enc01a2b3c4d5e6f7g8".into()),
            ),
            (
                serde_cbor::Value::Text("timestamp".into()),
                serde_cbor::Value::Integer(1769977102),
            ),
            (
                serde_cbor::Value::Text("digest".into()),
                serde_cbor::Value::Text("SHA384".into()),
            ),
            (
                serde_cbor::Value::Text("nonce".into()),
                serde_cbor::Value::Bytes(vec![0u8; 32]),
            ),
            (
                serde_cbor::Value::Text("user_data".into()),
                serde_cbor::Value::Bytes(user_data_bytes),
            ),
            (
                serde_cbor::Value::Text("public_key".into()),
                serde_cbor::Value::Bytes(vec![0u8; 270]),
            ), // RSA-2048 SPKI ~270 bytes
            (
                serde_cbor::Value::Text("pcrs".into()),
                serde_cbor::Value::Map(
                    vec![
                        (
                            serde_cbor::Value::Integer(0),
                            serde_cbor::Value::Bytes(vec![0xAA; 48]),
                        ),
                        (
                            serde_cbor::Value::Integer(1),
                            serde_cbor::Value::Bytes(vec![0xBB; 48]),
                        ),
                        (
                            serde_cbor::Value::Integer(2),
                            serde_cbor::Value::Bytes(vec![0xCC; 48]),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ),
            (
                serde_cbor::Value::Text("certificate".into()),
                serde_cbor::Value::Bytes(cert_chain[0].clone()),
            ),
            (
                serde_cbor::Value::Text("cabundle".into()),
                serde_cbor::Value::Array(
                    cert_chain
                        .iter()
                        .skip(1)
                        .map(|c| serde_cbor::Value::Bytes(c.clone()))
                        .collect(),
                ),
            ),
        ]
        .into_iter()
        .collect(),
    );
    let payload_bytes = serde_cbor::to_vec(&payload_map)?;

    eprintln!("[cose] Payload size: {} bytes", payload_bytes.len());

    // Build COSE_Sign1 with raw (r||s) signature format (matching NSM)
    let cose_bytes = build_cose_sign1(&payload_bytes, &leaf_key);
    eprintln!("[cose] COSE_Sign1 size: {} bytes", cose_bytes.len());

    // Run benchmarks
    eprintln!("[cose] Benchmarking COSE signature verification...");
    let sig_latencies = bench_cose_signature_verify(&cose_bytes);

    eprintln!("[cose] Benchmarking certificate chain validation (3 certs)...");
    let chain_latencies = bench_cert_chain_verify(&cert_chain, &root_ca_der);

    eprintln!("[cose] Benchmarking CBOR payload parsing...");
    let parse_latencies = bench_payload_parse(&cose_bytes);

    eprintln!("[cose] Benchmarking full verification pipeline...");
    let full_latencies = bench_full_verification(&cose_bytes, &cert_chain, &root_ca_der);

    let sig_stats = latency_stats(&sig_latencies);
    let chain_stats = latency_stats(&chain_latencies);
    let parse_stats = latency_stats(&parse_latencies);
    let full_stats = latency_stats(&full_latencies);

    eprintln!("[cose] Results:");
    eprintln!(
        "[cose]   COSE signature verify: mean={:.4}ms",
        sig_stats["mean"]
    );
    eprintln!(
        "[cose]   Cert chain (3 certs):  mean={:.4}ms",
        chain_stats["mean"]
    );
    eprintln!(
        "[cose]   CBOR payload parse:    mean={:.4}ms",
        parse_stats["mean"]
    );
    eprintln!(
        "[cose]   Full pipeline:         mean={:.4}ms",
        full_stats["mean"]
    );

    let commit = option_env!("GIT_COMMIT").unwrap_or("unknown");
    let timestamp = ephemeral_ml_common::metrics::iso8601_now();

    let results = serde_json::json!({
        "benchmark": "cose_attestation_verification",
        "environment": "bare_metal",
        "hardware": instance_type,
        "timestamp": timestamp,
        "commit": commit,
        "iterations": NUM_ITERATIONS,
        "warmup": NUM_WARMUP,
        "cert_chain_depth": cert_chain.len(),
        "curve": "P-384 (secp384r1)",
        "hash": "SHA-384",
        "cose_sign1_size_bytes": cose_bytes.len(),
        "payload_size_bytes": payload_bytes.len(),
        "cose_signature_verify_ms": sig_stats,
        "cert_chain_verify_ms": chain_stats,
        "cbor_payload_parse_ms": parse_stats,
        "full_verification_ms": full_stats,
        "notes": {
            "cose_signature_verify": "Parse COSE_Sign1 + extract leaf cert from payload + coset verify_signature() + ecdsa_raw_to_der + ECDSA-P384-SHA384 verify",
            "cert_chain_verify": "Walk 3-cert chain (root→intermediate→leaf), verify each signature with issuer pubkey",
            "cbor_payload_parse": "Deserialize CBOR attestation payload (~1KB with certificate field)",
            "full_verification": "All three steps combined (COSE verify + chain walk + payload parse)",
            "curve_note": "AWS Nitro root CA uses P-384 (secp384r1). Test chain uses identical curve and key sizes.",
            "signature_format": "Raw (r||s) matching NSM output, converted to DER for OpenSSL verification"
        }
    });

    println!("{}", serde_json::to_string_pretty(&results)?);
    eprintln!("[cose] Benchmark complete");
    Ok(())
}
