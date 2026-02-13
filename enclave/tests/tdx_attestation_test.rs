//! Integration tests for TDX attestation via TeeAttestationProvider.
//!
//! These tests use synthetic TDX quotes (no real hardware needed).
//! Run with: cargo test --features mock,tdx --test tdx_attestation_test

#[cfg(feature = "tdx")]
mod tests {
    use confidential_ml_transport::attestation::tdx::{
        build_synthetic_tdx_quote, encode_tdx_document,
    };
    use confidential_ml_transport::AttestationVerifier;
    use ephemeral_ml_enclave::tee_provider::{
        print_tdx_measurements, TeeAttestationEnvelope, TeeAttestationProvider,
    };
    use ephemeral_ml_enclave::AttestationProvider;
    use sha2::Digest;

    #[test]
    fn synthetic_attestation_roundtrip() {
        let provider = TeeAttestationProvider::synthetic();
        let nonce = [0xDE; 32];
        let receipt_key = [0x42; 32];

        // Generate attestation
        let doc = provider.generate_attestation(&nonce, receipt_key).unwrap();
        assert_eq!(doc.module_id, "tdx-cvm");

        // Decode envelope
        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();
        assert_eq!(envelope.platform, "tdx");

        // User data should contain our receipt key
        let ud: ephemeral_ml_enclave::AttestationUserData =
            serde_json::from_slice(&envelope.user_data).unwrap();
        assert_eq!(ud.receipt_signing_key, receipt_key);
        assert_eq!(ud.hpke_public_key, provider.get_hpke_public_key());
        assert_eq!(ud.protocol_version, 1);

        // TDX wire should be valid cml-transport format
        assert_eq!(&envelope.tdx_wire[..6], b"TDX_V1");
    }

    #[test]
    fn measurement_extraction_from_synthetic_quote() {
        // Build a quote with known measurement values
        let mrtd = [0x11; 48];
        let rtmrs = [[0x22; 48], [0x33; 48], [0x44; 48], [0x55; 48]];
        let reportdata = [0xFF; 64];

        let raw_quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);

        // Parse measurements
        let measurements = TeeAttestationProvider::parse_measurements(&raw_quote).unwrap();

        // MRTD → pcr0
        assert_eq!(measurements.pcr0, vec![0x11; 48]);
        // RTMR0 → pcr1
        assert_eq!(measurements.pcr1, vec![0x22; 48]);
        // RTMR1 → pcr2
        assert_eq!(measurements.pcr2, vec![0x33; 48]);

        // Parse REPORTDATA
        let rd = TeeAttestationProvider::parse_reportdata(&raw_quote).unwrap();
        assert_eq!(rd, [0xFF; 64]);
    }

    #[test]
    fn reportdata_binds_hpke_key_and_nonce() {
        let provider = TeeAttestationProvider::synthetic();
        let nonce = [0xAB; 32];
        let receipt_key = [0xCD; 32];

        let doc = provider.generate_attestation(&nonce, receipt_key).unwrap();
        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();

        // Extract raw quote from wire format (skip marker + size)
        let raw_quote = &envelope.tdx_wire[16..];
        let rd = TeeAttestationProvider::parse_reportdata(raw_quote).unwrap();

        // REPORTDATA[0..32] = HPKE public key
        assert_eq!(&rd[..32], &provider.get_hpke_public_key());
        // REPORTDATA[32..64] = nonce
        assert_eq!(&rd[32..64], &nonce);
    }

    #[test]
    fn wire_format_compatible_with_cml_transport() {
        // Build a quote using cml-transport's builder directly
        let reportdata = [0u8; 64];
        let mrtd = [0x01; 48];
        let rtmrs = [[0x02; 48], [0x03; 48], [0x04; 48], [0x05; 48]];

        let raw_quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        let wire = encode_tdx_document(&raw_quote);

        // Verify our parser handles it correctly
        assert_eq!(&wire[..6], b"TDX_V1");
        let quote_size = u32::from_le_bytes(wire[12..16].try_into().unwrap()) as usize;
        assert_eq!(wire.len(), 16 + quote_size);

        // Our measurement parser should work on the raw quote
        let measurements = TeeAttestationProvider::parse_measurements(&raw_quote).unwrap();
        assert_eq!(measurements.pcr0, vec![0x01; 48]);
        assert_eq!(measurements.pcr1, vec![0x02; 48]);
        assert_eq!(measurements.pcr2, vec![0x03; 48]);
    }

    #[test]
    fn cml_transport_verifier_accepts_synthetic_quote() {
        // This proves our wire format is compatible with cml-transport's TdxVerifier
        let provider = TeeAttestationProvider::synthetic();
        let nonce = [0u8; 32];
        let doc = provider.generate_attestation(&nonce, [0u8; 32]).unwrap();

        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();

        // Create cml-transport AttestationDocument and verify
        let cml_doc = confidential_ml_transport::attestation::types::AttestationDocument::new(
            envelope.tdx_wire,
        );

        let verifier = confidential_ml_transport::attestation::tdx::TdxVerifier::new(None);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(verifier.verify(&cml_doc));

        assert!(
            result.is_ok(),
            "TdxVerifier rejected our quote: {:?}",
            result.err()
        );

        let verified = result.unwrap();
        // Measurements should be present
        assert!(verified.measurements.contains_key(&0)); // MRTD
        assert!(verified.measurements.contains_key(&1)); // RTMR0
        assert!(verified.measurements.contains_key(&2)); // RTMR1

        // Public key should be extracted from REPORTDATA
        assert!(verified.public_key.is_some());
        assert_eq!(
            verified.public_key.unwrap(),
            provider.get_hpke_public_key().to_vec()
        );
    }

    #[test]
    fn print_measurements_smoke() {
        let mrtd = [0xAA; 48];
        let rtmrs = [[0xBB; 48], [0xCC; 48], [0xDD; 48], [0xEE; 48]];
        let reportdata = [0x42; 64];

        let raw_quote = build_synthetic_tdx_quote(reportdata, mrtd, rtmrs);
        print_tdx_measurements(&raw_quote).unwrap();
    }

    #[test]
    fn envelope_preserves_user_data_integrity() {
        let provider = TeeAttestationProvider::synthetic();
        let receipt_key = ephemeral_ml_common::ReceiptSigningKey::generate().unwrap();
        let receipt_pk = receipt_key.public_key_bytes();

        let doc = provider
            .generate_attestation(&[0u8; 32], receipt_pk)
            .unwrap();

        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();
        let ud: ephemeral_ml_enclave::AttestationUserData =
            serde_json::from_slice(&envelope.user_data).unwrap();

        // The receipt signing key in user_data must match what we passed in
        assert_eq!(ud.receipt_signing_key, receipt_pk);

        // Tamper detection: modifying envelope should change attestation hash
        let hash1: [u8; 32] = sha2::Sha256::digest(&doc.signature).into();

        let mut tampered_envelope = envelope.clone();
        tampered_envelope.user_data[0] ^= 0xFF;
        let tampered_bytes = tampered_envelope.to_cbor().unwrap();
        let hash2: [u8; 32] = sha2::Sha256::digest(&tampered_bytes).into();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn multiple_attestations_produce_unique_keypairs() {
        let p1 = TeeAttestationProvider::synthetic();
        let p2 = TeeAttestationProvider::synthetic();

        // Each provider should have a unique HPKE keypair
        assert_ne!(p1.get_hpke_public_key(), p2.get_hpke_public_key());
    }

    #[test]
    fn long_nonce_hashed_to_fit_reportdata() {
        let provider = TeeAttestationProvider::synthetic();
        let long_nonce = [0xFF; 64]; // > 32 bytes

        let doc = provider
            .generate_attestation(&long_nonce, [0u8; 32])
            .unwrap();

        let envelope = TeeAttestationEnvelope::from_cbor(&doc.signature).unwrap();
        let raw_quote = &envelope.tdx_wire[16..];
        let rd = TeeAttestationProvider::parse_reportdata(raw_quote).unwrap();

        // Nonce should be SHA-256 of the long nonce
        let expected: [u8; 32] = sha2::Sha256::digest(&long_nonce).into();
        assert_eq!(&rd[32..64], &expected);
    }
}
