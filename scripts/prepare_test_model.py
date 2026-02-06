#!/usr/bin/env python3
"""
Prepare a properly formatted encrypted test model for EphemeralML S3 storage.

DETERMINISTIC version - uses fixed nonce and DEK for reproducible hashes.

This script generates:
1. A valid SafeTensors model file (plaintext)
2. SHA-256 hash of the plaintext (for ModelManifest verification)
3. Encrypted artifact in format: [12-byte nonce][ciphertext+tag]
4. Uploads to S3 under the model_id key

Usage:
    python prepare_test_model.py [--upload]
"""

import os
import sys
import json
import struct
import hashlib
import argparse
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


# ============================================================================
# Configuration
# ============================================================================
MODEL_ID = "test-model-001"
MODEL_VERSION = "1.0.0"
S3_BUCKET = os.environ.get("EPHEMERALML_S3_BUCKET", "ephemeral-ml-models-demo")

# FIXED values for deterministic output (test only - production uses random!)
FIXED_DEK = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
FIXED_NONCE = bytes.fromhex("000102030405060708090a0b")

OUTPUT_DIR = Path("test_artifacts")


def create_safetensors_model() -> bytes:
    """
    Create a minimal valid SafeTensors file.
    
    SafeTensors format:
    - 8 bytes: header length (u64 LE)
    - N bytes: JSON header with tensor metadata
    - M bytes: raw tensor data
    """
    # Create a simple tensor: 4 floats (16 bytes of data)
    tensor_data = struct.pack('<4f', 0.1, 0.2, 0.3, 0.4)
    
    # Header describes the tensor
    header = {
        "weights": {
            "dtype": "F32",
            "shape": [4],
            "data_offsets": [0, len(tensor_data)]
        }
    }
    
    # Encode header as JSON (deterministic: sorted keys, no spaces)
    header_json = json.dumps(header, separators=(',', ':'), sort_keys=True).encode('utf-8')
    
    # Build the file
    header_len = struct.pack('<Q', len(header_json))
    safetensors_bytes = header_len + header_json + tensor_data
    
    print(f"[+] Created SafeTensors model:")
    print(f"    Header: {header_json.decode()}")
    print(f"    Header length: {len(header_json)} bytes")
    print(f"    Tensor data: {len(tensor_data)} bytes")
    print(f"    Total size: {len(safetensors_bytes)} bytes")
    
    return safetensors_bytes


def encrypt_model(plaintext: bytes, dek: bytes, nonce: bytes) -> bytes:
    """
    Encrypt model using ChaCha20-Poly1305.
    
    Output format: [12-byte nonce][ciphertext || 16-byte auth tag]
    """
    cipher = ChaCha20Poly1305(dek)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    encrypted = nonce + ciphertext
    
    print(f"[+] Encrypted model:")
    print(f"    Nonce: {nonce.hex()}")
    print(f"    Ciphertext+tag: {len(ciphertext)} bytes")
    print(f"    Total encrypted: {len(encrypted)} bytes")
    
    return encrypted


def main():
    parser = argparse.ArgumentParser(description="Prepare encrypted test model for EphemeralML")
    parser.add_argument("--upload", action="store_true", help="Upload to S3")
    parser.add_argument("--bucket", default=S3_BUCKET, help=f"S3 bucket (default: {S3_BUCKET})")
    args = parser.parse_args()
    
    print("=" * 70)
    print("EphemeralML Test Model Preparation (DETERMINISTIC)")
    print("=" * 70)
    
    OUTPUT_DIR.mkdir(exist_ok=True)
    
    # Step 1: Create SafeTensors model
    print("\n[Step 1] Creating SafeTensors model...")
    plaintext = create_safetensors_model()
    
    # Step 2: Calculate PLAINTEXT hash (this goes in ModelManifest.model_hash)
    print("\n[Step 2] Calculating hashes...")
    plaintext_hash = hashlib.sha256(plaintext).digest()
    plaintext_hash_hex = plaintext_hash.hex()
    print(f"    PLAINTEXT SHA-256: {plaintext_hash_hex}")
    
    # Step 3: Encrypt with fixed DEK and nonce
    print("\n[Step 3] Encrypting model (deterministic)...")
    print(f"    Using fixed DEK: {FIXED_DEK.hex()[:16]}...")
    print(f"    Using fixed nonce: {FIXED_NONCE.hex()}")
    encrypted = encrypt_model(plaintext, FIXED_DEK, FIXED_NONCE)
    
    # Step 4: Calculate encrypted artifact hash (just for reference)
    encrypted_hash_hex = hashlib.sha256(encrypted).hexdigest()
    print(f"\n[+] Encrypted artifact SHA-256: {encrypted_hash_hex}")
    
    # Step 5: Save files
    print("\n[Step 4] Saving artifacts...")
    (OUTPUT_DIR / "model.safetensors").write_bytes(plaintext)
    (OUTPUT_DIR / f"{MODEL_ID}.enc").write_bytes(encrypted)
    (OUTPUT_DIR / "dek.bin").write_bytes(FIXED_DEK)
    
    manifest = {
        "model_id": MODEL_ID,
        "version": MODEL_VERSION,
        "plaintext_hash_sha256": plaintext_hash_hex,
        "encrypted_hash_sha256": encrypted_hash_hex,
        "dek_hex": FIXED_DEK.hex(),
        "nonce_hex": FIXED_NONCE.hex(),
        "format": "safetensors",
        "encryption": {
            "algorithm": "ChaCha20-Poly1305",
            "nonce_bytes": 12,
            "key_bytes": 32,
            "format": "[nonce][ciphertext+tag]"
        }
    }
    (OUTPUT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"    ✓ Saved to {OUTPUT_DIR}/")
    
    # Step 6: Upload
    if args.upload:
        print(f"\n[Step 5] Uploading to S3...")
        if not HAS_BOTO3:
            print("    ERROR: pip install boto3")
            sys.exit(1)
        
        s3 = boto3.client('s3')
        try:
            s3.put_object(Bucket=args.bucket, Key=MODEL_ID, Body=encrypted)
            print(f"    ✓ Uploaded to s3://{args.bucket}/{MODEL_ID}")
        except Exception as e:
            print(f"    ERROR: {e}")
            sys.exit(1)
    else:
        print(f"\n[!] To upload: aws s3 cp {OUTPUT_DIR}/{MODEL_ID}.enc s3://{args.bucket}/{MODEL_ID}")
    
    # Summary
    print("\n" + "=" * 70)
    print("COPY THIS TO enclave/src/main.rs:")
    print("=" * 70)
    print(f"""
// For boot health check (verifying RAW S3 fetch works):
// The manifest.model_hash should be the PLAINTEXT hash for full flow.
// But boot check currently hashes the encrypted bytes - this is a bug.
//
// CORRECT approach: manifest.model_hash = hash of PLAINTEXT
let manifest = ModelManifest {{
    model_id: "{MODEL_ID}".to_string(),
    version: "{MODEL_VERSION}".to_string(),
    model_hash: hex::decode("{plaintext_hash_hex}").unwrap(),
    hash_algorithm: "sha256".to_string(),
    key_id: "test".to_string(),
    signature: vec![0u8; 64],
}};

// DEK (for KMS mock or testing):
// {FIXED_DEK.hex()}
""")
    
    print("[✓] Done! Files are deterministic and reproducible.")


if __name__ == "__main__":
    main()
