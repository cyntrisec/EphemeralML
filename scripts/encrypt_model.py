#!/usr/bin/env python3
import boto3
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Config
# IMPORTANT: Do not hardcode account-specific KMS key ARNs in-repo.
# Export `EPHEMERALML_KMS_KEY_ARN` before running.
KEY_ARN = os.environ.get("EPHEMERALML_KMS_KEY_ARN", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

INPUT_FILE = os.environ.get("EPHEMERALML_MODEL_INPUT", "test_assets/minilm/model.safetensors")
OUTPUT_FILE = os.environ.get("EPHEMERALML_MODEL_OUTPUT", "test_assets/minilm/model.safetensors.encrypted")
OUTPUT_DEK_FILE = os.environ.get("EPHEMERALML_MODEL_DEK_WRAPPED", "test_assets/minilm/model.dek.wrapped")

def encrypt_model():
    print(f"🔐 Starting envelope encryption for {INPUT_FILE}...")
    
    if not KEY_ARN:
        raise SystemExit("❌ EPHEMERALML_KMS_KEY_ARN is not set")

    # 1. Initialize AWS KMS client
    kms = boto3.client('kms', region_name=AWS_REGION)
    
    # 2. Generate a Data Encryption Key (DEK)
    print("💎 Generating Data Encryption Key (DEK) via KMS...")
    response = kms.generate_data_key(KeyId=KEY_ARN, KeySpec='AES_256')
    plaintext_dek = response['Plaintext']
    ciphertext_dek = response['CiphertextBlob']
    
    # 3. Read the model weights
    with open(INPUT_FILE, 'rb') as f:
        data = f.read()
    
    # 4. Encrypt the data locally using ChaCha20-Poly1305
    # (matches enclave decryption in model_loader.rs and prepare_benchmark_model.sh)
    print("⚡ Encrypting model weights with ChaCha20-Poly1305...")
    cipher = ChaCha20Poly1305(plaintext_dek)
    nonce = os.urandom(12)  # ChaCha20-Poly1305 standard nonce size
    ciphertext = cipher.encrypt(nonce, data, None)
    
    # 5. Save the encrypted model (nonce + ciphertext)
    with open(OUTPUT_FILE, 'wb') as f:
        f.write(nonce + ciphertext)
    
    # 6. Save the wrapped DEK
    with open(OUTPUT_DEK_FILE, 'wb') as f:
        f.write(ciphertext_dek)
    
    print(f"✅ Success!")
    print(f"📦 Encrypted Model: {OUTPUT_FILE} ({len(nonce+ciphertext)} bytes)")
    print(f"🔑 Wrapped DEK: {OUTPUT_DEK_FILE} ({len(ciphertext_dek)} bytes)")
    print("------------------------------------------")
    print("Note: The host can see these files, but only the attested Enclave can unwrap the DEK.")

if __name__ == "__main__":
    if not os.path.exists(INPUT_FILE):
        print(f"❌ Error: {INPUT_FILE} not found. Run this from projects/EphemeralML directory or set EPHEMERALML_MODEL_INPUT.")
    elif not KEY_ARN:
        print("❌ Error: EPHEMERALML_KMS_KEY_ARN not set. Example:\n"
              "  export EPHEMERALML_KMS_KEY_ARN=arn:aws:kms:REGION:ACCOUNT:key/KEY_ID")
    else:
        encrypt_model()
