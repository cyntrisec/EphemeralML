# Prepare encrypted model for S3 test

import os
import json
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def prepare_test_model():
    # 1. Create a dummy model file (SafeTensors-like structure)
    model_data = b"This is a fake model weight file for testing Nitro Enclaves S3 loading."
    model_hash = hashlib.sha256(model_data).hexdigest()
    
    # 2. Encrypt the model
    dek = os.urandom(32)
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(dek)
    encrypted_data = cipher.encrypt(nonce, model_data, None)
    
    # 3. Create manifest
    manifest = {
        "model_id": "test-model-001",
        "version": "1.0.0",
        "hash_sha256": model_hash,
        "encryption": {
            "algorithm": "ChaCha20-Poly1305",
            "nonce": nonce.hex()
        }
    }
    
    # Save files
    os.makedirs("test_artifacts", exist_ok=True)
    with open("test_artifacts/model.bin.enc", "wb") as f:
        f.write(encrypted_data)
    with open("test_artifacts/manifest.json", "w") as f:
        json.dump(manifest, f)
    
    print(f"Artifacts prepared in test_artifacts/")
    print(f"DEK (hex): {dek.hex()}")
    print(f"Model Hash: {model_hash}")

if __name__ == "__main__":
    prepare_test_model()
