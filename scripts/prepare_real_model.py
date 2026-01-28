import os
import torch
from transformers import AutoModel, AutoTokenizer
from safetensors.torch import save_file
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_ID = "mini-lm-v2"

def prepare():
    print(f"Downloading {MODEL_NAME}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModel.from_pretrained(MODEL_NAME)
    
    # Save as safetensors
    os.makedirs("test_artifacts", exist_ok=True)
    weights_path = "test_artifacts/mini-lm-v2.safetensors"
    save_file(model.state_dict(), weights_path)
    
    with open(weights_path, "rb") as f:
        plaintext = f.read()
    
    plaintext_hash = hashlib.sha256(plaintext).hexdigest()
    
    # Encrypt
    dek = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    nonce = bytes.fromhex("000102030405060708090a0b")
    cipher = ChaCha20Poly1305(dek)
    encrypted = nonce + cipher.encrypt(nonce, plaintext, None)
    
    encrypted_path = f"test_artifacts/{MODEL_ID}.enc"
    with open(encrypted_path, "wb") as f:
        f.write(encrypted)
    
    # Save manifest info
    manifest = {
        "model_id": MODEL_ID,
        "plaintext_hash": plaintext_hash,
        "encrypted_hash": hashlib.sha256(encrypted).hexdigest(),
        "size_bytes": len(encrypted)
    }
    
    with open("test_artifacts/mini-lm-v2-manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    
    print(f"Prepared {MODEL_ID}")
    print(f"Plaintext Hash: {plaintext_hash}")
    print(f"Encrypted Hash: {manifest['encrypted_hash']}")
    print(f"Size: {len(encrypted) / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    prepare()
