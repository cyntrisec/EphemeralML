import os
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MODEL_ID = "large-bench-model"
SIZE_MB = 100

def prepare():
    print(f"Generating {SIZE_MB}MB dummy model...")
    plaintext = os.urandom(SIZE_MB * 1024 * 1024)
    plaintext_hash = hashlib.sha256(plaintext).hexdigest()
    
    # Encrypt
    dek = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    nonce = bytes.fromhex("000102030405060708090a0b")
    cipher = ChaCha20Poly1305(dek)
    encrypted = nonce + cipher.encrypt(nonce, plaintext, None)
    
    os.makedirs("test_artifacts", exist_ok=True)
    encrypted_path = f"test_artifacts/{MODEL_ID}.enc"
    with open(encrypted_path, "wb") as f:
        f.write(encrypted)
    
    print(f"Prepared {MODEL_ID}")
    print(f"Plaintext Hash: {plaintext_hash}")
    print(f"Encrypted Hash: {hashlib.sha256(encrypted).hexdigest()}")
    print(f"Size: {len(encrypted) / 1024 / 1024:.2f} MB")

if __name__ == "__main__":
    prepare()
