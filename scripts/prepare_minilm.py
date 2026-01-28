import os
import hashlib
import json
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MODEL_ID = "mini-lm-v2"
BASE_URL = "https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main"

FILES = [
    "model.safetensors",
    "config.json",
    "tokenizer.json"
]

DEK = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
NONCE = bytes.fromhex("000102030405060708090a0b")

def download_and_prepare():
    os.makedirs("test_artifacts", exist_ok=True)
    
    manifest_data = {
        "model_id": MODEL_ID,
        "parts": {}
    }
    
    for filename in FILES:
        print(f"Downloading {filename}...")
        url = f"{BASE_URL}/{filename}"
        dest = f"test_artifacts/{filename}"
        os.system(f"curl -L -o {dest} {url}")
        
        with open(dest, "rb") as f:
            data = f.read()
            
        plaintext_hash = hashlib.sha256(data).hexdigest()
        
        if filename == "model.safetensors":
            s3_key = f"{MODEL_ID}-weights"
            print(f"Encrypting {filename} -> {s3_key}...")
            cipher = ChaCha20Poly1305(DEK)
            encrypted = NONCE + cipher.encrypt(NONCE, data, None)
            with open(f"test_artifacts/{s3_key}.enc", "wb") as f:
                f.write(encrypted)
            
            manifest_data["parts"]["weights"] = {
                "s3_key": s3_key,
                "plaintext_hash": plaintext_hash,
                "encrypted_hash": hashlib.sha256(encrypted).hexdigest(),
                "size_bytes": len(encrypted)
            }
        else:
            s3_key = f"{MODEL_ID}-{filename.split('.')[0]}"
            print(f"Storing {filename} -> {s3_key}...")
            with open(f"test_artifacts/{s3_key}.bin", "wb") as f:
                f.write(data)
            
            manifest_data["parts"][filename.split('.')[0]] = {
                "s3_key": s3_key,
                "plaintext_hash": plaintext_hash,
                "size_bytes": len(data)
            }

    with open("test_artifacts/mini-lm-manifest-full.json", "w") as f:
        json.dump(manifest_data, f, indent=2)
    
    print("Done! Artifacts in test_artifacts/")

if __name__ == "__main__":
    download_and_prepare()
