#!/usr/bin/env bash
# Download MiniLM-L6-v2 model weights for EphemeralML demo
# Uses symlink from confidential-ml-transport if available, otherwise downloads from HuggingFace
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODEL_DIR="$PROJECT_DIR/test_assets/minilm"

SYMLINK_SRC="/home/tsyrulb/vsock/confidential-ml-transport/examples/nitro-inference/model/model.safetensors"
HF_URL="https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main"

mkdir -p "$MODEL_DIR"

# Check if weights already exist (symlink or real file)
if [ -f "$MODEL_DIR/model.safetensors" ]; then
    echo "Model weights already present at $MODEL_DIR/model.safetensors"
    ls -lh "$MODEL_DIR/model.safetensors"
    exit 0
fi

# Try symlink first
if [ -f "$SYMLINK_SRC" ]; then
    echo "Symlinking model weights from confidential-ml-transport..."
    ln -sf "$SYMLINK_SRC" "$MODEL_DIR/model.safetensors"
    echo "Done: $MODEL_DIR/model.safetensors -> $SYMLINK_SRC"
    exit 0
fi

# Fall back to HuggingFace download
echo "Downloading model weights from HuggingFace..."
echo "  model.safetensors (~87MB)"

if command -v curl &>/dev/null; then
    curl -L -o "$MODEL_DIR/model.safetensors" "$HF_URL/model.safetensors"
elif command -v wget &>/dev/null; then
    wget -O "$MODEL_DIR/model.safetensors" "$HF_URL/model.safetensors"
else
    echo "ERROR: Neither curl nor wget found. Install one and retry."
    exit 1
fi

# Also download config and tokenizer if missing
if [ ! -f "$MODEL_DIR/config.json" ]; then
    echo "  config.json"
    curl -sL -o "$MODEL_DIR/config.json" "$HF_URL/config.json" 2>/dev/null || \
        wget -qO "$MODEL_DIR/config.json" "$HF_URL/config.json"
fi

if [ ! -f "$MODEL_DIR/tokenizer.json" ]; then
    echo "  tokenizer.json"
    curl -sL -o "$MODEL_DIR/tokenizer.json" "$HF_URL/tokenizer.json" 2>/dev/null || \
        wget -qO "$MODEL_DIR/tokenizer.json" "$HF_URL/tokenizer.json"
fi

echo "Model downloaded to $MODEL_DIR/"
ls -lh "$MODEL_DIR/"
