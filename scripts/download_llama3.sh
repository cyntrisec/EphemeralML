#!/usr/bin/env bash
# Download Llama 3 8B Instruct Q4_K_M GGUF + tokenizer for EphemeralML.
#
# Usage:
#   bash scripts/download_llama3.sh [MODEL_DIR]
#
# The tokenizer requires a HuggingFace token with access to
# meta-llama/Meta-Llama-3-8B-Instruct. Set HF_TOKEN env var or
# run `huggingface-cli login` first.
set -euo pipefail

MODEL_DIR="${1:-test_assets/llama3}"
mkdir -p "$MODEL_DIR"

echo "Downloading Llama 3 8B Instruct Q4_K_M GGUF (~4.7 GB)..."
echo "Target: $MODEL_DIR"
echo

# Download Q4_K_M GGUF from bartowski's quantization
GGUF_URL="https://huggingface.co/bartowski/Meta-Llama-3-8B-Instruct-GGUF/resolve/main/Meta-Llama-3-8B-Instruct-Q4_K_M.gguf"

if [ -f "$MODEL_DIR/model.gguf" ]; then
    echo "model.gguf already exists, skipping download (delete to re-download)"
else
    wget -c -O "$MODEL_DIR/model.gguf" "$GGUF_URL"
fi

# Download tokenizer.json from NousResearch ungated mirror (no auth required)
TOKENIZER_URL="https://huggingface.co/NousResearch/Meta-Llama-3-8B-Instruct/resolve/main/tokenizer.json"

if [ -f "$MODEL_DIR/tokenizer.json" ]; then
    echo "tokenizer.json already exists, skipping download"
else
    echo "Downloading tokenizer.json from NousResearch mirror (no auth required)..."
    wget -c -O "$MODEL_DIR/tokenizer.json" "$TOKENIZER_URL"
fi

echo
echo "Model downloaded to $MODEL_DIR"
echo
echo "Files:"
ls -lh "$MODEL_DIR/"
echo
echo "Model hash (SHA-256):"
sha256sum "$MODEL_DIR/model.gguf"
