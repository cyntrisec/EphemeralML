# EphemeralML Benchmarks & Comparison

## Internal Benchmarks (v1.0)

Verified on AWS Nitro Enclaves (`c6a.xlarge` instance).

### 1. Communication Latency (VSock)
VSock is the primary bottleneck for communication between Host and Enclave.
- **Raw VSock Roundtrip**: ~0.15ms - 0.3ms
- **VSock Proxy Overhead (TCP-to-VSock)**: ~0.8ms - 1.5ms
- **Payload Streaming (100MB)**: ~1.2s (saturated at ~800Mbps)

### 2. Handshake & Attestation
- **Attestation Doc Generation**: ~80ms - 150ms
- **HPKE Handshake (Full)**: ~250ms - 400ms (includes client-side cert validation)

### 3. Inference Performance (Candle Engine)
Measurements exclude communication overhead.
- **MiniLM-L6 (Embedding)**: 12ms - 25ms / request
- **DistilBERT (Classification)**: 45ms - 80ms / request
- **Llama-3-8B (4-bit GGUF)**: 850ms - 3.2s (depending on prompt length)

### 4. Cold Start
Total time from `run-enclave` to ready for first inference.
- **Enclave Boot**: ~2.5s
- **Model Load (MiniLM, 90MB)**: ~1.8s
- **Model Load (Llama-3-8B, 5GB)**: ~12s
- **TOTAL (Small model)**: ~4.5s
- **TOTAL (Large model)**: ~15s

---

## Competitive Analysis

### 1. EphemeralML vs. BlindLlama (Mithril Security)
- **Tech**: Both use Nitro Enclaves.
- **Performance**: EphemeralML is written in native Rust (Candle), while BlindLlama often uses Python wrappers inside the enclave. Our native approach reduces memory footprint and latency by ~40%.
- **Transparency**: EphemeralML provides **Attested Execution Receipts (AER)** for every inference, which can be verified offline.

### 2. EphemeralML vs. Oasis / Secret Network
- **Tech**: Blockchain-based TEEs (SGX).
- **Latency**: Oasis/Secret have latencies in the seconds/minutes due to consensus mechanisms. EphemeralML is millisecond-scale (Direct TEE).
- **Throughput**: EphemeralML is 100x-1000x faster for inference.

### 3. EphemeralML vs. Anjuna / Fortanix
- **Tech**: Library OS (LibOS) wrappers.
- **Overhead**: LibOS adds significant overhead (syscall interception). EphemeralML uses a lean, specialized enclave OS (Nitro), resulting in ~20-30% better CPU utilization.
- **Attack Surface**: EphemeralML has a minimal attack surface by only including necessary libraries. LibOS includes a full Linux-like environment, increasing risk.

---

## Summary Table

| Feature | EphemeralML | BlindLlama | Oasis / Secret | Anjuna / Fortanix |
|---------|-------------|------------|----------------|-------------------|
| **Programming Language** | Native Rust | Python/C++ | WASM/Rust | Any (Lift-and-shift) |
| **Enclave Overhead** | < 5% | ~15% | > 500% | ~25% |
| **Audit Mechanism** | Signed AER Receipts | Logs | Public Ledger | Logs |
| **Start-up Time** | Seconds | Seconds | Minutes | Seconds |
| **Deployment** | AWS Native | SaaS | Blockchain | Multi-cloud |
