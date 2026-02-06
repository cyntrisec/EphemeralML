# Adversarial Host Research Plan: VSock Traffic Analysis Attack on Nitro Enclaves

**Project:** EphemeralML Metadata Leakage Analysis
**Target:** Demonstrate whether a malicious Nitro host can classify encrypted inference input domains
**Status:** Planning Phase (v2 - Corrected)
**Created:** February 2026
**Last Updated:** February 2026

---

## Executive Summary

This research investigates whether an untrusted host in AWS Nitro Enclaves can infer the semantic domain (medical, legal, financial, general) of encrypted inference requests using only observable VSock metadata. This directly stress-tests EphemeralML's threat model, where the host is assumed to be a "blind relay" that cannot learn anything about encrypted payloads.

**Hypothesis:** A malicious host observing VSock traffic metadata (packet sizes, timing, inter-arrival gaps) can classify the domain of encrypted inference inputs with accuracy significantly above random chance (>25% for 4 classes).

**Novelty:** No published work has measured metadata leakage on Nitro Enclaves for ML inference.

---

## Critical Architecture Note

### Current State: No Host Relay for Inference

The current codebase has **no TCP-to-VSock relay for inference traffic**:

| Component | Handles | Location |
|-----------|---------|----------|
| `kms_proxy_host.rs` | KMS, Storage, Audit only | `host/src/bin/` |
| `enclave/server.rs` | Direct VSock listener (production) | Enclave-side |
| `enclave/mock.rs` | Direct TCP listener (mock mode) | Same process as client |

**Problem:** Clients currently connect directly to the enclave. There's no host-observable inference gateway.

### Required: Inference Gateway Binary

For this experiment (and realistic deployment), we must create:

```
┌─────────────────────────────────────────────────────────────┐
│                         HOST                                │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           inference_gateway (NEW BINARY)              │  │
│  │  - TCP listener (external clients)                    │  │
│  │  - VSock client (to enclave)                          │  │
│  │  - TrafficLogger (for this experiment)                │  │
│  │  - Pure byte relay (no decryption)                    │  │
│  └───────────────────────────────────────────────────────┘  │
│                    TCP :8443  ←──┼──→  VSock CID:16:5000    │
└───────────────────────────────────┼──────────────────────────┘
                                    │
┌───────────────────────────────────┼──────────────────────────┐
│                         ENCLAVE                              │
│                    VSock listener :5000                      │
│  MessageType::Hello → ClientHello/ServerHello               │
│  MessageType::Data  → EncryptedMessage (inference)          │
└──────────────────────────────────────────────────────────────┘
```

**This gateway is also a Phase 3 roadmap item** (HTTP transport bridge) — building it serves dual purposes.

---

## 1. Literature Foundation

### 1.1 Foundational Papers (Local)

| Paper | Venue | Key Insight | Relevance |
|-------|-------|-------------|-----------|
| [Controlled-Channel Attacks](../papers/side_channel_research/controlled_channel_sgx_2015.md) | IEEE S&P 2015 | Untrusted OS can extract secrets via page fault patterns | Establishes threat model |
| [Pacer](../papers/side_channel_research/pacer_usenix22.md) | USENIX Security 2022 | Network side-channels leak via timing/size; 96% video classification | Traffic shaping defense |
| [CipherLeaks](../papers/side_channel_research/cipherleaks_usenix21.md) | USENIX Security 2021 | AMD SEV ciphertext changes leak execution state | Metadata leakage persists |
| [Branch History Attack](../papers/side_channel_research/branch_history_usenix25.md) | arXiv 2025 | BPU features create new attack surfaces | Modern CPU side-channels |

### 1.2 Critical External Research

| Paper | Key Finding | Application |
|-------|-------------|-------------|
| [Whisper Leak](https://arxiv.org/abs/2511.03675) | 98%+ accuracy classifying LLM topics from encrypted traffic | Validates high-accuracy domain classification |
| [Wiretapping LLMs](https://eprint.iacr.org/2025/167) | Token lengths inferable from encrypted LLM traffic | Token-level granularity possible |
| [Trail of Bits Nitro](https://blog.trailofbits.com/2024/09/24/notes-on-aws-nitro-enclaves-attack-surface/) | Host can measure with near-system-clock precision | Confirms timing attacks viable |
| [Cloudflare Mitigation](https://blog.cloudflare.com/ai-side-channel-attack-mitigated/) | Padding mitigates token-length attacks | Informs defense evaluation |

---

## 2. Threat Model

### 2.1 Attacker Capabilities

The adversary operates the **inference gateway** on the host. It can:

1. **Observe all TCP/VSock traffic** between client and enclave
2. **Measure precise timestamps** (nanosecond resolution via `Instant`)
3. **Record ciphertext sizes** of HPKE-encrypted payloads
4. **Count messages** and compute inter-arrival times
5. **Correlate across sessions** to build profiles

The adversary **cannot**:
- Decrypt HPKE payloads (no access to session keys)
- Access enclave memory
- Modify messages without detection (AEAD integrity)
- Break cryptographic primitives

### 2.2 Observable Features Per Inference Request

| Feature | Source | Leakage Potential |
|---------|--------|-------------------|
| `request_ciphertext_bytes` | EncryptedMessage size | **Primary:** Correlates with input token count |
| `response_ciphertext_bytes` | EncryptedMessage size | Fixed for embeddings (384 × f32 + overhead) |
| `inference_latency_ns` | Time between request/response | **Secondary:** Correlates with input length |
| `session_setup_ns` | Hello round-trip | Should be constant |
| `iat_request_ns` | Inter-arrival time | May reveal user behavior |

**Key insight:** For embedding models, response size is constant. Attack must rely on:
1. Request ciphertext size (input length → ciphertext length)
2. Inference latency (longer inputs → more computation)

---

## 3. Dataset Design

### 3.1 Current Dataset Issues

**Problem 1: Base64 noise is too easy**
- Base64 tokenizes very differently from natural language
- Classifier may learn "noise vs text" not "domain classification"

**Problem 2: Length confounds**
- If medical texts are systematically shorter than legal texts, classifier learns length
- We need ablation to separate length leakage from semantic leakage

### 3.2 Corrected Dataset

| Domain | Source | Samples | Purpose |
|--------|--------|---------|---------|
| Medical | Holden's Landmarks | 1,000 | Domain A |
| Legal | Federalist Papers | 1,000 | Domain B |
| Financial | Wealth of Nations | 1,000 | Domain C |
| **General** | **Wikipedia/news excerpts** | 1,000 | **Realistic control (replaces random)** |

**Preprocessing:**
- Normalize to common length ranges OR explicitly control length in ablation
- Strip metadata that could leak domain
- Verify token distributions overlap sufficiently

### 3.3 Length-Controlled Condition (Critical Fix)

**Wrong approach:** "Pad to 256 tokens" after tokenization
- HPKE ciphertext length still varies with input byte length

**Correct approach:** Pad plaintext bytes before encryption
```python
# Before HPKE encryption
MAX_PLAINTEXT_SIZE = 4096  # bytes
plaintext_bytes = json.dumps(inference_request).encode()
padded = plaintext_bytes + b'\x00' * (MAX_PLAINTEXT_SIZE - len(plaintext_bytes))
ciphertext = hpke_encrypt(padded, session_key)
# Now all ciphertexts are identical size
```

This requires modifying the client to support padding mode for the experiment.

---

## 4. Ablation Experiments

To produce publishable results, we must demonstrate **what** is leaking:

| Experiment | Features Used | Plaintext Padding | Purpose |
|------------|---------------|-------------------|---------|
| **A1: Size-only** | `request_ciphertext_bytes` only | None | Isolate size leakage |
| **A2: Timing-only** | `inference_latency_ns` only | **Constant (4KB)** | Isolate timing leakage |
| **A3: Full features** | Size + timing + IAT | None | Maximum attack signal |
| **A4: Defended** | Size + timing | Constant + random delay | Evaluate mitigations |

**Expected outcomes:**
- If A1 >> random: Size leakage dominates, padding is critical
- If A2 >> random: Timing leakage persists, need constant-time inference
- If A3 ≈ A1: No additional signal from timing (good for embeddings)
- If A4 ≈ random: Mitigations are effective

---

## 5. Implementation Plan

### Phase 1: Inference Gateway Binary

**New file:** `host/src/bin/inference_gateway.rs`

```rust
//! TCP-to-VSock relay for inference traffic with traffic logging.
//!
//! This binary:
//! 1. Accepts TCP connections from external clients
//! 2. Forwards to enclave via VSock (production) or TCP (mock)
//! 3. Logs observable metadata for adversarial analysis
//! 4. Acts as a pure byte relay (no decryption)

use std::sync::Arc;
use std::time::Instant;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[cfg(feature = "production")]
use tokio_vsock::VsockStream;

/// Buffered traffic logger - avoids disk I/O during measurement
struct TrafficLogger {
    buffer: Vec<TrafficEvent>,
    capacity: usize,
}

#[derive(Clone)]
struct TrafficEvent {
    timestamp_ns: u64,          // Monotonic nanoseconds
    session_id: u64,            // Correlation key (from connection order)
    direction: Direction,       // Inbound (client→enclave) or Outbound
    msg_type: u8,               // MessageType discriminant
    payload_len: usize,         // Ciphertext length
    sequence: u32,              // Message sequence within session
}

#[derive(Clone, Copy)]
enum Direction {
    Inbound,   // Client → Gateway → Enclave
    Outbound,  // Enclave → Gateway → Client
}

impl TrafficLogger {
    fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
        }
    }

    fn log(&mut self, event: TrafficEvent) {
        if self.buffer.len() < self.capacity {
            self.buffer.push(event);
        }
        // Silently drop if full - don't block on I/O
    }

    fn flush_to_file(&self, path: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(path)?;
        writeln!(f, "timestamp_ns,session_id,direction,msg_type,payload_len,sequence")?;
        for e in &self.buffer {
            writeln!(f, "{},{},{:?},{},{},{}",
                e.timestamp_ns, e.session_id, e.direction,
                e.msg_type, e.payload_len, e.sequence)?;
        }
        Ok(())
    }
}

async fn relay_connection(
    mut client: TcpStream,
    enclave_addr: &str,
    session_id: u64,
    logger: Arc<Mutex<TrafficLogger>>,
    start_time: Instant,
) -> anyhow::Result<()> {
    #[cfg(feature = "production")]
    let mut enclave = VsockStream::connect(16, 5000).await?;
    #[cfg(not(feature = "production"))]
    let mut enclave = TcpStream::connect(enclave_addr).await?;

    let mut inbound_seq = 0u32;
    let mut outbound_seq = 0u32;

    // Simple relay loop with logging
    let mut client_buf = vec![0u8; 65536];
    let mut enclave_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            // Client → Enclave
            result = client.read(&mut client_buf) => {
                let n = result?;
                if n == 0 { break; }

                let now = start_time.elapsed().as_nanos() as u64;
                let msg_type = if n >= 5 { client_buf[4] } else { 0 };

                logger.lock().log(TrafficEvent {
                    timestamp_ns: now,
                    session_id,
                    direction: Direction::Inbound,
                    msg_type,
                    payload_len: n,
                    sequence: inbound_seq,
                });
                inbound_seq += 1;

                enclave.write_all(&client_buf[..n]).await?;
            }

            // Enclave → Client
            result = enclave.read(&mut enclave_buf) => {
                let n = result?;
                if n == 0 { break; }

                let now = start_time.elapsed().as_nanos() as u64;
                let msg_type = if n >= 5 { enclave_buf[4] } else { 0 };

                logger.lock().log(TrafficEvent {
                    timestamp_ns: now,
                    session_id,
                    direction: Direction::Outbound,
                    msg_type,
                    payload_len: n,
                    sequence: outbound_seq,
                });
                outbound_seq += 1;

                client.write_all(&enclave_buf[..n]).await?;
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listen_port: u16 = std::env::var("GATEWAY_PORT")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(8443);
    let enclave_addr = std::env::var("ENCLAVE_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:5000".to_string());
    let log_capacity: usize = std::env::var("LOG_CAPACITY")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let output_path = std::env::var("TRAFFIC_LOG")
        .unwrap_or_else(|_| "/tmp/traffic_log.csv".to_string());

    let logger = Arc::new(Mutex::new(TrafficLogger::new(log_capacity)));
    let start_time = Instant::now();

    let listener = TcpListener::bind(format!("0.0.0.0:{}", listen_port)).await?;
    println!("Inference gateway listening on port {}", listen_port);

    let mut session_counter = 0u64;

    // Graceful shutdown handler
    let logger_clone = logger.clone();
    let output_clone = output_path.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        println!("Flushing traffic log...");
        logger_clone.lock().flush_to_file(&output_clone).ok();
        std::process::exit(0);
    });

    loop {
        let (client, addr) = listener.accept().await?;
        println!("Connection from {:?}, session {}", addr, session_counter);

        let logger = logger.clone();
        let enclave_addr = enclave_addr.clone();
        let session_id = session_counter;
        session_counter += 1;

        tokio::spawn(async move {
            if let Err(e) = relay_connection(
                client, &enclave_addr, session_id, logger, start_time
            ).await {
                eprintln!("Session {} error: {}", session_id, e);
            }
        });
    }
}
```

**Key design decisions:**
- **Buffered logging:** All events stored in memory, flushed on shutdown
- **No disk I/O in hot path:** Prevents timing distortion
- **Minimal parsing:** Only extract msg_type byte, don't deserialize
- **Session correlation:** `session_id` links request/response pairs

### Phase 2: Client Padding Mode

**Modify:** `client/src/secure_client.rs`

Add optional plaintext padding before HPKE encryption:

```rust
impl SecureClient {
    /// Execute inference with optional plaintext padding for experiments
    pub async fn execute_inference_padded(
        &mut self,
        model_id: &str,
        input: Vec<f32>,
        pad_to_bytes: Option<usize>,
    ) -> Result<InferenceResult, ClientError> {
        let request = InferenceHandlerInput {
            model_id: model_id.to_string(),
            input_data: input,
            input_shape: None,
        };

        let mut plaintext = serde_json::to_vec(&request)?;

        // Apply plaintext padding if specified
        if let Some(target_size) = pad_to_bytes {
            if plaintext.len() < target_size {
                plaintext.resize(target_size, 0u8);
            }
        }

        let encrypted = self.session.encrypt(&plaintext)?;
        // ... rest unchanged
    }
}
```

### Phase 3: Data Collection Pipeline

**File:** `scripts/collect_adversarial_data.py`

```python
#!/usr/bin/env python3
"""
Collect traffic metadata for adversarial host experiment.
Runs inference through the gateway and collects host-observable features.
"""

import asyncio
import json
import random
import subprocess
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

DATASET_PATH = Path("/path/to/adversarial_data")
OUTPUT_DIR = Path("benchmark_results/adversarial")

@dataclass
class Sample:
    path: Path
    domain: str
    text: str

@dataclass
class ExperimentConfig:
    name: str
    pad_to_bytes: Optional[int]  # None = no padding
    add_delay_ms: Optional[int]  # None = no delay


def load_samples() -> List[Sample]:
    """Load all samples from dataset directories."""
    samples = []
    for domain in ["medical", "legal", "financial", "general"]:
        domain_path = DATASET_PATH / domain
        for sample_file in sorted(domain_path.glob("*.txt")):
            text = sample_file.read_text().strip()
            samples.append(Sample(sample_file, domain, text))
    return samples


def run_inference(sample: Sample, config: ExperimentConfig) -> dict:
    """
    Run single inference through the gateway.
    Returns observable metadata (NOT the actual inference result).
    """
    # Use the client binary with appropriate flags
    cmd = [
        "./target/release/ephemeral-client",
        "--gateway", "127.0.0.1:8443",
        "--model", "minilm-l6",
        "--input", sample.text,
    ]

    if config.pad_to_bytes:
        cmd.extend(["--pad-bytes", str(config.pad_to_bytes)])

    start = time.perf_counter_ns()
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    end = time.perf_counter_ns()

    return {
        "domain": sample.domain,
        "sample_path": str(sample.path),
        "input_length_chars": len(sample.text),
        "client_observed_latency_ns": end - start,
        "experiment": config.name,
    }


async def run_experiment(config: ExperimentConfig, samples: List[Sample], runs: int = 3):
    """Run full experiment with multiple independent runs."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for run_idx in range(runs):
        print(f"Run {run_idx + 1}/{runs} for experiment '{config.name}'")

        # Shuffle samples to avoid ordering effects
        shuffled = samples.copy()
        random.shuffle(shuffled)

        # Start gateway with fresh log
        gateway_log = OUTPUT_DIR / f"{config.name}_run{run_idx}_gateway.csv"
        # ... start gateway process with TRAFFIC_LOG=gateway_log

        results = []
        for i, sample in enumerate(shuffled):
            if i % 100 == 0:
                print(f"  Progress: {i}/{len(shuffled)}")
            result = run_inference(sample, config)
            results.append(result)

        # ... stop gateway, flush log

        # Save client-side metadata
        client_log = OUTPUT_DIR / f"{config.name}_run{run_idx}_client.json"
        with open(client_log, "w") as f:
            json.dump(results, f, indent=2)


async def main():
    samples = load_samples()
    print(f"Loaded {len(samples)} samples")

    # Define ablation experiments
    experiments = [
        ExperimentConfig("baseline", pad_to_bytes=None, add_delay_ms=None),
        ExperimentConfig("padded_4k", pad_to_bytes=4096, add_delay_ms=None),
        ExperimentConfig("padded_delayed", pad_to_bytes=4096, add_delay_ms=50),
    ]

    for config in experiments:
        await run_experiment(config, samples, runs=3)


if __name__ == "__main__":
    asyncio.run(main())
```

### Phase 4: Classifier Training with Ablations

**File:** `scripts/train_adversarial_classifier.py`

```python
#!/usr/bin/env python3
"""
Train classifiers with ablation analysis.
"""

import json
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, f1_score
)
import warnings
warnings.filterwarnings('ignore')


def load_and_merge_logs(experiment_name: str, run_idx: int) -> pd.DataFrame:
    """Merge gateway log (host-observable) with client log (ground truth)."""
    gateway_path = f"benchmark_results/adversarial/{experiment_name}_run{run_idx}_gateway.csv"
    client_path = f"benchmark_results/adversarial/{experiment_name}_run{run_idx}_client.json"

    gateway_df = pd.read_csv(gateway_path)
    with open(client_path) as f:
        client_data = json.load(f)

    # Join on session_id / sample order
    # ... implementation details

    return merged_df


def run_ablation(df: pd.DataFrame, feature_sets: dict) -> dict:
    """
    Run classifiers with different feature subsets.

    feature_sets = {
        "size_only": ["request_ciphertext_bytes"],
        "timing_only": ["inference_latency_ns"],
        "full": ["request_ciphertext_bytes", "inference_latency_ns", "iat_ns"],
    }
    """
    results = {}

    for ablation_name, features in feature_sets.items():
        print(f"\n=== Ablation: {ablation_name} ===")
        print(f"Features: {features}")

        X = df[features].fillna(0)
        y = df["domain"]

        # Stratified 5-fold cross-validation
        cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scaler = StandardScaler()

        classifiers = {
            "RandomForest": RandomForestClassifier(n_estimators=100, random_state=42),
            "GradientBoosting": GradientBoostingClassifier(n_estimators=100, random_state=42),
            "LogisticRegression": LogisticRegression(max_iter=1000, random_state=42),
        }

        ablation_results = {}

        for clf_name, clf in classifiers.items():
            fold_accuracies = []
            fold_f1s = []

            for train_idx, test_idx in cv.split(X, y):
                X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
                y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

                X_train_scaled = scaler.fit_transform(X_train)
                X_test_scaled = scaler.transform(X_test)

                clf.fit(X_train_scaled, y_train)
                y_pred = clf.predict(X_test_scaled)

                fold_accuracies.append(accuracy_score(y_test, y_pred))
                fold_f1s.append(f1_score(y_test, y_pred, average='macro'))

            acc_mean = np.mean(fold_accuracies)
            acc_std = np.std(fold_accuracies)
            f1_mean = np.mean(fold_f1s)
            f1_std = np.std(fold_f1s)

            print(f"  {clf_name}: Acc={acc_mean:.4f}±{acc_std:.4f}, "
                  f"Macro-F1={f1_mean:.4f}±{f1_std:.4f}")

            ablation_results[clf_name] = {
                "accuracy_mean": acc_mean,
                "accuracy_std": acc_std,
                "macro_f1_mean": f1_mean,
                "macro_f1_std": f1_std,
            }

            # Feature importance for interpretability
            if hasattr(clf, "feature_importances_"):
                ablation_results[clf_name]["feature_importance"] = dict(
                    zip(features, clf.feature_importances_)
                )

        results[ablation_name] = ablation_results

    return results


def compute_confusion_matrix(df: pd.DataFrame, best_features: list) -> np.ndarray:
    """Train best model on full data, report confusion matrix."""
    X = df[best_features].fillna(0)
    y = df["domain"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train_scaled, y_train)
    y_pred = clf.predict(X_test_scaled)

    print("\n=== Final Classification Report ===")
    print(classification_report(y_test, y_pred))

    print("\n=== Confusion Matrix ===")
    cm = confusion_matrix(y_test, y_pred, labels=["medical", "legal", "financial", "general"])
    print(pd.DataFrame(cm,
        index=["true:medical", "true:legal", "true:financial", "true:general"],
        columns=["pred:medical", "pred:legal", "pred:financial", "pred:general"]
    ))

    return cm


def main():
    # Aggregate across runs
    all_runs = []
    for run_idx in range(3):
        df = load_and_merge_logs("baseline", run_idx)
        df["run"] = run_idx
        all_runs.append(df)

    combined = pd.concat(all_runs, ignore_index=True)
    print(f"Total samples: {len(combined)}")

    # Define feature sets for ablation
    feature_sets = {
        "size_only": ["request_payload_len"],
        "timing_only": ["inference_latency_ns"],
        "size_timing": ["request_payload_len", "inference_latency_ns"],
        "full": ["request_payload_len", "response_payload_len",
                 "inference_latency_ns", "session_setup_ns", "iat_ns"],
    }

    results = run_ablation(combined, feature_sets)

    # Save results
    with open("benchmark_results/adversarial/ablation_results.json", "w") as f:
        json.dump(results, f, indent=2)

    # Confusion matrix for best model
    compute_confusion_matrix(combined, feature_sets["full"])


if __name__ == "__main__":
    main()
```

---

## 6. Evaluation Methodology

### 6.1 Statistical Rigor

| Requirement | Implementation |
|-------------|----------------|
| Multiple runs | 3 independent runs per experiment |
| Cross-validation | 5-fold stratified CV |
| Shuffling | Random sample order per run |
| Confidence intervals | Mean ± std reported for all metrics |
| Avoid ordering effects | Train/test split doesn't leak temporal patterns |

### 6.2 Metrics Reported

| Metric | Purpose |
|--------|---------|
| **Accuracy** | Overall correctness |
| **Macro-F1** | Balanced per-class performance |
| **Per-class Precision/Recall** | Identify which domains leak most |
| **Confusion Matrix** | Visualize misclassification patterns |
| **Feature Importance** | Identify which features leak most |

### 6.3 Baseline Comparisons

| Baseline | Expected Accuracy | Purpose |
|----------|-------------------|---------|
| Random chance | 25% (4 classes) | Lower bound |
| Majority class | ~25% (balanced dataset) | Naive baseline |
| Length-only oracle | Varies | Upper bound for size leakage |

---

## 7. Success Criteria

| Accuracy | Interpretation | Action |
|----------|----------------|--------|
| 25% | Random chance — strong defense | Publish as validation |
| 25-40% | Weak signal — marginal concern | Investigate feature importance |
| 40-60% | Moderate leakage — significant finding | Recommend mitigations |
| 60-80% | Strong leakage — vulnerability | Critical finding, prioritize defenses |
| >80% | Critical leakage | Major vulnerability disclosure |

**Ablation interpretation:**
- If size_only >> timing_only: Padding is critical mitigation
- If timing_only >> random: Constant-time inference needed
- If padded experiment ≈ random: Padding is effective
- If padded_delayed ≈ random: Combined defense works

---

## 8. Implementation Checklist

### Phase 1: Infrastructure
- [ ] Create `host/src/bin/inference_gateway.rs`
- [ ] Implement `TrafficLogger` with buffered I/O
- [ ] Add `--pad-bytes` flag to client
- [ ] Test gateway in mock mode
- [ ] Deploy and test on Nitro

### Phase 2: Dataset
- [ ] Replace "random" with "general" (Wikipedia excerpts)
- [ ] Verify length distributions across domains
- [ ] Create length-normalized subset

### Phase 3: Data Collection
- [ ] Implement `collect_adversarial_data.py`
- [ ] Run baseline experiment (3 runs)
- [ ] Run padded experiment (3 runs)
- [ ] Run padded+delayed experiment (3 runs)

### Phase 4: Analysis
- [ ] Implement `train_adversarial_classifier.py`
- [ ] Run all ablations
- [ ] Generate confusion matrices
- [ ] Compute feature importance rankings
- [ ] Statistical significance tests

### Phase 5: Reporting
- [ ] Write results section
- [ ] Create visualizations
- [ ] Document methodology for reproducibility

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Gateway introduces timing noise | Medium | Distorted measurements | Use buffered logging, benchmark overhead |
| Domain lengths strongly correlated | High | Confounded results | Run timing-only ablation with padding |
| Insufficient samples | Low | Low power | 4,000 samples is adequate per literature |
| Classifier overfitting | Medium | Inflated accuracy | 5-fold CV, multiple runs |
| Mock mode differs from production | Medium | Non-generalizable | Final validation on real Nitro |

---

## 10. Timeline

| Week | Tasks |
|------|-------|
| 1 | Implement inference_gateway.rs, client padding mode |
| 2 | Prepare dataset (replace random with general), collection pipeline |
| 3 | Run experiments (baseline, padded, padded+delayed) × 3 runs each |
| 4 | Train classifiers, ablation analysis, write-up |

---

## 11. Appendix: Quick Start

```bash
# 1. Build all binaries
cargo build --release --bin inference_gateway
cargo build --release --bin ephemeral-client

# 2. Start enclave (mock mode for development)
./target/release/ephemeral-enclave &

# 3. Start gateway with logging
GATEWAY_PORT=8443 ENCLAVE_ADDR=127.0.0.1:5000 \
LOG_CAPACITY=50000 TRAFFIC_LOG=/tmp/traffic.csv \
./target/release/inference_gateway &

# 4. Run data collection
python3 scripts/collect_adversarial_data.py

# 5. Train and evaluate
python3 scripts/train_adversarial_classifier.py

# 6. Generate report
python3 scripts/generate_adversarial_report.py
```

---

**Document Status:** Ready for implementation (v2)
**Key Changes from v1:**
1. ✅ Correct instrumentation point (new inference_gateway, not kms_proxy_host)
2. ✅ Ablation experiments (size-only, timing-only, combined)
3. ✅ Plaintext padding before HPKE (not token padding)
4. ✅ Replace base64 random with general English
5. ✅ Buffered logging to avoid timing distortion
6. ✅ Statistical rigor (3 runs, 5-fold CV, macro-F1)
