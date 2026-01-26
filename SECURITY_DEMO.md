# Security Demonstration: Host Blindness via Spy Mode

This document describes how to use **Spy Mode** to verify the core security guarantee of EphemeralML: **Host Blindness**.

Even when the host is actively trying to "spy" on the traffic passing through it, it cannot see the plaintext prompts, model weights, or inference results because they are protected by end-to-end HPKE encryption between the Client and the Enclave.

## Overview of Spy Mode

Spy Mode is a diagnostic tool implemented as a `SpyProxy` wrapper around the host's relay logic. When enabled, it:
1. Intercepts every payload forwarded to the enclave.
2. Logs the raw bytes (in hex) to a file.
3. Attempts to find any human-readable strings (ASCII graphics) in the payload.
4. Records the timestamp and payload length.

This simulates a "malicious" or "compromised" host attempting to exfiltrate data.

## Verifying Host Blindness

To verify that the host is indeed blind to the sensitive data, you can run the integration test specifically designed for this purpose.

### Running the Verification Test

Execute the following command from the project root:

```bash
cd projects/EphemeralML
cargo test --test spy_test
```

### What the Test Does

The `spy_test.rs` performs the following steps:
1. **Initializes a `SpyProxy`**: It wraps a mock host proxy with the spying capability.
2. **Simulates Encrypted Traffic**: It sends a payload that represents an HPKE-encrypted message (simulated with non-printable bytes in the test).
3. **Intercepts and Logs**: The `SpyProxy` writes the intercepted data to `spy_intercept.log`.
4. **Validates Blindness**: The test checks the log file to ensure:
   - The hex representation matches the sent bytes (confirming interception works).
   - **Crucially**, no sensitive plaintext is found in the "Potential clear-text" section.
   - Non-printable characters are represented as dots (`.`), demonstrating that the data remains opaque to the host.

## Understanding `spy_intercept.log`

The log file produced by Spy Mode follows this format:

```text
[TIMESTAMP] Intercepted payload length: N bytes
Payload (hex): [HEX_BYTES]
Potential clear-text: [FILTERED_ASCII]
---
```

### Log Format Breakdown:

- **TIMESTAMP**: Unix epoch time of the interception.
- **Payload (hex)**: The raw bytes as seen by the host. While the host can see the raw bits, it cannot interpret them without the private keys held only by the Enclave.
- **Potential clear-text**: A best-effort attempt by the host to find printable ASCII characters (`is_ascii_graphic()`). 
  - If the data is truly encrypted, this field will mostly consist of dots (`.`) and random gibberish characters.
  - If you see your prompt or inference results here, the security boundary has been breached!

## Conclusion

Spy Mode provides cryptographic proof through empirical observation that the Host remains a "dumb pipe". By inspecting the `spy_intercept.log`, security auditors can verify that sensitive information never leaves the enclave-client encrypted tunnel in a readable format.
