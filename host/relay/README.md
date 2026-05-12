# Cyntrisec Relay

`cyntrisec-relay` is the parent-host byte relay between an external TCP/NLB connection and the Nitro Enclave worker vsock port.

It does not parse plaintext, OpenAI JSON, TLS, policies, receipts, or manifests. One inbound TCP connection maps to one upstream vsock connection and bytes are copied in both directions until EOF, error, idle timeout, or shutdown.

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--tcp-bind` | `CYNTRISEC_RELAY_TCP_BIND` | `0.0.0.0:443` |
| `--vsock-cid` | `CYNTRISEC_RELAY_VSOCK_CID` | `16` |
| `--vsock-port` | `CYNTRISEC_RELAY_VSOCK_PORT` | `5000` |
| `--max-connections` | `CYNTRISEC_RELAY_MAX_CONN` | `1024` |
| `--idle-timeout-secs` | `CYNTRISEC_RELAY_IDLE_SECS` | `300` |
| `--log-format` | `CYNTRISEC_RELAY_LOG_FORMAT` | `json` |

## Future Egress Helper

KMS Decrypt and S3 PutObject egress are intentionally not part of this relay. They require AWS SDK dependencies, IAM policy, request authorization, and a real protocol surface.

That work should land as a separate slice, preferably a separate binary such as `cyntrisec-relay-egress`, on a different vsock port.
