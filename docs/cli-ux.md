# EphemeralML CLI UX Contract

This document defines the output conventions for all EphemeralML CLI tools and shell scripts.

## Output Modes

| Mode | When | Colors | Mascot | Structure |
|------|------|--------|--------|-----------|
| **Rich** | TTY detected, no overrides | Yes | Yes | Headers, badges, kv pairs |
| **Plain** | `--plain`, non-TTY, CI, `NO_COLOR` | No | No | Same structure, no ANSI |
| **JSON** | `--format json` | No | No | Machine-readable JSON |

## Color Policy

Colors are enabled when **all** of the following are true:
- stdout is a TTY (`std::io::IsTerminal`)
- `NO_COLOR` environment variable is **not** set
- `CI` environment variable is **not** set
- `--plain` flag was **not** passed
- `--no-color` flag was **not** passed
- `--format json` was **not** passed

Override with `EPHEMERALML_UI=rich` to force colors on, or `EPHEMERALML_UI=plain` to force off.

## Ghost Mascot

A 3-line ASCII ghost appears at the start (idle) and end (success/fail) of commands:

```
  .--.
 / oo \     (idle)
 \ -- /

  .--.
 / ^^ \     (success - green)
 \ -- /

  .--.
 / xx \     (fail - red)
 \ -- /
```

Suppressed by: `--no-mascot`, `--plain`, `--format json`, non-TTY, `NO_COLOR`, `CI`, `EPHEMERALML_NO_MASCOT` (shell scripts).

## CLI Flags (all binaries)

| Flag | Effect |
|------|--------|
| `--plain` | Disable all colors and mascot |
| `--no-color` | Disable color output only |
| `--no-mascot` | Disable ghost mascot only |
| `--format json` | JSON output (ephemeralml-verify only) |

## Exit Codes

| Binary | Code | Meaning |
|--------|------|---------|
| `ephemeralml infer` | 0 | Inference succeeded |
| `ephemeralml infer` | 1 | Inference failed |
| `ephemeralml verify-pipeline` | 0 | Pipeline verified |
| `ephemeralml verify-pipeline` | 1 | Pipeline invalid |
| `ephemeralml-verify` | 0 | Receipt verified |
| `ephemeralml-verify` | 1 | Receipt invalid |
| `ephemeralml-verify` | 2 | Error (bad input) |
| `ephemeralml-orchestrator` | 0 | Pipeline completed |
| `ephemeralml-orchestrator` | 1 | Pipeline or chain failed |

## Explainable Trust Output

When a verification check fails (`[FAIL]`), an inline explanation appears:

```
  Signature (Ed25519)       [FAIL]
    Why: The Ed25519 signature does not match the provided public key.
    Fix: Verify you are using the correct public key (--public-key or --public-key-file).
```

All 7 checks have explanations: `signature`, `model_match`, `measurement_type`, `timestamp_fresh`, `measurements_present`, `attestation_source`, `image_digest`.

`[PASS]` and `[SKIP]` checks show no explanation.

## Shell Script Conventions

### Shared Library

All GCP scripts source `scripts/lib/ui.sh`, which provides:

- `ui_header`, `ui_section`, `ui_kv`, `ui_ok`, `ui_fail`, `ui_warn`, `ui_info`, `ui_bullet`, `ui_blank`
- `run_step STEP_NUM TOTAL LABEL COMMAND...` — collapsed build/deploy output
- `ui_ghost_idle`, `ui_ghost_ok`, `ui_ghost_fail` — shell mascot

### `run_step` Behavior

```bash
run_step 3 6 "Building container image" docker build ...
```

1. Prints `[3/6] Building container image...`
2. Captures stdout+stderr to a tempfile
3. On success: `[OK] Building container image (12s)`
4. On failure: `[FAIL] Building container image (exit 1, 5s)` + last 20 lines + log path
5. `VERBOSE=true`: streams output live

### Environment Variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Disable colors in all tools |
| `CI` | Disable colors (auto-detected in CI) |
| `VERBOSE` | Stream full build output instead of collapsing |
| `EPHEMERALML_UI` | `rich` or `plain` — override color detection |
| `EPHEMERALML_NO_MASCOT` | Suppress ghost mascot in shell scripts |

## JSON Stability Contract

The `--format json` output of `ephemeralml-verify` produces a `VerifyResult` struct. The following fields are stable:

- `verified` (bool)
- `receipt_id` (string)
- `model_id` (string)
- `model_version` (string)
- `measurement_type` (string)
- `sequence_number` (u64)
- `execution_timestamp` (u64)
- `checks.signature` / `checks.model_match` / etc. ("pass" | "fail" | "skip")
- `errors` (array of strings)
- `warnings` (array of strings)

New fields may be added. Existing fields will not be removed or renamed without a major version bump.

## Troubleshooting

### No colors in terminal

Check: `echo $TERM`, `echo $NO_COLOR`, `echo $CI`. Force with `EPHEMERALML_UI=rich`.

### Ghost not showing

The ghost only shows when colors are enabled. Check `--plain`, `--no-mascot`, `EPHEMERALML_NO_MASCOT`.

### Build output flooding the screen

Use default mode (output is collapsed). If already collapsed, the failure happened — check the log path printed by `run_step`.

### `deploy.sh` shows full Docker output

This is expected with `VERBOSE=true`. Unset it to collapse output.
