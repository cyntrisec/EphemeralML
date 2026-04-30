// ephemeralml-smoke-test — Phase 1 BYOC end-to-end smoke test
//
// Contract: see startup-plans/10-operations/byoc-phase-1-ephemeralml-smoke-test-spec-2026-04-23.md
//
// The runner is intentionally fail-closed: every stage gates the next, and
// evidence upload is refused unless the local AIR verification and required
// evidence files are present.

use std::process::ExitCode;

mod bundle;
mod cli;
mod context;
mod error;
mod output;
mod stages;

use cli::Args;
use error::SmokeTestError;
use output::Format;

#[tokio::main]
async fn main() -> ExitCode {
    let args = match Args::parse_strict() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(2); // CLI usage error
        }
    };

    match run(args).await {
        Ok(code) => code,
        Err(SmokeTestError::InfrastructureUnreachable(msg)) => {
            eprintln!("[INFRA] {}", msg);
            ExitCode::from(3)
        }
        Err(SmokeTestError::Internal(msg)) => {
            eprintln!("[INTERNAL] {}", msg);
            ExitCode::from(4)
        }
    }
}

async fn run(args: Args) -> Result<ExitCode, SmokeTestError> {
    let ctx = context::Context::bootstrap(&args).await?;
    let registry = stages::Registry::default();
    let results = registry.run(&ctx, &args).await;

    cleanup_enclave_if_needed(&ctx, &args, &results).await;

    let overall_pass = results
        .iter()
        .all(|r| r.is_pass() || matches!(r.status, stages::StageStatus::Skipped));

    let format = if args.json {
        Format::Json {
            verbose: args.verbose,
        }
    } else {
        Format::Text {
            verbose: args.verbose,
        }
    };
    output::render(&ctx, &results, format);

    Ok(if overall_pass {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    })
}

async fn cleanup_enclave_if_needed(
    ctx: &context::Context,
    args: &Args,
    results: &[stages::StageResult],
) {
    if ctx.retain_enclave {
        return;
    }
    let Some(enclave_id) = launched_enclave_id(results) else {
        return;
    };

    let output = tokio::process::Command::new(&args.nitro_cli)
        .arg("terminate-enclave")
        .arg("--enclave-id")
        .arg(&enclave_id)
        .output()
        .await;

    match output {
        Ok(out) if out.status.success() => {
            eprintln!("[cleanup] terminated Nitro enclave {}", enclave_id);
        }
        Ok(out) => {
            eprintln!(
                "[cleanup] failed to terminate Nitro enclave {}: {}{}",
                enclave_id,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Err(e) => {
            eprintln!(
                "[cleanup] failed to execute '{} terminate-enclave': {}",
                args.nitro_cli, e
            );
        }
    }
}

fn launched_enclave_id(results: &[stages::StageResult]) -> Option<String> {
    results
        .iter()
        .find(|r| r.stage_name() == "enclave_launch" && r.is_pass())
        .and_then(|r| r.details.get("launch"))
        .and_then(|launch| launch.get("EnclaveID").or_else(|| launch.get("enclave_id")))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
}
