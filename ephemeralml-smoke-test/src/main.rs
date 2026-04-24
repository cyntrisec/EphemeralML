// ephemeralml-smoke-test — Phase 1 BYOC end-to-end smoke test
//
// Contract: see startup-plans/10-operations/byoc-phase-1-ephemeralml-smoke-test-spec-2026-04-23.md
//
// Skeleton status: CLI + output + stage registry + evidence bundle types + error
// routing are real. Individual stage implementations return
// `check_code: "SKELETON_UNIMPLEMENTED"` (fail status) until the Phase 1
// real-AWS deploy + doctor real-probe implementations are done.

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

    let overall_pass = results.iter().all(|r| r.is_pass());

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
