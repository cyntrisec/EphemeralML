// ephemeralml-doctor — Phase 1 BYOC preflight check
//
// Contract: see startup-plans/10-operations/byoc-phase-1-ephemeralml-doctor-spec-2026-04-23.md
//
// Skeleton status: CLI + output + check registry + error routing is real.
// Individual check probes return `check_code: "SKELETON_UNIMPLEMENTED"` until
// the real-AWS deploy produces the outputs needed to exercise the real paths.

use std::process::ExitCode;

mod checks;
mod cli;
mod context;
mod error;
mod output;

use cli::Args;
use error::DoctorError;
use output::Format;

#[tokio::main]
async fn main() -> ExitCode {
    let args = match Args::parse_strict() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::from(2); // Per spec: 2 = CLI usage error
        }
    };

    match run(args).await {
        Ok(code) => code,
        Err(DoctorError::InfrastructureUnreachable(msg)) => {
            eprintln!("[INFRA] {}", msg);
            ExitCode::from(3)
        }
        Err(DoctorError::Internal(msg)) => {
            eprintln!("[INTERNAL] {}", msg);
            ExitCode::from(4)
        }
    }
}

async fn run(args: Args) -> Result<ExitCode, DoctorError> {
    let ctx = context::Context::bootstrap(&args).await?;
    let registry = checks::Registry::default();
    let results = registry.run(&ctx, args.check.as_deref()).await;
    let overall_pass = results.iter().all(|r| r.is_ok());

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
