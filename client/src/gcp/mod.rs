pub mod commands;
pub mod config;
pub mod doctor;
pub mod preflight;
pub mod runner;

#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};
use config::GcpFlags;

/// GCP deployment and management commands.
#[derive(Parser)]
pub struct GcpArgs {
    #[command(subcommand)]
    pub command: GcpCommand,
}

#[derive(Subcommand)]
pub enum GcpCommand {
    /// Run preflight checks (gcloud, docker, disk space, auth)
    Doctor,

    /// Initialize GCP configuration (generates .env.gcp)
    Init(InitArgs),

    /// One-time GCP infrastructure setup (APIs, Artifact Registry, service account)
    Setup(SetupArgs),

    /// Set up Cloud KMS keyring, WIP, and GCS bucket
    SetupKms(SetupKmsArgs),

    /// Encrypt, sign, and upload model to GCS
    PackageModel(PackageModelArgs),

    /// Build container and launch Confidential Space CVM
    Deploy(DeployArgs),

    /// Smoke test a deployed CVM (inference + receipt verify)
    Verify(VerifyArgs),

    /// Delete the Confidential Space CVM
    Teardown(TeardownArgs),

    /// Run full end-to-end pipeline (setup -> deploy -> verify -> teardown)
    E2e(E2eArgs),

    /// Run pre-release validation gate
    ReleaseGate(ReleaseGateArgs),
}

// ---- Shared flags ----

#[derive(Parser)]
pub struct SharedArgs {
    /// GCP project ID
    #[arg(long)]
    pub project: Option<String>,

    /// GCP region (default: derived from zone, e.g. us-central1)
    #[arg(long)]
    pub region: Option<String>,

    /// GCP zone (default: us-central1-a)
    #[arg(long)]
    pub zone: Option<String>,

    /// Print command without executing (skips preflight checks)
    #[arg(long)]
    pub dry_run: bool,

    /// Verbose output (print resolved config values)
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Output structured JSON status on completion
    #[arg(long)]
    pub json: bool,
}

// ---- Per-subcommand args ----

#[derive(Parser)]
pub struct InitArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Non-interactive mode (read values from env vars / .env.gcp)
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Parser)]
pub struct SetupArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Firewall source CIDR ranges
    #[arg(long)]
    pub source_ranges: Option<String>,
}

#[derive(Parser)]
pub struct SetupKmsArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Container image digest for WIP binding (e.g. sha256:abc123...)
    #[arg(long)]
    pub image_digest: Option<String>,

    /// Allow broad WIP binding (dev only, no image restriction)
    #[arg(long)]
    pub allow_broad_binding: bool,
}

#[derive(Parser)]
pub struct PackageModelArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Path to local model directory
    #[arg(long)]
    pub model_dir: Option<String>,

    /// GCS path prefix for model upload
    #[arg(long)]
    pub model_prefix: Option<String>,

    /// Model identifier
    #[arg(long)]
    pub model_id: Option<String>,

    /// Model version
    #[arg(long, name = "model-version")]
    pub model_version: Option<String>,

    /// Model format (safetensors or gguf)
    #[arg(long)]
    pub model_format: Option<String>,

    /// Cloud KMS key resource name
    #[arg(long)]
    pub kms_key: Option<String>,

    /// GCS bucket name
    #[arg(long)]
    pub bucket: Option<String>,
}

#[derive(Parser)]
pub struct DeployArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Deploy with GPU (a3-highgpu-1g with H100 CC)
    #[arg(long)]
    pub gpu: bool,

    /// Use debug image (SSH enabled)
    #[arg(long)]
    pub debug: bool,

    /// Skip Docker build/push
    #[arg(long)]
    pub skip_build: bool,

    /// Skip confirmations
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Custom container image tag
    #[arg(long)]
    pub tag: Option<String>,

    /// Model source: local, gcs, or gcs-kms
    #[arg(long)]
    pub model_source: Option<String>,

    /// Cloud KMS key resource name
    #[arg(long)]
    pub kms_key: Option<String>,

    /// WIP audience for STS exchange
    #[arg(long)]
    pub wip_audience: Option<String>,

    /// GCS bucket name
    #[arg(long)]
    pub bucket: Option<String>,

    /// GCS path prefix for model
    #[arg(long)]
    pub model_prefix: Option<String>,

    /// SHA-256 hash of plaintext model weights
    #[arg(long)]
    pub model_hash: Option<String>,

    /// Ed25519 public key (hex) for model manifest verification
    #[arg(long)]
    pub model_signing_pubkey: Option<String>,

    /// Model format (safetensors or gguf)
    #[arg(long)]
    pub model_format: Option<String>,
}

#[derive(Parser)]
pub struct VerifyArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Explicit IP address of the deployed CVM
    #[arg(long)]
    pub ip: Option<String>,

    /// Target GPU instance name
    #[arg(long)]
    pub gpu: bool,

    /// Skip audience pin check (dev only)
    #[arg(long)]
    pub allow_unpinned_audience: bool,
}

#[derive(Parser)]
pub struct TeardownArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Target GPU instance name
    #[arg(long)]
    pub gpu: bool,

    /// Skip confirmations
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Also delete the container image tag from Artifact Registry
    #[arg(long)]
    pub delete_image: bool,
}

#[derive(Parser)]
pub struct E2eArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Use CPU-only mode (c3-standard-4 instead of a3-highgpu-1g)
    #[arg(long)]
    pub cpu_only: bool,

    /// Skip KMS/WIP setup (reuse existing infra)
    #[arg(long)]
    pub skip_setup: bool,

    /// Skip VM teardown at end
    #[arg(long)]
    pub skip_teardown: bool,

    /// Path to local model directory
    #[arg(long)]
    pub model_dir: Option<String>,

    /// Model format (safetensors or gguf)
    #[arg(long)]
    pub model_format: Option<String>,
}

#[derive(Parser)]
pub struct ReleaseGateArgs {
    #[command(flatten)]
    pub shared: SharedArgs,

    /// Skip slow tests (fmt + clippy + unit only)
    #[arg(long)]
    pub quick: bool,
}

// ---- Helper to extract shared fields into GcpFlags ----

fn shared_to_flags(s: &SharedArgs) -> GcpFlags {
    GcpFlags {
        project: s.project.clone(),
        region: s.region.clone(),
        zone: s.zone.clone(),
        dry_run: s.dry_run,
        verbose: s.verbose,
        json: s.json,
        ..Default::default()
    }
}

// ---- Conversion helpers: subcommand args -> GcpFlags ----

impl From<&InitArgs> for GcpFlags {
    fn from(a: &InitArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.non_interactive = a.non_interactive;
        f
    }
}

impl From<&SetupArgs> for GcpFlags {
    fn from(a: &SetupArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.source_ranges = a.source_ranges.clone();
        f
    }
}

impl From<&SetupKmsArgs> for GcpFlags {
    fn from(a: &SetupKmsArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.allow_broad_binding = a.allow_broad_binding;
        f.image_digest = a.image_digest.clone();
        f
    }
}

impl From<&PackageModelArgs> for GcpFlags {
    fn from(a: &PackageModelArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.model_dir = a.model_dir.clone();
        f.model_prefix = a.model_prefix.clone();
        f.model_id = a.model_id.clone();
        f.model_version = a.model_version.clone();
        f.model_format = a.model_format.clone();
        f.kms_key = a.kms_key.clone();
        f.bucket = a.bucket.clone();
        f
    }
}

impl From<&DeployArgs> for GcpFlags {
    fn from(a: &DeployArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.gpu = a.gpu;
        f.debug = a.debug;
        f.skip_build = a.skip_build;
        f.yes = a.yes;
        f.tag = a.tag.clone();
        f.model_source = a.model_source.clone();
        f.kms_key = a.kms_key.clone();
        f.wip_audience = a.wip_audience.clone();
        f.bucket = a.bucket.clone();
        f.model_prefix = a.model_prefix.clone();
        f.model_hash = a.model_hash.clone();
        f.model_signing_pubkey = a.model_signing_pubkey.clone();
        f.model_format = a.model_format.clone();
        f
    }
}

impl From<&VerifyArgs> for GcpFlags {
    fn from(a: &VerifyArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.gpu = a.gpu;
        f.ip = a.ip.clone();
        f.allow_unpinned_audience = a.allow_unpinned_audience;
        f
    }
}

impl From<&TeardownArgs> for GcpFlags {
    fn from(a: &TeardownArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.gpu = a.gpu;
        f.yes = a.yes;
        f.delete_image = a.delete_image;
        f
    }
}

impl From<&E2eArgs> for GcpFlags {
    fn from(a: &E2eArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.cpu_only = a.cpu_only;
        f.skip_setup = a.skip_setup;
        f.skip_teardown = a.skip_teardown;
        f.model_dir = a.model_dir.clone();
        f.model_format = a.model_format.clone();
        f
    }
}

impl From<&ReleaseGateArgs> for GcpFlags {
    fn from(a: &ReleaseGateArgs) -> Self {
        let mut f = shared_to_flags(&a.shared);
        f.quick = a.quick;
        f
    }
}
