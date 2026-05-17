#[path = "ephemeralml_verify.rs"]
mod ephemeralml_verify;

fn main() -> anyhow::Result<()> {
    ephemeralml_verify::main()
}
