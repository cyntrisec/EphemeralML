use super::config::UiConfig;
use super::explain::explain_check;
use super::mascot::{ghost_lines, GhostState};
use crate::receipt_verify::CheckStatus;
use std::io::Write;

// ANSI escape codes
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// Structured CLI output renderer.
///
/// Holds a `UiConfig` and a writer (stdout by default, `Vec<u8>` in tests).
pub struct Ui {
    config: UiConfig,
    writer: Box<dyn Write>,
}

impl Ui {
    /// Create a new Ui writing to stdout.
    pub fn stdout(config: UiConfig) -> Self {
        Self {
            config,
            writer: Box::new(std::io::stdout()),
        }
    }

    /// Create a new Ui writing to an arbitrary writer (for testing).
    pub fn new(config: UiConfig, writer: Box<dyn Write>) -> Self {
        Self { config, writer }
    }

    /// Access the config.
    pub fn config(&self) -> &UiConfig {
        &self.config
    }

    // -- ANSI helpers --

    fn bold(&self, text: &str) -> String {
        if self.config.color {
            format!("{BOLD}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    fn green(&self, text: &str) -> String {
        if self.config.color {
            format!("{GREEN}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    fn red(&self, text: &str) -> String {
        if self.config.color {
            format!("{RED}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    fn yellow(&self, text: &str) -> String {
        if self.config.color {
            format!("{YELLOW}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    fn dim(&self, text: &str) -> String {
        if self.config.color {
            format!("{DIM}{text}{RESET}")
        } else {
            text.to_string()
        }
    }

    // -- Output methods --

    /// Print a blank line.
    pub fn blank(&mut self) {
        let _ = writeln!(self.writer);
    }

    /// Print a major header with `====` bars.
    pub fn header(&mut self, title: &str) {
        let bar = "=".repeat(62);
        let _ = writeln!(self.writer, "  {}", self.dim(&bar));
        let _ = writeln!(self.writer, "  {}", self.bold(title));
        let _ = writeln!(self.writer, "  {}", self.dim(&bar));
    }

    /// Print a section header with `----` bars.
    pub fn section(&mut self, title: &str) {
        let thin = "-".repeat(62);
        let _ = writeln!(self.writer, "  {}", self.dim(&thin));
        let _ = writeln!(self.writer, "  {}:", self.bold(title));
        let _ = writeln!(self.writer, "  {}", self.dim(&thin));
    }

    /// Print a thin divider line.
    pub fn divider(&mut self) {
        let thin = "-".repeat(62);
        let _ = writeln!(self.writer, "  {}", self.dim(&thin));
    }

    /// Print a key-value pair, indented.
    pub fn kv(&mut self, key: &str, value: &str) {
        let _ = writeln!(self.writer, "  {:<13}{}", format!("{}:", key), value);
    }

    /// Print a check result line with [PASS]/[FAIL]/[SKIP] badge.
    pub fn check(&mut self, label: &str, status: &CheckStatus) {
        let badge = match status {
            CheckStatus::Pass => self.green("[PASS]"),
            CheckStatus::Fail => self.red("[FAIL]"),
            CheckStatus::Skip => self.dim("[SKIP]"),
        };
        let _ = writeln!(self.writer, "  {:<28}{}", label, badge);
    }

    /// Print a check with an inline explanation if the check failed.
    ///
    /// `check_name` is the canonical name used by `explain_check` (e.g. "signature").
    /// `label` is the display name shown on the check line.
    pub fn check_explained(&mut self, label: &str, check_name: &str, status: &CheckStatus) {
        self.check(label, status);
        if let Some(exp) = explain_check(check_name, status) {
            let why = self.dim(&format!("Why: {}", exp.why));
            let fix = self.dim(&format!("Fix: {}", exp.fix));
            let _ = writeln!(self.writer, "    {}", why);
            let _ = writeln!(self.writer, "    {}", fix);
        }
    }

    /// Print a success message (bold green).
    pub fn success(&mut self, msg: &str) {
        let _ = writeln!(self.writer, "  {}", self.green(&self.bold(msg)));
    }

    /// Print a failure message (bold red).
    pub fn failure(&mut self, msg: &str) {
        let _ = writeln!(self.writer, "  {}", self.red(&self.bold(msg)));
    }

    /// Print a warning message (yellow).
    pub fn warn(&mut self, msg: &str) {
        let _ = writeln!(self.writer, "  {}", self.yellow(msg));
    }

    /// Print a bullet point, indented.
    pub fn bullet(&mut self, msg: &str) {
        let _ = writeln!(self.writer, "    - {}", msg);
    }

    /// Print an indented info line.
    pub fn info(&mut self, msg: &str) {
        let _ = writeln!(self.writer, "  {}", msg);
    }

    /// Print a stage summary line (for pipeline verification).
    pub fn stage_line(&mut self, text: &str) {
        let _ = writeln!(self.writer, "  {}", text);
    }

    /// Print a tagged status line like "Chain[0]    PASS  root (no predecessor)".
    pub fn chain_status(&mut self, label: &str, pass: bool, detail: &str) {
        let tag = if pass {
            self.green("PASS")
        } else {
            self.red("FAIL")
        };
        let _ = writeln!(self.writer, "  {:<14}{}  {}", label, tag, detail);
    }

    /// Print the final verification verdict.
    pub fn verdict(&mut self, verified: bool, detail: &str) {
        self.blank();
        if verified {
            let msg = format!("  --> PIPELINE VERIFIED ({})", detail);
            let _ = writeln!(self.writer, "{}", self.green(&msg));
        } else {
            let _ = writeln!(self.writer, "{}", self.red("  --> PIPELINE INVALID"));
        }
    }

    /// Print the ghost mascot if mascot is enabled in config.
    pub fn ghost(&mut self, state: GhostState) {
        if !self.config.mascot {
            return;
        }
        let color_fn = match state {
            GhostState::Idle => None,
            GhostState::Success => Some(GREEN),
            GhostState::Fail => Some(RED),
        };
        let lines = ghost_lines(state);
        for line in &lines {
            if let Some(color) = color_fn {
                let _ = writeln!(self.writer, "  {}{}{}", color, line, RESET);
            } else {
                let _ = writeln!(self.writer, "  {}", line);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_config() -> UiConfig {
        UiConfig {
            color: false,
            mascot: false,
        }
    }

    fn color_config() -> UiConfig {
        UiConfig {
            color: true,
            mascot: true,
        }
    }

    struct CaptureBuf {
        inner: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    }

    impl CaptureBuf {
        fn new() -> (Self, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
            let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            (Self { inner: buf.clone() }, buf)
        }
    }

    impl Write for CaptureBuf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.inner.lock().unwrap().write(data)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn run_ui(config: UiConfig, f: impl FnOnce(&mut Ui)) -> String {
        let (cap, buf) = CaptureBuf::new();
        let mut ui = Ui::new(config, Box::new(cap));
        f(&mut ui);
        drop(ui);
        let locked = buf.lock().unwrap();
        String::from_utf8(locked.clone()).unwrap()
    }

    #[test]
    fn header_produces_bar_lines() {
        let out = run_ui(plain_config(), |ui| ui.header("Test Title"));
        assert!(out.contains("===="));
        assert!(out.contains("Test Title"));
        // Output should have 3 lines: bar, title, bar
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("===="));
        assert!(lines[1].contains("Test Title"));
        assert!(lines[2].contains("===="));
    }

    #[test]
    fn check_pass_produces_pass_badge() {
        let out = run_ui(plain_config(), |ui| {
            ui.check("Signature (Ed25519)", &CheckStatus::Pass);
        });
        assert!(out.contains("[PASS]"));
        assert!(out.contains("Signature (Ed25519)"));
    }

    #[test]
    fn check_fail_produces_fail_badge() {
        let out = run_ui(plain_config(), |ui| {
            ui.check("Signature (Ed25519)", &CheckStatus::Fail);
        });
        assert!(out.contains("[FAIL]"));
    }

    #[test]
    fn check_skip_produces_skip_badge() {
        let out = run_ui(plain_config(), |ui| {
            ui.check("Model ID match", &CheckStatus::Skip);
        });
        assert!(out.contains("[SKIP]"));
    }

    #[test]
    fn no_ansi_in_plain_mode() {
        let out = run_ui(plain_config(), |ui| {
            ui.header("Title");
            ui.check("Sig", &CheckStatus::Pass);
            ui.success("OK");
            ui.failure("BAD");
            ui.warn("WARN");
        });
        assert!(!out.contains("\x1b["));
    }

    #[test]
    fn ansi_present_in_color_mode() {
        let out = run_ui(color_config(), |ui| {
            ui.check("Sig", &CheckStatus::Pass);
        });
        assert!(out.contains("\x1b[32m")); // GREEN
    }

    #[test]
    fn kv_formats_correctly() {
        let out = run_ui(plain_config(), |ui| {
            ui.kv("Receipt", "abc-123");
        });
        assert!(out.contains("Receipt:"));
        assert!(out.contains("abc-123"));
    }

    #[test]
    fn bullet_formats_correctly() {
        let out = run_ui(plain_config(), |ui| {
            ui.bullet("Something went wrong");
        });
        assert!(out.contains("- Something went wrong"));
    }

    #[test]
    fn success_and_failure() {
        let out = run_ui(plain_config(), |ui| {
            ui.success("VERIFIED");
            ui.failure("INVALID");
        });
        assert!(out.contains("VERIFIED"));
        assert!(out.contains("INVALID"));
    }

    #[test]
    fn check_explained_shows_why_fix_on_fail() {
        let out = run_ui(plain_config(), |ui| {
            ui.check_explained("Signature (Ed25519)", "signature", &CheckStatus::Fail);
        });
        assert!(out.contains("[FAIL]"));
        assert!(out.contains("Why:"));
        assert!(out.contains("Fix:"));
    }

    #[test]
    fn check_explained_no_extra_on_pass() {
        let out = run_ui(plain_config(), |ui| {
            ui.check_explained("Signature (Ed25519)", "signature", &CheckStatus::Pass);
        });
        assert!(out.contains("[PASS]"));
        assert!(!out.contains("Why:"));
        assert!(!out.contains("Fix:"));
    }

    #[test]
    fn ghost_hidden_when_mascot_disabled() {
        let out = run_ui(plain_config(), |ui| {
            ui.ghost(GhostState::Idle);
        });
        assert!(out.is_empty());
    }

    #[test]
    fn ghost_shown_when_mascot_enabled() {
        let out = run_ui(color_config(), |ui| {
            ui.ghost(GhostState::Idle);
        });
        assert!(out.contains(".--.")); // ghost top
        assert!(out.contains("oo")); // idle eyes
    }

    #[test]
    fn ghost_success_has_caret_eyes() {
        let out = run_ui(color_config(), |ui| {
            ui.ghost(GhostState::Success);
        });
        assert!(out.contains("^^"));
    }

    #[test]
    fn ghost_fail_has_xx_eyes() {
        let out = run_ui(color_config(), |ui| {
            ui.ghost(GhostState::Fail);
        });
        assert!(out.contains("xx"));
    }

    #[test]
    fn section_produces_dashes() {
        let out = run_ui(plain_config(), |ui| {
            ui.section("Checks");
        });
        assert!(out.contains("----"));
        assert!(out.contains("Checks:"));
    }

    #[test]
    fn divider_produces_dashes() {
        let out = run_ui(plain_config(), |ui| {
            ui.divider();
        });
        assert!(out.contains("----"));
    }

    #[test]
    fn chain_status_shows_pass_fail() {
        let out = run_ui(plain_config(), |ui| {
            ui.chain_status("Chain[0]", true, "root");
            ui.chain_status("Chain[1]", false, "mismatch");
        });
        assert!(out.contains("PASS"));
        assert!(out.contains("FAIL"));
        assert!(out.contains("root"));
        assert!(out.contains("mismatch"));
    }

    #[test]
    fn verdict_verified() {
        let out = run_ui(plain_config(), |ui| {
            ui.verdict(true, "2 stages, intact");
        });
        assert!(out.contains("PIPELINE VERIFIED"));
        assert!(out.contains("2 stages, intact"));
    }

    #[test]
    fn verdict_invalid() {
        let out = run_ui(plain_config(), |ui| {
            ui.verdict(false, "");
        });
        assert!(out.contains("PIPELINE INVALID"));
    }

    #[test]
    fn full_verify_report_structure_plain() {
        let out = run_ui(plain_config(), |ui| {
            ui.blank();
            ui.header("EphemeralML Receipt Verification");
            ui.blank();
            ui.kv("Receipt", "abc-123");
            ui.kv("Model", "minilm v1.0");
            ui.kv("Platform", "nitro-pcr");
            ui.blank();
            ui.section("Checks");
            ui.check_explained("Signature (Ed25519)", "signature", &CheckStatus::Pass);
            ui.check_explained("Model ID match", "model_match", &CheckStatus::Fail);
            ui.divider();
            ui.blank();
            ui.failure("INVALID");
            ui.blank();
        });

        // Structural assertions
        assert!(out.contains("===="));
        assert!(out.contains("EphemeralML Receipt Verification"));
        assert!(out.contains("Receipt:"));
        assert!(out.contains("abc-123"));
        assert!(out.contains("----"));
        assert!(out.contains("Checks:"));
        assert!(out.contains("[PASS]"));
        assert!(out.contains("[FAIL]"));
        assert!(out.contains("Why:"));
        assert!(out.contains("Fix:"));
        assert!(out.contains("INVALID"));
        // No ANSI in plain mode
        assert!(!out.contains("\x1b["));
    }
}
