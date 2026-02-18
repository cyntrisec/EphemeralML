/// Resolved UI configuration for CLI output.
///
/// Priority: explicit CLI arg > env var > TTY auto-detect.
#[derive(Debug, Clone)]
pub struct UiConfig {
    /// Emit ANSI color codes.
    pub color: bool,
    /// Show ghost mascot.
    pub mascot: bool,
}

/// Snapshot of the environment variables relevant to UI configuration.
///
/// Extracted into a struct so tests can inject values without mutating
/// the real process environment (which causes flakes in parallel tests).
#[derive(Debug, Clone, Default)]
pub struct EnvState {
    /// `NO_COLOR` env var is set (any value).
    pub no_color: bool,
    /// `CI` env var is set (any value).
    pub ci: bool,
    /// Value of `EPHEMERALML_UI` env var (empty if unset).
    pub ephemeralml_ui: String,
}

impl EnvState {
    /// Read the current process environment.
    pub fn from_env() -> Self {
        Self {
            no_color: std::env::var("NO_COLOR").is_ok(),
            ci: std::env::var("CI").is_ok(),
            ephemeralml_ui: std::env::var("EPHEMERALML_UI").unwrap_or_default(),
        }
    }
}

impl UiConfig {
    /// Resolve UI config from CLI flags, environment, and TTY state.
    ///
    /// Reads the process environment via `EnvState::from_env()`.
    /// For tests, use `resolve_with` to inject an `EnvState` directly.
    ///
    /// Priority: explicit CLI arg > env var > TTY auto-detect.
    pub fn resolve(
        is_tty: bool,
        plain: bool,
        no_color: bool,
        no_mascot: bool,
        format_json: bool,
    ) -> Self {
        Self::resolve_with(
            is_tty,
            plain,
            no_color,
            no_mascot,
            format_json,
            &EnvState::from_env(),
        )
    }

    /// Resolve UI config with an explicit `EnvState` (for testing).
    ///
    /// Priority: explicit CLI arg > env var > TTY auto-detect.
    /// - `--plain` or `--format json` disables everything.
    /// - `--no-color` disables color regardless of env.
    /// - `EPHEMERALML_UI=rich/plain` overrides TTY auto-detect, but NOT `--no-color`.
    /// - `NO_COLOR` and `CI` disable color (below CLI flags, same level as env).
    pub fn resolve_with(
        is_tty: bool,
        plain: bool,
        no_color: bool,
        no_mascot: bool,
        format_json: bool,
        env: &EnvState,
    ) -> Self {
        // JSON output or --plain disables all decoration
        if format_json || plain {
            return Self {
                color: false,
                mascot: false,
            };
        }

        // CLI --no-color takes absolute priority over env vars
        if no_color {
            return Self {
                color: false,
                mascot: false,
            };
        }

        // Env vars (lower priority than CLI flags)
        let color = match env.ephemeralml_ui.as_str() {
            "rich" => true,
            "plain" => false,
            _ => is_tty && !env.no_color && !env.ci,
        };

        let mascot = color && !no_mascot;

        Self { color, mascot }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_env() -> EnvState {
        EnvState {
            no_color: false,
            ci: false,
            ephemeralml_ui: String::new(),
        }
    }

    #[test]
    fn tty_with_no_overrides_enables_color() {
        let cfg = UiConfig::resolve_with(true, false, false, false, false, &empty_env());
        assert!(cfg.color);
        assert!(cfg.mascot);
    }

    #[test]
    fn non_tty_disables_color() {
        let cfg = UiConfig::resolve_with(false, false, false, false, false, &empty_env());
        assert!(!cfg.color);
        assert!(!cfg.mascot);
    }

    #[test]
    fn plain_flag_disables_all() {
        let cfg = UiConfig::resolve_with(true, true, false, false, false, &empty_env());
        assert!(!cfg.color);
        assert!(!cfg.mascot);
    }

    #[test]
    fn no_color_flag_disables_color() {
        let cfg = UiConfig::resolve_with(true, false, true, false, false, &empty_env());
        assert!(!cfg.color);
        assert!(!cfg.mascot);
    }

    #[test]
    fn no_mascot_flag_disables_mascot_only() {
        let cfg = UiConfig::resolve_with(true, false, false, true, false, &empty_env());
        assert!(cfg.color);
        assert!(!cfg.mascot);
    }

    #[test]
    fn format_json_disables_all() {
        let cfg = UiConfig::resolve_with(true, false, false, false, true, &empty_env());
        assert!(!cfg.color);
        assert!(!cfg.mascot);
    }

    #[test]
    fn ui_env_rich_forces_color_on_non_tty() {
        let env = EnvState {
            ephemeralml_ui: "rich".to_string(),
            ..empty_env()
        };
        let cfg = UiConfig::resolve_with(false, false, false, false, false, &env);
        assert!(cfg.color);
    }

    #[test]
    fn ui_env_plain_forces_no_color() {
        let env = EnvState {
            ephemeralml_ui: "plain".to_string(),
            ..empty_env()
        };
        let cfg = UiConfig::resolve_with(true, false, false, false, false, &env);
        assert!(!cfg.color);
    }

    #[test]
    fn no_color_flag_overrides_ui_env_rich() {
        let env = EnvState {
            ephemeralml_ui: "rich".to_string(),
            ..empty_env()
        };
        // --no-color flag (CLI) must override EPHEMERALML_UI=rich (env)
        let cfg = UiConfig::resolve_with(true, false, true, false, false, &env);
        assert!(!cfg.color);
        assert!(!cfg.mascot);
    }

    #[test]
    fn plain_flag_overrides_ui_env_rich() {
        let env = EnvState {
            ephemeralml_ui: "rich".to_string(),
            ..empty_env()
        };
        let cfg = UiConfig::resolve_with(true, true, false, false, false, &env);
        assert!(!cfg.color);
        assert!(!cfg.mascot);
    }

    #[test]
    fn no_color_env_disables_color() {
        let env = EnvState {
            no_color: true,
            ..empty_env()
        };
        let cfg = UiConfig::resolve_with(true, false, false, false, false, &env);
        assert!(!cfg.color);
    }

    #[test]
    fn ci_env_disables_color() {
        let env = EnvState {
            ci: true,
            ..empty_env()
        };
        let cfg = UiConfig::resolve_with(true, false, false, false, false, &env);
        assert!(!cfg.color);
    }
}
