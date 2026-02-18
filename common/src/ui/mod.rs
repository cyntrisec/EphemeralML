pub mod config;
pub mod explain;
pub mod mascot;
pub mod render;

pub use config::UiConfig;
pub use explain::{explain_check, CheckExplanation};
pub use mascot::{ghost_lines, GhostState};
pub use render::Ui;
