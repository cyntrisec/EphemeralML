/// Ghost states for the mascot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GhostState {
    Idle,
    Success,
    Fail,
}

/// Return the 3-line ASCII ghost for the given state.
pub fn ghost_lines(state: GhostState) -> [&'static str; 3] {
    match state {
        GhostState::Idle => ["  .--. ", " / oo \\", " \\ -- /"],
        GhostState::Success => ["  .--. ", " / ^^ \\", " \\ -- /"],
        GhostState::Fail => ["  .--. ", " / xx \\", " \\ -- /"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_states_produce_3_lines() {
        for state in [GhostState::Idle, GhostState::Success, GhostState::Fail] {
            let lines = ghost_lines(state);
            assert_eq!(lines.len(), 3);
            for line in &lines {
                assert!(!line.is_empty());
            }
        }
    }

    #[test]
    fn idle_has_oo_eyes() {
        let lines = ghost_lines(GhostState::Idle);
        assert!(lines[1].contains("oo"));
    }

    #[test]
    fn success_has_caret_eyes() {
        let lines = ghost_lines(GhostState::Success);
        assert!(lines[1].contains("^^"));
    }

    #[test]
    fn fail_has_xx_eyes() {
        let lines = ghost_lines(GhostState::Fail);
        assert!(lines[1].contains("xx"));
    }
}
