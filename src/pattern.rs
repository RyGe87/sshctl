//! Matching `Host` patterns the way ssh does.
//!
//! A `Host` line is not a name but a list of patterns: `*` stands for any
//! sequence, `?` for a single character, and a leading `!` excludes instead.
//! `Host *.example !nas.example` really does exist.
//!
//! sshctl first compared aliases literally and therefore overlooked such
//! blocks — precisely the blocks you least expect.

/// Matches a single pattern (without `!`) against a name.
fn matches_one(pattern: &str, name: &str) -> bool {
    glob(pattern.as_bytes(), name.as_bytes())
}

/// Small glob: `*` = zero or more characters, `?` = exactly one.
/// Iterative with backtracking, so `*` does not go exponential.
fn glob(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0usize, 0usize);
    let (mut star, mut backtrack) = (None, 0usize);

    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            backtrack = n;
            p += 1;
        } else if let Some(s) = star {
            // Let the last `*` swallow one more character.
            p = s + 1;
            backtrack += 1;
            n = backtrack;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Matches a complete `Host` line (several patterns, space-separated) against
/// a name. One excluding pattern that matches always wins: that is how ssh
/// works, and it is easy to overlook.
pub fn host_line_matches(patterns: &[String], name: &str) -> bool {
    let mut positive = false;
    for raw in patterns {
        if let Some(neg) = raw.strip_prefix('!') {
            if matches_one(neg, name) {
                return false;
            }
        } else if matches_one(raw, name) {
            positive = true;
        }
    }
    positive
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn a_literal_name() {
        assert!(host_line_matches(&line("unraid"), "unraid"));
        assert!(!host_line_matches(&line("unraid"), "unraidx"));
    }

    #[test]
    fn a_star_matches_everything() {
        assert!(host_line_matches(&line("*"), "anything at all"));
    }

    #[test]
    fn a_star_in_the_middle_and_at_the_start() {
        assert!(host_line_matches(&line("*.example"), "nas.example"));
        assert!(!host_line_matches(&line("*.example"), "nas.local"));
        assert!(host_line_matches(&line("web*.prod"), "web12.prod"));
    }

    #[test]
    fn a_question_mark_is_exactly_one_character() {
        assert!(host_line_matches(&line("web?"), "web1"));
        assert!(!host_line_matches(&line("web?"), "web12"));
    }

    #[test]
    fn several_patterns_on_one_line() {
        let l = line("unraid nas.example");
        assert!(host_line_matches(&l, "unraid"));
        assert!(host_line_matches(&l, "nas.example"));
        assert!(!host_line_matches(&l, "server"));
    }

    #[test]
    fn an_exclusion_beats_a_hit() {
        // This is the trap: the block applies to everything on .example EXCEPT
        // the nas.
        let l = line("*.example !nas.example");
        assert!(host_line_matches(&l, "server.example"));
        assert!(!host_line_matches(&l, "nas.example"));
    }

    #[test]
    fn exclusions_on_their_own_never_match() {
        assert!(!host_line_matches(&line("!nas.example"), "unraid"));
    }

    #[test]
    fn a_star_does_not_swallow_too_greedily() {
        // Naive implementations trip over this one.
        assert!(host_line_matches(&line("*a*b"), "xxaxxb"));
        assert!(!host_line_matches(&line("*a*b"), "xxaxxc"));
    }
}
