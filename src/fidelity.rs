//! The round-trip check.
//!
//! sshctl used to generate a file it owned itself; anything it did not
//! understand simply did not exist. Now it writes back over a file that *you*
//! own, and then everything the parser does not hold on to is no longer
//! "unknown" but "gone".
//!
//! Hence: render straight back at read time and lay the result next to the
//! original. What does not survive the round trip is something you know before
//! you start editing — not only once you save.

use crate::generate;
use crate::model::Source;

#[derive(Debug, PartialEq, Eq)]
pub struct Loss {
    /// The line from the original that does not come back.
    pub line: String,
    pub reason: Reason,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Reason {
    /// sshctl does not understand the construct (Match, Include, …).
    Unsupported,
    /// A comment that is not attached to a host.
    Comment,
    /// A setting the parser did not hold on to.
    Dropped,
    /// A line that was not there and that sshctl would add.
    ///
    /// Just as dangerous as throwing something away, and far easier to
    /// overlook: an added `HostName` on `Host web1 web2` suddenly sends web2
    /// to web1.
    Added,
}

impl Reason {
    pub fn describe(self) -> &'static str {
        match self {
            Reason::Unsupported => "sshctl does not understand this construct",
            Reason::Comment => "standalone comment; only comments right above a Host are kept",
            Reason::Dropped => "sshctl does not hold on to this setting",
            Reason::Added => "this line was not there and would be added",
        }
    }
}

/// Everything that would change if you read this original in and wrote it
/// back. An empty list means: rewriting is safe.
///
/// Deliberately looks **both** ways. The first version only looked at what
/// disappeared, so an invented line could slip in unnoticed — and that is
/// exactly the change that silently alters the meaning.
pub fn check(original: &str, source: &Source) -> Vec<Loss> {
    let rendered = generate::render(source);
    let survives: Vec<String> = rendered.lines().map(normalise).collect();

    let mut losses = Vec::new();
    for raw in original.lines() {
        let line = raw.trim();

        if line.is_empty() {
            continue;
        }

        if line.starts_with('#') {
            // A comment is lost only when it really does not come back. A
            // comment right above a Host survives as `comment`, and a group
            // heading is written out again by the generator — guessing from
            // the position instead of looking at the result reported both as
            // lost, and the second one showed up on every tidy file.
            if !survives.contains(&normalise(line)) {
                losses.push(Loss {
                    line: line.to_string(),
                    reason: Reason::Comment,
                });
            }
            continue;
        }

        // Does this line, normalised, also show up in the result?
        if survives.contains(&normalise(line)) {
            continue;
        }

        let reason = if source.unsupported.iter().any(|u| u.trim() == line) {
            Reason::Unsupported
        } else {
            Reason::Dropped
        };
        losses.push(Loss {
            line: line.to_string(),
            reason,
        });
    }

    // And now the other direction: which lines get added?
    let was_there: Vec<String> = original
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(normalise)
        .collect();
    for raw in rendered.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if was_there.contains(&normalise(line)) {
            continue;
        }
        losses.push(Loss {
            line: line.to_string(),
            reason: Reason::Added,
        });
    }

    losses
}

/// Makes lines comparable: keyword lowercased, `=` as a space, doubled
/// whitespace gone, quotes off. `IdentityFile=~/x` and `  identityfile ~/x`
/// are the same thing to ssh and have to be the same thing here — and so are
/// `Host "web1"` and `Host web1`.
fn normalise(line: &str) -> String {
    let line = line.trim().replace('=', " ").replace('"', "");
    let mut parts = line.split_whitespace();
    let Some(keyword) = parts.next() else {
        return String::new();
    };
    let rest: Vec<&str> = parts.collect();
    format!("{} {}", keyword.to_ascii_lowercase(), rest.join(" "))
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    /// What happens with an ordinary configuration: nothing is lost.
    #[test]
    fn a_tidy_config_survives_the_round_trip() {
        let original = "\
Host unraid
  HostName 192.0.2.10
  User root
  IdentityFile ~/.ssh/id_ed25519_unraid
  IdentitiesOnly yes
";
        let source = parser::parse(original);
        assert_eq!(check(original, &source), vec![]);
    }

    #[test]
    fn an_unknown_option_survives_because_we_keep_it_raw() {
        let original = "Host nas\n  HostName nas.nl\n  HostKeyAlgorithms +ssh-rsa\n";
        let source = parser::parse(original);
        assert_eq!(check(original, &source), vec![]);
    }

    #[test]
    fn a_match_block_survives_because_it_goes_back_verbatim() {
        // It used to be reported as a loss, which was honest but meant anyone
        // with a Match block could never use `write` at all. It now goes back
        // in exactly where it stood.
        let original = "Host a\n  HostName a.nl\n\nMatch host b\n  User someoneelse\n";
        let source = parser::parse(original);
        assert_eq!(check(original, &source), vec![]);
        let rendered = crate::generate::render(&source);
        assert!(rendered.contains("Match host b"), "got:\n{rendered}");
        assert!(rendered.contains("  User someoneelse"), "got:\n{rendered}");
    }

    #[test]
    fn a_standalone_comment_is_reported_but_one_above_a_host_is_not() {
        let original =
            "# passing thought\n\n# the media server\nHost unraid\n  HostName 192.0.2.10\n";
        let source = parser::parse(original);
        let losses = check(original, &source);
        assert_eq!(losses.len(), 1, "got {losses:?}");
        assert_eq!(losses[0].line, "# passing thought");
        assert_eq!(losses[0].reason, Reason::Comment);
    }

    #[test]
    fn a_group_heading_is_not_reported_as_lost() {
        // The generator writes it back itself; calling it a loss put a
        // warning banner on every file that uses groups.
        let original = "# ---------- home ----------\n\nHost a\n  HostName a.nl\n";
        let source = parser::parse(original);
        assert_eq!(check(original, &source), vec![]);
    }

    #[test]
    fn a_comment_inside_a_block_is_reported_as_lost() {
        // The parser cannot hold on to it (only comments right above a Host
        // survive), so the honest answer is "this line goes" — not quietly
        // moving it to the next block, which is what used to happen.
        let original =
            "Host a\n  HostName a.nl\n  # inline note\n  User root\nHost b\n  HostName b.nl\n";
        let source = parser::parse(original);
        let losses = check(original, &source);
        assert_eq!(losses.len(), 1, "got {losses:?}");
        assert_eq!(losses[0].line, "# inline note");
        assert_eq!(losses[0].reason, Reason::Comment);
    }

    #[test]
    fn the_equals_sign_notation_counts_as_the_same_line() {
        let original = "Host x\n  HostName=1.2.3.4\n  User=root\n";
        let source = parser::parse(original);
        assert_eq!(check(original, &source), vec![]);
    }

    #[test]
    fn a_per_host_setting_that_moves_to_the_star_block_is_no_loss() {
        // IdentitiesOnly sits per host in the original and ends up in Host *:
        // same line, different place. That is not a loss.
        let original = "\
Host a
  HostName a.nl
  IdentitiesOnly yes
Host b
  HostName b.nl
  IdentitiesOnly yes
";
        let source = parser::parse(original);
        assert_eq!(check(original, &source), vec![]);
    }

    #[test]
    fn an_invented_hostname_is_reported() {
        // The case the first version missed: `Host web1 web2` without a
        // HostName. Writing one sends web2 to web1.
        let original = "Host web1 web2\n  User deploy\n";
        let source = parser::parse(original);
        let losses = check(original, &source);
        assert!(
            losses.is_empty(),
            "nothing should be invented, got {losses:?}"
        );
        assert!(!crate::generate::render(&source).contains("HostName"));
    }

    #[test]
    fn a_pattern_block_gets_no_hostname() {
        let original = "Host *.internal\n  User admin\n";
        let source = parser::parse(original);
        assert_eq!(check(original, &source), vec![]);
        assert!(!crate::generate::render(&source).contains("HostName *.internal"));
    }

    #[test]
    fn an_added_line_is_reported_just_like_a_removed_one() {
        // Artificial: we put something in the model that was not in the text.
        let original = "Host a\n  HostName a.nl\n";
        let mut source = parser::parse(original);
        source.hosts[0].user = "root".to_string();
        let losses = check(original, &source);
        assert!(
            losses
                .iter()
                .any(|l| l.reason == Reason::Added && l.line.contains("User root")),
            "got {losses:?}"
        );
    }

    #[test]
    fn an_empty_config_loses_nothing() {
        let source = parser::parse("");
        assert_eq!(check("", &source), vec![]);
    }
}
