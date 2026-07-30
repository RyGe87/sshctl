//! Proving that a rewrite changes nothing — by asking ssh, not by comparing text.
//!
//! [`crate::fidelity`] compares lines. That is fast and it shows you what is
//! about to disappear, but it cannot tell a real change from a harmless one. It
//! called `Port 2222 # the odd port` becoming `Port 2222` a loss, while ssh
//! ends up on port 2222 either way. And the other direction is worse: it would
//! wave through a rewrite that happens to keep every line and still changes
//! which block matches first.
//!
//! So the gate is a proof instead. Write both versions to a temporary file, ask
//! `ssh -G -F <file> <name>` for every name that matters, and compare the
//! answers. That is ssh's own fully-resolved configuration — after Host
//! patterns, Match, Include and its built-in defaults. If it is identical for
//! every name, the rewrite changes nothing about what happens when you connect.
//!
//! Two things this deliberately does not do:
//!
//!   * It says nothing about comments. `ssh -G` does not report them, so
//!     [`lost_comments`] checks those separately as plain text.
//!   * It does not invent an answer when ssh cannot be asked. Then the verdict
//!     is [`Verdict::Unknown`] and the text check has the last word again.

use crate::model::Source;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// One setting on which the two versions disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Difference {
    /// The name we asked ssh about.
    pub name: String,
    /// The setting, as `ssh -G` spells it (lower case).
    pub key: String,
    pub before: String,
    pub after: String,
}

impl Difference {
    pub fn describe(&self) -> String {
        format!(
            "ssh {}: {} was {}, becomes {}",
            self.name,
            self.key,
            show(&self.before),
            show(&self.after)
        )
    }
}

fn show(value: &str) -> String {
    if value.is_empty() {
        "(unset)".to_string()
    } else {
        value.to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// ssh gives exactly the same answer for every name asked.
    Same { probed: usize },
    /// It really does behave differently.
    Changed(Vec<Difference>),
    /// ssh could not be asked, so nothing has been proved either way.
    Unknown(String),
}

impl Verdict {
    /// Is writing safe as far as *behaviour* goes? `Unknown` is deliberately
    /// not safe: not having checked is not the same as having checked.
    pub fn is_proven_safe(&self) -> bool {
        matches!(self, Verdict::Same { .. })
    }
}

/// Every name worth asking about.
///
/// **A proof is only as strong as the names it probes.** Taking them from the
/// model alone was not enough, and that was not a detail: a `Match host beta`
/// block mentions `beta` nowhere else, so `beta` never got asked, and deleting
/// the whole block came out as "nothing changed". So the names are read out of
/// both texts as well.
///
/// One name that appears nowhere is added on top, to catch a pattern block such
/// as `Host *` or `Host * !prod` that would otherwise never be probed.
fn names_to_probe(source: &Source, texts: [&str; 2]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut add = |n: &str| {
        let n = n.trim().trim_matches('"');
        // A pattern is not a name you can ask about: `ssh -G '*'` would match
        // itself and tell you nothing.
        if n.is_empty() || n.contains(['*', '?', '!']) {
            return;
        }
        if !names.iter().any(|existing| existing == n) {
            names.push(n.to_string());
        }
    };
    for host in &source.hosts {
        add(&host.alias);
        for extra in &host.aliases {
            add(extra);
        }
        add(&host.hostname);
    }
    for text in texts {
        for name in names_in_text(text) {
            add(&name);
        }
    }
    names.push("sshctl-probe.invalid".to_string());
    names
}

/// Names mentioned anywhere in a config file, including inside constructs
/// sshctl does not model itself.
fn names_in_text(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let Some(keyword) = words.next() else {
            continue;
        };
        match keyword.to_ascii_lowercase().as_str() {
            "host" | "hostname" => found.extend(words.map(String::from)),
            // `Match host beta,gamma` and `Match originalhost x` name hosts
            // that may appear nowhere else in the file.
            "match" => {
                let parts: Vec<&str> = words.collect();
                for pair in parts.windows(2) {
                    let criterion = pair[0].to_ascii_lowercase();
                    if criterion == "host" || criterion == "originalhost" {
                        found.extend(pair[1].split(',').map(String::from));
                    }
                }
            }
            _ => {}
        }
    }
    found
}

/// Constructs that pull in behaviour from outside this text, so that comparing
/// two files cannot settle the question.
///
/// `Include` brings in a file we never read. `Match exec` runs a command whose
/// outcome depends on the moment. If either disappears in the rewrite, "ssh
/// answers the same" is not proof of anything, and saying so is better than
/// a confident wrong answer.
fn unprovable_loss(original: &str, rendered: &str) -> Option<String> {
    for raw in original.lines() {
        let line = raw.trim();
        let lower = line.to_ascii_lowercase();
        let risky = lower.starts_with("include ")
            || (lower.starts_with("match ") && lower.contains("exec"));
        if !risky {
            continue;
        }
        let survives = rendered.lines().any(|l| l.trim() == line);
        if !survives {
            return Some(format!(
                "'{line}' disappears, and what it does cannot be read here"
            ));
        }
    }
    None
}

/// Compares what ssh makes of the two versions.
pub fn compare(original: &str, rendered: &str, source: &Source) -> Verdict {
    let Some(before_file) = TempConfig::new("before", original) else {
        return Verdict::Unknown("could not write a temporary file".to_string());
    };
    let Some(after_file) = TempConfig::new("after", rendered) else {
        return Verdict::Unknown("could not write a temporary file".to_string());
    };

    if let Some(why) = unprovable_loss(original, rendered) {
        return Verdict::Unknown(why);
    }

    let names = names_to_probe(source, [original, rendered]);
    let mut differences = Vec::new();
    for name in &names {
        let before = match resolve(&before_file.path, name) {
            Ok(v) => v,
            // The original itself is not something ssh will accept. Then there
            // is nothing to compare against, and saying so is the honest
            // answer — this is also how you find out your config is broken.
            Err(e) => return Verdict::Unknown(format!("ssh rejects the current config: {e}")),
        };
        let after = match resolve(&after_file.path, name) {
            Ok(v) => v,
            Err(e) => {
                differences.push(Difference {
                    name: name.clone(),
                    key: "(the whole file)".to_string(),
                    before: "accepted".to_string(),
                    after: format!("rejected: {e}"),
                });
                continue;
            }
        };
        differences.extend(diff_settings(name, &before, &after));
    }

    if differences.is_empty() {
        Verdict::Same {
            probed: names.len(),
        }
    } else {
        Verdict::Changed(differences)
    }
}

/// Comments that were in the original and are not in the rewrite.
///
/// Kept apart from the proof on purpose: `ssh -G` says nothing about comments,
/// so a lost comment can never show up there. It is also not a reason to refuse
/// — nothing breaks — but you do deserve to be told.
pub fn lost_comments(original: &str, rendered: &str) -> Vec<String> {
    let after: Vec<&str> = rendered.lines().map(str::trim).collect();
    let mut lost = Vec::new();
    for line in original.lines() {
        let trimmed = line.trim();
        let Some(text) = comment_of(trimmed) else {
            continue;
        };
        if text.is_empty() {
            continue;
        }
        let survives = after
            .iter()
            .filter_map(|l| comment_of(l))
            .any(|other| other.contains(&text));
        if !survives && !lost.contains(&text) {
            lost.push(text);
        }
    }
    lost
}

/// The comment part of a line, whether it stands alone or sits at the end.
fn comment_of(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let starts_comment = *b == b'#' && (i == 0 || (bytes[i - 1] as char).is_whitespace());
        if starts_comment {
            return Some(line[i + 1..].trim().to_string());
        }
    }
    None
}

/// `ssh -G -F <file> <name>` as a map of setting to value.
fn resolve(config: &PathBuf, name: &str) -> Result<Vec<(String, String)>, String> {
    let out = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(config)
        .arg(name)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        // ssh writes CRLF on stderr on every platform, so trim rather than
        // compare.
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(stderr
            .lines()
            .next()
            .unwrap_or("no reason given")
            .trim()
            .to_string());
    }
    let mut settings = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let line = line.trim();
        let (key, value) = match line.split_once(char::is_whitespace) {
            Some((k, v)) => (k.to_string(), v.trim().to_string()),
            None if !line.is_empty() => (line.to_string(), String::new()),
            None => continue,
        };
        settings.push((key, value));
    }
    Ok(settings)
}

/// Compares two `ssh -G` outputs.
///
/// A setting may appear more than once — `identityfile` usually does — so the
/// values are gathered per key and compared as a whole. Order matters there:
/// ssh tries identity files in the order given.
fn diff_settings(
    name: &str,
    before: &[(String, String)],
    after: &[(String, String)],
) -> Vec<Difference> {
    let mut keys: Vec<&str> = Vec::new();
    for (k, _) in before.iter().chain(after.iter()) {
        if !keys.contains(&k.as_str()) {
            keys.push(k);
        }
    }
    let gather = |settings: &[(String, String)], key: &str| -> String {
        settings
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = Vec::new();
    for key in keys {
        let b = gather(before, key);
        let a = gather(after, key);
        if b != a {
            out.push(Difference {
                name: name.to_string(),
                key: key.to_string(),
                before: b,
                after: a,
            });
        }
    }
    out
}

/// A config file that cleans itself up. Made with 0600, because ssh refuses to
/// read a config anyone else can write to.
struct TempConfig {
    path: PathBuf,
}

impl TempConfig {
    fn new(label: &str, contents: &str) -> Option<Self> {
        let path = std::env::temp_dir().join(format!(
            "sshctl-{label}-{}-{}.conf",
            std::process::id(),
            next_serial()
        ));
        let mut file = open_private(&path)?;
        file.write_all(contents.as_bytes()).ok()?;
        file.flush().ok()?;
        Some(TempConfig { path })
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn open_private(path: &PathBuf) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .ok()
}

#[cfg(not(unix))]
fn open_private(path: &PathBuf) -> Option<std::fs::File> {
    // On Windows a file in the user's own temp directory is not readable by
    // other users to begin with, and ssh does not check the mode there.
    std::fs::File::create(path).ok()
}

/// Keeps two temporary files in the same process from colliding. Not a clock:
/// a counter is enough and stays predictable in tests.
fn next_serial() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate, parser};

    fn verdict_for(text: &str) -> Verdict {
        let source = parser::parse(text);
        compare(text, &generate::render(&source), &source)
    }

    #[test]
    fn a_tidy_config_comes_back_unchanged() {
        let text = "Host alfa\n  HostName alfa.example\n  User admin\n  Port 2222\n";
        assert!(
            verdict_for(text).is_proven_safe(),
            "{:?}",
            verdict_for(text)
        );
    }

    #[test]
    fn a_trailing_comment_changes_nothing_about_the_connection() {
        // This is the case the text check got wrong: it called the lost comment
        // a loss and refused to write. ssh lands on port 2222 either way.
        let text = "Host alfa\n  HostName alfa.example\n  Port 2222 # the odd port\n";
        assert!(
            verdict_for(text).is_proven_safe(),
            "{:?}",
            verdict_for(text)
        );
        assert_eq!(
            lost_comments(text, &generate::render(&parser::parse(text))),
            vec!["the odd port"]
        );
    }

    #[test]
    fn a_block_without_a_hostname_keeps_both_names_pointing_at_themselves() {
        // Writing out a HostName here would send web2 to web1 — the exact
        // mistake this whole check exists for.
        let text = "Host web1 web2\n  User deploy\n";
        assert!(
            verdict_for(text).is_proven_safe(),
            "{:?}",
            verdict_for(text)
        );
    }

    #[test]
    fn an_exclusion_pattern_survives() {
        let text = "Host * !prod\n  ServerAliveInterval 30\nHost prod\n  HostName prod.example\n";
        assert!(
            verdict_for(text).is_proven_safe(),
            "{:?}",
            verdict_for(text)
        );
    }

    #[test]
    fn a_real_change_is_caught() {
        let text = "Host alfa\n  HostName alfa.example\n  Port 22\n";
        let mut source = parser::parse(text);
        source.hosts[0].port = Some(2222);
        match compare(text, &generate::render(&source), &source) {
            Verdict::Changed(diffs) => {
                assert!(
                    diffs.iter().any(|d| d.key == "port" && d.after == "2222"),
                    "got {diffs:?}"
                );
            }
            other => panic!("a changed port has to show up, got {other:?}"),
        }
    }

    #[test]
    fn widening_a_setting_to_other_hosts_is_caught() {
        // The bug that got through both the diff and the text check: lifting
        // `IdentitiesOnly yes` into `Host *` widens it to hosts that have no
        // key of their own, and those then offer nothing at all.
        let text = "Host alfa\n  HostName alfa.example\n  IdentitiesOnly yes\nHost beta\n  HostName beta.example\n";
        let source = parser::parse(text);
        let widened = "Host alfa\n  HostName alfa.example\nHost beta\n  HostName beta.example\nHost *\n  IdentitiesOnly yes\n";
        match compare(text, widened, &source) {
            Verdict::Changed(diffs) => {
                assert!(
                    diffs
                        .iter()
                        .any(|d| d.name == "beta" && d.key == "identitiesonly"),
                    "beta must not quietly get IdentitiesOnly, got {diffs:?}"
                );
            }
            other => panic!("this is the dangerous case and must be caught, got {other:?}"),
        }
    }

    #[test]
    fn a_standalone_comment_that_survives_is_not_reported() {
        let text = "# the media server\nHost unraid\n  HostName 192.0.2.10\n";
        let rendered = generate::render(&parser::parse(text));
        assert_eq!(lost_comments(text, &rendered), Vec::<String>::new());
    }

    #[test]
    fn a_deleted_match_block_is_caught() {
        // The hole that made the first version of this module useless: `beta`
        // appears nowhere except inside the Match block, so it never got
        // probed, and deleting the whole block came out as "nothing changed".
        // The generator keeps Match blocks now, so this is tested against a
        // deletion made by hand.
        let text = "Host alfa\n  HostName alfa.example\nMatch host beta\n  User someoneelse\n";
        let stripped = "Host alfa\n  HostName alfa.example\n";
        let source = parser::parse(text);
        match compare(text, stripped, &source) {
            Verdict::Changed(diffs) => {
                assert!(
                    diffs.iter().any(|d| d.name == "beta" && d.key == "user"),
                    "beta loses its user, got {diffs:?}"
                );
            }
            other => panic!("deleting a Match block must not pass, got {other:?}"),
        }
    }

    #[test]
    fn a_match_block_that_stays_put_changes_nothing() {
        let text = "Host alfa\n  HostName alfa.example\n\nMatch host beta\n  User someoneelse\n";
        assert!(
            verdict_for(text).is_proven_safe(),
            "{:?}",
            verdict_for(text)
        );
    }

    #[test]
    fn a_disappearing_include_makes_the_answer_unknown() {
        // What an Include brings in is not in this text, so comparing the two
        // texts settles nothing. Better to say so than to answer confidently.
        // Again tested against a deletion made by hand: the generator keeps it.
        let text = "Include ~/.ssh/extra\nHost alfa\n  HostName alfa.example\n";
        let stripped = "Host alfa\n  HostName alfa.example\n";
        let source = parser::parse(text);
        match compare(text, stripped, &source) {
            Verdict::Unknown(why) => assert!(why.contains("Include"), "got {why}"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn an_include_that_stays_put_changes_nothing() {
        let text = "Include ~/.ssh/extra\n\nHost alfa\n  HostName alfa.example\n";
        assert!(
            verdict_for(text).is_proven_safe(),
            "{:?}",
            verdict_for(text)
        );
    }

    #[test]
    fn names_come_out_of_the_text_as_well_as_the_model() {
        let names = names_to_probe(
            &parser::parse("Host alfa\n  HostName alfa.example\n"),
            ["Match host beta,gamma\n  User x\n", ""],
        );
        for expected in ["alfa", "alfa.example", "beta", "gamma"] {
            assert!(
                names.iter().any(|n| n == expected),
                "{expected} is missing from {names:?}"
            );
        }
        assert!(
            !names.iter().any(|n| n.contains('*')),
            "a pattern is not a name you can ask about: {names:?}"
        );
    }

    #[test]
    fn a_broken_config_is_not_declared_safe() {
        // `ssh -G` refuses this, so nothing can be proved and we must not
        // pretend otherwise.
        let source = parser::parse("Host alfa\n  HostName alfa.example\n");
        match compare("Bogusdirective yes\n", "Host alfa\n", &source) {
            Verdict::Unknown(_) => {}
            other => panic!("expected Unknown, got {other:?}"),
        }
    }
}
