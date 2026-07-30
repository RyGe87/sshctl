//! The ledger: `known_hosts`.
//!
//! `config` says what you want, `known_hosts` says what you have seen. You
//! write the first, the second grows by itself — and it is the only protection
//! against a machine passing itself off as yours.
//!
//! **The path is never invented by us.** Next to `known_hosts` there is often
//! a `known_hosts.old` that ssh-keygen leaves behind after a `-R`. It contains
//! old, revoked keys: on this machine it holds an outdated key for
//! 192.0.2.10. Anyone globbing on `known_hosts*` therefore reads quiet
//! nonsense. That is why we ask `ssh -G` which files really apply.
//!
//! The link with `config` runs through `HostName`, not through your alias:
//! `unraid` sits in the ledger as `192.0.2.10`. Change the `HostName` and
//! the machine is suddenly unknown, and you get a trust prompt all over again.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The first field of the line, literally. On a hashed line that is
    /// `|1|salt|hash`; otherwise a comma-separated list of names.
    pub raw_names: String,
    /// The individual names, empty if the line is hashed.
    pub names: Vec<String>,
    pub hashed: bool,
    pub fingerprint: String,
    pub key_type: String,
}

impl Entry {
    /// A readable designation, even when the name has been made unreadable.
    pub fn label(&self) -> String {
        if self.hashed {
            "(hashed name)".to_string()
        } else {
            self.names.join(", ")
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ledger {
    /// The files ssh actually uses.
    pub files: Vec<PathBuf>,
    pub entries: Vec<Entry>,
}

/// Which files apply? Straight out of `ssh -G`, so that `known_hosts.old`
/// cannot possibly slip in.
pub fn files_in_use(resolved: &[(String, String)]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for (keyword, value) in resolved {
        if keyword == "userknownhostsfile" || keyword == "globalknownhostsfile" {
            out.extend(split_paths(value));
        }
    }
    out.into_iter().filter(|p| p.exists()).collect()
}

/// Which known_hosts files apply across the whole configuration.
///
/// `UserKnownHostsFile` can be set per host, so asking about one host and using
/// that answer for all of them is wrong in the quietest possible way: a host
/// with its own ledger would be judged against someone else's, and come out as
/// "not known yet" for no visible reason. So we ask per host and take the
/// union.
///
/// With no hosts at all we still ask once, so the ledger of a fresh config is
/// not simply empty.
pub fn files_for_all(source: &crate::model::Source) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut add = |paths: Vec<PathBuf>| {
        for p in paths {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    };
    if source.hosts.is_empty() {
        if let Ok(resolved) = crate::effective::ask_ssh("localhost") {
            add(files_in_use(&resolved));
        }
        return out;
    }
    for host in &source.hosts {
        // A pattern is not a name you can ask ssh about.
        if host.alias.contains(['*', '?', '!']) {
            continue;
        }
        if let Ok(resolved) = crate::effective::ask_ssh(&host.alias) {
            add(files_in_use(&resolved));
        }
    }
    out
}

/// `ssh -G` puts several paths one after another, space-separated.
fn split_paths(value: &str) -> Vec<PathBuf> {
    value
        .split_whitespace()
        .map(|p| {
            if let Some(rest) = p.strip_prefix("~/") {
                crate::model::home().join(rest)
            } else {
                PathBuf::from(p)
            }
        })
        .collect()
}

impl Ledger {
    pub fn load(files: &[PathBuf]) -> Self {
        let mut entries = Vec::new();
        for file in files {
            if let Ok(listing) = list_keys(file) {
                entries.extend(parse_listing(&listing));
            }
        }
        Self {
            files: files.to_vec(),
            entries,
        }
    }

    /// Machines that sit in the ledger under more than one name. The same
    /// fingerprint under two names means: one machine, two entries.
    pub fn duplicates(&self) -> Vec<(String, Vec<String>)> {
        let mut per_fingerprint: HashMap<&str, Vec<&Entry>> = HashMap::new();
        for e in &self.entries {
            per_fingerprint.entry(&e.fingerprint).or_default().push(e);
        }
        let mut out: Vec<(String, Vec<String>)> = per_fingerprint
            .into_iter()
            .filter(|(_, v)| v.len() > 1)
            .map(|(fp, v)| {
                let mut names: Vec<String> = v.iter().map(|e| e.label()).collect();
                names.sort();
                names.dedup();
                (fp.to_string(), names)
            })
            .filter(|(_, names)| names.len() > 1)
            .collect();
        out.sort();
        out
    }
}

/// `ssh-keygen -lf <file>`: one line per stored key.
fn list_keys(file: &Path) -> Result<String, String> {
    let out = Command::new("ssh-keygen")
        .arg("-l")
        .arg("-f")
        .arg(file)
        .output()
        .map_err(|e| format!("could not start ssh-keygen: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Lines like: `256 SHA256:abc… 192.0.2.10 (ED25519)`
pub fn parse_listing(text: &str) -> Vec<Entry> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let _bits = parts.next()?;
            let fingerprint = parts.next()?.to_string();
            let raw_names = parts.next()?.to_string();
            let key_type = parts
                .next()
                .unwrap_or("(unknown)")
                .trim_matches(['(', ')'])
                .to_string();
            let hashed = raw_names.starts_with("|1|");
            let names = if hashed {
                Vec::new()
            } else {
                raw_names.split(',').map(|s| s.to_string()).collect()
            };
            Some(Entry {
                raw_names,
                names,
                hashed,
                fingerprint,
                key_type,
            })
        })
        .collect()
}

/// The entries a host from your config points at. One single place, so that
/// the sidebar and the doctor cannot possibly give a different answer.
pub fn claimed(source: &crate::model::Source, files: &[PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    for host in &source.hosts {
        out.extend(lookup(&host.hostname, host.port_or_default(), files));
    }
    out
}

impl Ledger {
    /// One row per name instead of per key: a machine with an RSA, an ECDSA
    /// *and* an Ed25519 key is one machine.
    pub fn per_name(&self) -> Vec<(String, Vec<&Entry>)> {
        let mut order: Vec<String> = Vec::new();
        for e in &self.entries {
            let name = e.label();
            if !order.contains(&name) {
                order.push(name);
            }
        }
        order
            .into_iter()
            .map(|name| {
                let lines = self
                    .entries
                    .iter()
                    .filter(|e| e.label() == name)
                    .collect::<Vec<_>>();
                (name, lines)
            })
            .collect()
    }
}

impl Ledger {
    /// Names that designate the same machine as another name. That is the only
    /// statement an entry can make about itself: the file knows nothing about
    /// reachability.
    pub fn duplicate_names(&self) -> Vec<String> {
        self.duplicates()
            .into_iter()
            .flat_map(|(_, names)| names)
            .collect()
    }
}

/// One branch of the tree: a host from your config with the evidence hanging
/// below it. `host` is None for entries nobody points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    pub host: Option<String>,
    /// The name the lookup happens under (the HostName, or the HostKeyAlias).
    pub lookup_name: String,
    /// The names of the entries hanging below it.
    pub entries: Vec<String>,
}

/// Per host the entries it points at. Costs one ssh-keygen call per host, so
/// only call this when reading things in.
pub fn lookup_per_host(
    source: &crate::model::Source,
    files: &[PathBuf],
) -> Vec<(String, String, Vec<String>)> {
    source
        .hosts
        .iter()
        .map(|h| {
            let lookup_name = lookup_name_for(h);
            let hits = lookup(&lookup_name, h.port_or_default(), files);
            (h.alias.clone(), lookup_name, hits)
        })
        .collect()
}

/// Under which name does ssh look this host up? Normally the HostName, unless
/// there is a HostKeyAlias — which is exactly what that option exists for.
pub fn lookup_name_for(host: &crate::model::Host) -> String {
    host.options
        .iter()
        .find_map(|o| {
            let (k, v) = o.split_once(char::is_whitespace)?;
            k.eq_ignore_ascii_case("hostkeyalias")
                .then(|| v.trim().to_string())
        })
        .unwrap_or_else(|| host.hostname.clone())
}

/// Builds the tree: every host with its evidence, and at the end whatever
/// belongs nowhere. Pure, so it can be tested without starting ssh-keygen.
pub fn tree(per_host: &[(String, String, Vec<String>)], ledger: &Ledger) -> Vec<Branch> {
    let mut branches: Vec<Branch> = per_host
        .iter()
        .map(|(alias, lookup_name, raw)| Branch {
            host: Some(alias.clone()),
            lookup_name: lookup_name.clone(),
            entries: ledger
                .per_name()
                .into_iter()
                .filter(|(_, lines)| lines.iter().any(|e| raw.contains(&e.raw_names)))
                .map(|(name, _)| name)
                .collect(),
        })
        .collect();

    let claimed: Vec<String> = branches.iter().flat_map(|t| t.entries.clone()).collect();
    for (name, _) in ledger.per_name() {
        if !claimed.contains(&name) {
            branches.push(Branch {
                host: None,
                lookup_name: name.clone(),
                entries: vec![name],
            });
        }
    }
    branches
}

/// Does the ledger know this hostname? We ask `ssh-keygen -F`, because it
/// knows the rules we do not want to reimplement: hashed names, ports in
/// square brackets, and case insensitivity.
pub fn lookup(hostname: &str, port: u16, files: &[PathBuf]) -> Vec<String> {
    let query = if port == 22 {
        hostname.to_string()
    } else {
        format!("[{hostname}]:{port}")
    };
    let mut found = Vec::new();
    for file in files {
        let Ok(out) = Command::new("ssh-keygen")
            .arg("-F")
            .arg(&query)
            .arg("-f")
            .arg(file)
            .output()
        else {
            continue;
        };
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            if let Some(first) = line.split_whitespace().next() {
                found.push(first.to_string());
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "\
256 SHA256:aaa 192.0.2.10 (ED25519)
3072 SHA256:bbb 192.0.2.10 (RSA)
256 SHA256:ccc nas.example (ED25519)
256 SHA256:ccc NAS.Example (ED25519)
256 SHA256:ddd |1|Zm9v|YmFy (ED25519)
256 SHA256:eee server.example,192.0.2.20 (ED25519)
";

    #[test]
    fn reads_the_entries() {
        let e = parse_listing(LISTING);
        assert_eq!(e.len(), 6);
        assert_eq!(e[0].fingerprint, "SHA256:aaa");
        assert_eq!(e[0].key_type, "ED25519");
        assert_eq!(e[0].names, vec!["192.0.2.10"]);
    }

    #[test]
    fn a_hashed_line_is_recognised_and_has_no_readable_name() {
        let e = parse_listing(LISTING);
        let h = e.iter().find(|x| x.hashed).unwrap();
        assert!(h.names.is_empty());
        assert_eq!(h.label(), "(hashed name)");
    }

    #[test]
    fn several_names_on_one_line_belong_to_one_entry() {
        let e = parse_listing(LISTING);
        let r = e.iter().find(|x| x.names.len() == 2).unwrap();
        assert_eq!(r.names, vec!["server.example", "192.0.2.20"]);
    }

    fn ledger() -> Ledger {
        Ledger {
            files: vec![],
            entries: parse_listing(LISTING),
        }
    }

    #[test]
    fn duplicate_names_can_be_asked_for_separately() {
        let d = ledger().duplicate_names();
        assert!(d.contains(&"nas.example".to_string()));
        assert!(d.contains(&"NAS.Example".to_string()));
        // Two key types under one name is not a duplicate.
        assert!(!d.contains(&"192.0.2.10".to_string()));
    }

    #[test]
    fn the_tree_hangs_evidence_under_the_right_host() {
        let per_host = vec![(
            "unraid".to_string(),
            "192.0.2.10".to_string(),
            vec!["192.0.2.10".to_string()],
        )];
        let t = tree(&per_host, &ledger());
        assert_eq!(t[0].host.as_deref(), Some("unraid"));
        assert_eq!(t[0].entries, vec!["192.0.2.10"]);
    }

    #[test]
    fn entries_without_a_host_end_up_at_the_bottom_with_no_parent() {
        let per_host = vec![(
            "unraid".to_string(),
            "192.0.2.10".to_string(),
            vec!["192.0.2.10".to_string()],
        )];
        let t = tree(&per_host, &ledger());
        let loose: Vec<&Branch> = t.iter().filter(|x| x.host.is_none()).collect();
        // nas.example, NAS.Example, the hashed line and server+ip are left over
        assert_eq!(loose.len(), 4, "got {loose:?}");
        assert!(loose.iter().all(|x| x.host.is_none()));
    }

    #[test]
    fn a_host_without_evidence_gets_an_empty_branch() {
        let per_host = vec![("new".to_string(), "new.nl".to_string(), vec![])];
        let t = tree(&per_host, &ledger());
        assert_eq!(t[0].host.as_deref(), Some("new"));
        assert!(t[0].entries.is_empty());
    }

    #[test]
    fn hostkeyalias_determines_the_lookup_name() {
        use crate::model::Host;
        let mut h = Host {
            alias: "unraid".into(),
            hostname: "192.0.2.10".into(),
            ..Default::default()
        };
        assert_eq!(lookup_name_for(&h), "192.0.2.10");
        h.options.push("HostKeyAlias unraid-fixed".into());
        assert_eq!(lookup_name_for(&h), "unraid-fixed");
    }

    #[test]
    fn grouped_per_name_regardless_of_the_number_of_keys() {
        let l = Ledger {
            files: vec![],
            entries: parse_listing(LISTING),
        };
        let g = l.per_name();
        // 192.0.2.10 has two keys but is one entry.
        let ip = g.iter().find(|(n, _)| n == "192.0.2.10").unwrap();
        assert_eq!(ip.1.len(), 2);
        // five different names in total
        assert_eq!(
            g.len(),
            5,
            "got {:?}",
            g.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_same_machine_under_two_names_is_reported() {
        let l = Ledger {
            files: vec![],
            entries: parse_listing(LISTING),
        };
        let d = l.duplicates();
        assert_eq!(d.len(), 1, "got {d:?}");
        assert_eq!(d[0].1, vec!["NAS.Example", "nas.example"]);
    }

    #[test]
    fn two_key_types_for_the_same_name_are_not_a_duplicate() {
        // 192.0.2.10 is in there with an ED25519 *and* an RSA key; that is
        // normal and must not produce a warning.
        let l = Ledger {
            files: vec![],
            entries: parse_listing(LISTING),
        };
        assert!(
            !l.duplicates()
                .iter()
                .any(|(_, n)| n.contains(&"192.0.2.10".to_string()))
        );
    }

    #[test]
    fn paths_come_from_ssh_and_never_from_a_wildcard() {
        // Exactly the trap: next to known_hosts sits a known_hosts.old with
        // revoked keys. That one must never be included.
        let resolved = vec![(
            "userknownhostsfile".to_string(),
            "/nowhere/known_hosts /nowhere/known_hosts2".to_string(),
        )];
        let paths = files_in_use(&resolved);
        // They do not exist, so the list is empty — but above all: there is no
        // wildcard anywhere that could dredge up the .old file.
        assert!(paths.is_empty());
        assert!(!format!("{resolved:?}").contains(".old"));
    }

    #[test]
    fn a_tilde_in_a_path_gets_expanded() {
        let p = split_paths("~/.ssh/known_hosts");
        assert!(p[0].is_absolute());
        assert!(p[0].ends_with(".ssh/known_hosts"));
    }

    #[test]
    fn several_paths_on_one_line_get_split() {
        assert_eq!(split_paths("/a/b /c/d").len(), 2);
    }
}

/// Removes exactly those lines whose first field equals `raw_names`. Pure, so
/// it can be tested.
///
/// Deliberately *not* via `ssh-keygen -R`: that matches case-insensitively, so
/// removing `NAS.Example` takes `nas.example` along with it, and it cannot deal
/// with hashed entries because you do not know their name. Comparing on the
/// first field removes exactly what you point at.
pub fn without(text: &str, raw_names: &str) -> (String, usize) {
    let mut removed = 0;
    let mut out = String::new();
    for line in text.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        // Markers such as @revoked come before the names.
        let field = if first.starts_with('@') {
            line.split_whitespace().nth(1).unwrap_or("")
        } else {
            first
        };
        if !line.trim_start().starts_with('#') && field == raw_names {
            removed += 1;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, removed)
}

/// Removes an entry from every file it occurs in, leaving a backup next to it.
/// Returns how many lines are gone.
pub fn remove_entry(files: &[PathBuf], raw_names: &str) -> Result<usize, String> {
    let mut total = 0;
    for file in files {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        let (updated, removed) = without(&text, raw_names);
        if removed == 0 {
            continue;
        }
        let backup = file.with_extension("before-sshctl");
        std::fs::copy(file, &backup)
            .map_err(|e| format!("could not back up {}: {e}", file.display()))?;
        std::fs::write(file, updated)
            .map_err(|e| format!("could not write {}: {e}", file.display()))?;
        total += removed;
    }
    if total == 0 {
        return Err("found nothing to remove".to_string());
    }
    Ok(total)
}

#[cfg(test)]
mod removal_tests {
    use super::*;

    const FILE: &str = "\
# a comment
NAS.Example ssh-rsa AAAAB3aaa
nas.example ssh-rsa AAAAB3bbb
192.0.2.10 ssh-ed25519 AAAAC3ccc
192.0.2.10 ssh-rsa AAAAB3ddd
|1|Zm9v|YmFy ssh-ed25519 AAAAC3eee
@revoked bad.example ssh-ed25519 AAAAC3fff
";

    #[test]
    fn removes_only_the_exact_name() {
        // This is the trap that ssh-keygen -R does fall into: matching
        // case-insensitively removes two instead of one.
        let (out, removed) = without(FILE, "NAS.Example");
        assert_eq!(removed, 1);
        assert!(out.contains("nas.example"));
        assert!(!out.contains("NAS.Example"));
    }

    #[test]
    fn removes_every_key_belonging_to_one_name() {
        let (out, removed) = without(FILE, "192.0.2.10");
        assert_eq!(removed, 2, "both key types belong to the same machine");
        assert!(!out.contains("192.0.2.10"));
    }

    #[test]
    fn a_hashed_entry_can_go_too() {
        let (out, removed) = without(FILE, "|1|Zm9v|YmFy");
        assert_eq!(removed, 1);
        assert!(!out.contains("|1|Zm9v"));
    }

    #[test]
    fn a_marker_in_front_does_not_get_in_the_way() {
        let (out, removed) = without(FILE, "bad.example");
        assert_eq!(removed, 1);
        assert!(!out.contains("bad.example"));
    }

    #[test]
    fn comments_and_everything_else_stay_put() {
        let (out, _) = without(FILE, "nas.example");
        assert!(out.starts_with("# a comment"));
        assert_eq!(out.lines().count(), 6);
    }

    #[test]
    fn an_unknown_name_changes_nothing() {
        let (out, removed) = without(FILE, "does.not.exist");
        assert_eq!(removed, 0);
        assert_eq!(out.lines().count(), 7);
    }
}

/// Fetches a machine's host keys with `ssh-keyscan`.
///
/// Note what this is *not*: a check. You get the key of whoever answers,
/// whoever that may be. The fingerprint should be confirmed by some other
/// route before you trust it.
pub fn scan(hostname: &str, port: u16) -> Result<Vec<(String, String, String)>, String> {
    let out = Command::new("ssh-keyscan")
        .args(["-T", "5", "-p", &port.to_string(), hostname])
        .output()
        .map_err(|e| format!("could not start ssh-keyscan: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return Err(format!("no answer from {hostname}:{port}"));
    }
    Ok(lines
        .iter()
        .filter_map(|l| {
            let mut v = l.split_whitespace();
            let name = v.next()?.to_string();
            let kind = v.next()?.to_string();
            Some((name, kind, l.to_string()))
        })
        .collect())
}

/// Appends fetched lines to the first known_hosts file.
pub fn append(files: &[PathBuf], lines: &[String]) -> Result<usize, String> {
    let Some(file) = files.first() else {
        return Err("no known_hosts file known".to_string());
    };
    let existing = std::fs::read_to_string(file).unwrap_or_default();
    let backup = file.with_extension("before-sshctl");
    std::fs::copy(file, &backup).map_err(|e| format!("could not make a backup: {e}"))?;
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    std::fs::write(file, out).map_err(|e| format!("could not write {}: {e}", file.display()))?;
    Ok(lines.len())
}
