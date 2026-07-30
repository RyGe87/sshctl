//! Which keys are lying around in ~/.ssh, and which host uses them?
//!
//! This used to be buried in the doctor, which could only say a sentence about
//! it. As a list of its own you can also *do* something with it: give an
//! unused key a host in one click.

use crate::model::{Source, ssh_dir};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// Filename inside ~/.ssh, e.g. "id_ed25519_unraid".
    pub name: String,
    /// The alias of the host using it, if there is one.
    pub used_by: Option<String>,
    /// Is the public half lying next to it? Without that half you cannot
    /// authorise the key anywhere.
    pub has_public: bool,
}

impl KeyEntry {
    /// No host in this config points at it. That is something else than
    /// unused: sshctl does not see what happens outside `~/.ssh/config`.
    pub fn is_orphan(&self) -> bool {
        self.used_by.is_none()
    }

    /// A usable alias derived from the filename:
    /// "id_ed25519_unraid" -> "unraid", "server_key" -> "server".
    ///
    /// With a bare default name like "id_ed25519" there is no name *in* it, so
    /// we return nothing rather than invent a nonsense alias. The user then
    /// has to name it themselves.
    pub fn suggested_alias(&self) -> String {
        const BARE: [&str; 6] = [
            "id_ed25519",
            "id_ed25519_sk",
            "id_rsa",
            "id_ecdsa",
            "id_ecdsa_sk",
            "id_dsa",
        ];
        if BARE.contains(&self.name.as_str()) {
            return String::new();
        }
        let mut name = self.name.as_str();
        for prefix in ["id_ed25519_", "id_ecdsa_", "id_rsa_", "id_dsa_"] {
            if let Some(rest) = name.strip_prefix(prefix) {
                name = rest;
                break;
            }
        }
        if let Some(rest) = name.strip_suffix("_key") {
            name = rest;
        }
        name.to_string()
    }
}

/// All private keys in ~/.ssh, alphabetically, with who uses them.
pub fn inventory(source: &Source) -> Vec<KeyEntry> {
    let dir = ssh_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut out: Vec<KeyEntry> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && looks_like_private_key(p))
        .map(|path| {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            KeyEntry {
                used_by: user_of(source, &name),
                has_public: crate::model::public_half(&path).exists(),
                name,
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Which host points at this key? The comparison happens on the full path,
/// because a host may also give an absolute path.
fn user_of(source: &Source, name: &str) -> Option<String> {
    let target = ssh_dir().join(name);
    source
        .hosts
        .iter()
        .find(|h| h.key_path().as_deref() == Some(target.as_path()))
        .map(|h| h.alias.clone())
}

/// A file that looks like a private key. Deliberately judged on its contents
/// and not on its name: keys are called all sorts of things.
pub fn looks_like_private_key(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if name.ends_with(".pub") || name.starts_with('.') {
        return false;
    }
    if matches!(
        name.as_ref(),
        "config" | "known_hosts" | "known_hosts.old" | "authorized_keys" | "agent"
    ) {
        return false;
    }
    std::fs::read_to_string(path)
        .map(|c| c.starts_with("-----BEGIN"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> KeyEntry {
        KeyEntry {
            name: name.to_string(),
            used_by: None,
            has_public: true,
        }
    }

    #[test]
    fn the_alias_is_derived_from_the_filename() {
        assert_eq!(entry("id_ed25519_unraid").suggested_alias(), "unraid");
        assert_eq!(entry("server_key").suggested_alias(), "server");
        assert_eq!(entry("id_rsa_work").suggested_alias(), "work");
    }

    #[test]
    fn a_bare_default_name_yields_no_alias() {
        // "id_ed25519" contains no name; turning it into a host 'id_ed25519'
        // with hostname 'id_ed25519' is nonsense.
        assert_eq!(entry("id_ed25519").suggested_alias(), "");
        assert_eq!(entry("id_rsa").suggested_alias(), "");
    }

    #[test]
    fn a_name_without_a_recognisable_pattern_stays_as_it_is() {
        assert_eq!(entry("nuc_backup").suggested_alias(), "nuc_backup");
    }

    #[test]
    fn a_key_without_a_host_is_an_orphan() {
        assert!(entry("loose").is_orphan());
        let used = KeyEntry {
            used_by: Some("unraid".into()),
            ..entry("id_ed25519_unraid")
        };
        assert!(!used.is_orphan());
    }

    #[test]
    fn public_keys_and_well_known_files_do_not_count() {
        assert!(!looks_like_private_key(Path::new("/tmp/x.pub")));
        assert!(!looks_like_private_key(Path::new("/tmp/config")));
        assert!(!looks_like_private_key(Path::new("/tmp/known_hosts")));
    }
}

/// Everything we can tell about a single key without giving away the private
/// half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyDetail {
    pub name: String,
    pub bits: String,
    pub fingerprint: String,
    /// The comment field out of the key, usually who made it where.
    pub comment: String,
    pub key_type: String,
    pub encrypted: bool,
    /// The public line, ready to paste into authorized_keys.
    pub public_line: Option<String>,
    /// Was that line in a .pub file, or did we have to derive it?
    pub public_derived: bool,
    /// Permissions of the file, e.g. 0o600.
    pub mode: u32,
    pub used_by: Vec<String>,
}

/// `ssh-keygen -l -f` gives: `256 SHA256:xxx the comment (ED25519)`.
/// The comment may contain spaces, so we trim from both ends.
pub fn parse_key_line(line: &str) -> Option<(String, String, String, String)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 3 {
        return None;
    }
    let bits = fields[0].to_string();
    let fingerprint = fields[1].to_string();
    let last = fields[fields.len() - 1];
    let (key_type, end) = if last.starts_with('(') && last.ends_with(')') {
        (last.trim_matches(['(', ')']).to_string(), fields.len() - 1)
    } else {
        ("(unknown)".to_string(), fields.len())
    };
    let comment = fields[2..end].join(" ");
    Some((bits, fingerprint, comment, key_type))
}

/// Fetches the details of a single key in ~/.ssh.
pub fn detail(name: &str, source: &Source) -> Option<KeyDetail> {
    let path = ssh_dir().join(name);
    if !path.is_file() {
        return None;
    }

    let out = Command::new("ssh-keygen")
        .args(["-l", "-f"])
        .arg(&path)
        .output()
        .ok()?;
    let (bits, fingerprint, comment, key_type) =
        parse_key_line(String::from_utf8_lossy(&out.stdout).lines().next()?)?;

    // Not being encrypted means we can derive the public half, even when there
    // is no .pub lying next to it. That is exactly the case where you need it:
    // a key you cannot yet authorise anywhere.
    let encrypted = !Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(&path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(true);

    let pub_path = crate::model::public_half(&path);
    let (public_line, public_derived) = match std::fs::read_to_string(&pub_path) {
        Ok(t) => (Some(t.trim().to_string()), false),
        Err(_) if !encrypted => {
            let derived = Command::new("ssh-keygen")
                .args(["-y", "-P", "", "-f"])
                .arg(&path)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
            (derived, true)
        }
        Err(_) => (None, false),
    };

    let mode = crate::model::mode_of(&path).unwrap_or(0);

    let target = ssh_dir().join(name);
    let used_by = source
        .hosts
        .iter()
        .filter(|h| h.key_path().as_deref() == Some(target.as_path()))
        .map(|h| h.alias.clone())
        .collect();

    Some(KeyDetail {
        name: name.to_string(),
        bits,
        fingerprint,
        comment,
        key_type,
        encrypted,
        public_line,
        public_derived,
        mode,
        used_by,
    })
}

#[cfg(test)]
mod detail_tests {
    use super::*;

    #[test]
    fn reads_an_ordinary_line() {
        let (bits, fp, comment, t) =
            parse_key_line("256 SHA256:xwKno4 claude-unraid (ED25519)").unwrap();
        assert_eq!(bits, "256");
        assert_eq!(fp, "SHA256:xwKno4");
        assert_eq!(comment, "claude-unraid");
        assert_eq!(t, "ED25519");
    }

    #[test]
    fn a_comment_with_spaces_stays_intact() {
        let (_, _, comment, t) =
            parse_key_line("3072 SHA256:abc my old key from 2019 (RSA)").unwrap();
        assert_eq!(comment, "my old key from 2019");
        assert_eq!(t, "RSA");
    }

    #[test]
    fn a_line_without_a_comment() {
        let (_, _, comment, t) = parse_key_line("256 SHA256:abc no comment (ED25519)").unwrap();
        assert_eq!(comment, "no comment");
        assert_eq!(t, "ED25519");
    }

    #[test]
    fn nonsense_yields_nothing() {
        assert!(parse_key_line("").is_none());
        assert!(parse_key_line("short thing").is_none());
    }
}

/// Creates a new ed25519 key following the naming rule `id_ed25519_<name>`.
///
/// Deliberately **without** a passphrase. It would otherwise have to go
/// through ssh-keygen's command line and thus sit in the process table for a
/// moment, and it would travel through this app's memory. If you want one on
/// the key, do that afterwards with `ssh-keygen -p`, where you type it behind
/// a hidden prompt.
pub fn generate(alias: &str, comment: &str) -> Result<String, String> {
    let name = filename_for(alias)?;
    let path = ssh_dir().join(&name);
    if path.exists() {
        return Err(format!("{name} already exists"));
    }
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(&path)
        .output()
        .map_err(|e| format!("could not start ssh-keygen: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(name)
}

/// Turns an alias into a filename following the convention, and refuses
/// anything that does not yield a usable name.
pub fn filename_for(alias: &str) -> Result<String, String> {
    let clean = alias.trim();
    if clean.is_empty() {
        return Err("give it a name".to_string());
    }
    if clean.contains('/') || clean.starts_with('.') {
        return Err("a name may not contain / and may not start with a dot".to_string());
    }
    if clean.contains(char::is_whitespace) {
        return Err("a name may not contain spaces".to_string());
    }
    Ok(format!("id_ed25519_{clean}"))
}

/// Moves a key into `~/.ssh/deleted/` instead of throwing it away. Erasing a
/// private key is irreversible and can lock you out of machines you no longer
/// remember are using it.
pub fn delete(name: &str) -> Result<std::path::PathBuf, String> {
    let source = ssh_dir().join(name);
    if !source.is_file() {
        return Err(format!("{name} does not exist"));
    }
    let dir = ssh_dir().join("deleted");
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    restrict_to_owner(&dir);

    let target = free_name(&dir, name);
    std::fs::rename(&source, &target).map_err(|e| format!("move failed: {e}"))?;
    let pub_source = ssh_dir().join(format!("{name}.pub"));
    if pub_source.is_file() {
        let _ = std::fs::rename(
            &pub_source,
            dir.join(format!(
                "{}.pub",
                target.file_name().unwrap_or_default().to_string_lossy()
            )),
        );
    }
    Ok(target)
}

/// Permissions equal to those of ~/.ssh: private keys live in here. On
/// Windows there is nothing to set — the profile directory is already the
/// user's own.
#[cfg(unix)]
fn restrict_to_owner(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_to_owner(_dir: &Path) {}

/// Looks for a name that does not exist yet, so that a second deletion does
/// not overwrite the first.
fn free_name(dir: &Path, name: &str) -> std::path::PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    for n in 2..1000 {
        let candidate = dir.join(format!("{name}.{n}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    first
}

#[cfg(test)]
mod name_tests {
    use super::*;

    #[test]
    fn follows_the_naming_rule() {
        assert_eq!(filename_for("work").unwrap(), "id_ed25519_work");
        assert_eq!(filename_for("  unraid ").unwrap(), "id_ed25519_unraid");
    }

    #[test]
    fn refuses_what_cannot_be_a_filename() {
        assert!(filename_for("").is_err());
        assert!(filename_for("   ").is_err());
        assert!(filename_for("dir/key").is_err());
        assert!(filename_for(".hidden").is_err());
        assert!(filename_for("two words").is_err());
    }
}

/// Changes the comment field of a key.
///
/// Only touches this file: copies that already sit in `authorized_keys` on a
/// server keep their old comment.
pub fn set_comment(name: &str, comment: &str) -> Result<(), String> {
    let path = ssh_dir().join(name);
    if !path.is_file() {
        return Err(format!("{name} does not exist"));
    }
    let out = Command::new("ssh-keygen")
        .args(["-c", "-P", "", "-C", comment, "-f"])
        .arg(&path)
        .output()
        .map_err(|e| format!("could not start ssh-keygen: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    if err.contains("passphrase") {
        return Err(format!(
            "this key has a passphrase; change the comment in a terminal with: \
             ssh-keygen -c -C \"{comment}\" -f ~/.ssh/{name}"
        ));
    }
    Err(err.trim().to_string())
}
