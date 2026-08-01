//! The model of an SSH configuration.
//!
//! `~/.ssh/config` is the single source of truth. This model is a working
//! copy: you read the file in, edit the model, and write it back.
//!
//! The working copy may also sit on disk to look at, but it is wiped both on
//! startup and on exit. That way the question "which of the two is the right
//! one" can never arise: outside a running session there is simply only one
//! file.

use std::path::{Path, PathBuf};

pub fn ssh_dir() -> PathBuf {
    home().join(".ssh")
}

pub fn ssh_config_path() -> PathBuf {
    ssh_dir().join("config")
}

/// The working copy: a snapshot of what is currently in memory. It gets
/// written, never read back — otherwise it would become a second truth after
/// all.
pub fn work_path() -> PathBuf {
    home().join(".config/sshctl/working-copy.toml")
}

pub fn home() -> PathBuf {
    // Windows sets USERPROFILE and usually no HOME; panicking on the normal
    // state of a supported platform is not an option.
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .expect("neither HOME nor USERPROFILE is set")
}

/// Permission bits of a file, or `None` where the notion does not exist.
/// Windows has no Unix modes; inventing a number there would trip every
/// checker that compares against 0o600.
#[cfg(unix)]
pub fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(std::fs::metadata(path).ok()?.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
pub fn mode_of(_path: &Path) -> Option<u32> {
    None
}

/// Throws away all working files. Meant to run both on startup and on exit, so
/// that nothing is left lying around between sessions.
pub fn wipe_work_files() {
    let _ = std::fs::remove_file(work_path());
}

#[derive(Debug, Default, Clone)]
pub struct Source {
    pub defaults: Defaults,
    /// Order here = order in the file that gets written.
    pub hosts: Vec<Host>,
    /// Lines sshctl does not understand and therefore must not rewrite either,
    /// such as `Match` or `Include` constructs. Kept so the checks can say what
    /// is being passed through untouched.
    pub unsupported: Vec<String>,
    /// Raw lines that stood before the first `Host` block, exactly as written.
    ///
    /// Position matters in ssh: `Include` pulls a file in at the spot where it
    /// stands, and first value wins. So these are written back in the same
    /// place rather than tidied away somewhere.
    pub leading: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Defaults {
    pub add_keys_to_agent: bool,
    /// Only meaningful on macOS.
    pub use_keychain: bool,
    /// Stops ssh from offering arbitrary agent keys and leaving you with a
    /// meaningless "Permission denied".
    pub identities_only: bool,
    pub server_alive_interval: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Host {
    /// The short name you type: `ssh unraid`.
    pub alias: String,
    /// The real address or IP. Stays filled with the alias when no `HostName`
    /// was given, because that is what ssh does — but see `hostname_explicit`,
    /// which says whether it was actually there.
    pub hostname: String,
    /// Was there a `HostName` line in the file?
    ///
    /// Writing one out of nowhere changes the meaning. `Host web1 web2`
    /// without a HostName lets both names point at themselves; adding
    /// `HostName web1` suddenly sends web2 to web1. And on `Host *.internal`
    /// it would literally produce `HostName *.internal`, which solves
    /// nothing.
    pub hostname_explicit: bool,
    pub user: String,
    /// Filename inside ~/.ssh, or an absolute path.
    pub key: Option<String>,
    pub port: Option<u16>,
    /// Which machine(s) the connection jumps through. Multiple hops are
    /// comma-separated; every hop may be `user@host:port` and may also be an
    /// alias from this very file.
    pub proxy_jump: Option<String>,
    /// Extra names this block also matches on.
    pub aliases: Vec<String>,
    /// Raw ssh options that sshctl does not model itself, e.g.
    /// "HostKeyAlgorithms +ssh-rsa" for old equipment.
    pub options: Vec<String>,
    /// Free-form group name; purely for the readability of the file.
    pub group: Option<String>,
    /// Comment that sat right above the block; kept when rewriting.
    pub comment: Option<String>,
    /// Raw lines that followed this block and that sshctl does not model —
    /// a whole `Match` section, say. Written back here unchanged, because
    /// where they stand is part of what they mean.
    pub trailing: Vec<String>,
}

impl Host {
    /// Absolute path to the private key, if one is given and sshctl can work
    /// out where it is. Returns `None` for a path with tokens only ssh can
    /// fill in — see [`Host::key_has_tokens`], because "I do not know" and
    /// "there is none" must not look the same.
    pub fn key_path(&self) -> Option<PathBuf> {
        let key = self.key.as_ref()?;
        let expanded = expand_tokens(key);
        if expanded.contains('%') {
            return None;
        }
        Some(expand(&expanded))
    }

    /// Does the key path contain `%`-tokens that sshctl cannot resolve? Then
    /// there *is* a key, we just cannot say anything about it.
    pub fn key_has_tokens(&self) -> bool {
        self.key
            .as_ref()
            .map(|k| expand_tokens(k).contains('%'))
            .unwrap_or(false)
    }

    /// The way it ends up in the file: with ~ instead of /Users/…, because
    /// that stays readable and travels along to another machine.
    pub fn key_for_config(&self) -> Option<String> {
        self.key.as_ref().map(|k| {
            // Only a bare filename gets ~/.ssh/ put in front of it. Anything
            // with a slash or a %-token is already a path of its own; adding to
            // it would break it.
            let bare = !k.contains('/') && !k.contains('%');
            let path = if bare {
                format!("~/.ssh/{k}")
            } else {
                k.clone()
            };
            // A space has to go back inside quotes, otherwise ssh reads the
            // path as two arguments.
            if path.contains(char::is_whitespace) {
                format!("\"{path}\"")
            } else {
                path
            }
        })
    }

    pub fn port_or_default(&self) -> u16 {
        self.port.unwrap_or(22)
    }
}

/// The public half sits next to the private key as `<name>.pub` — appended to
/// the whole filename, not swapping the extension.
///
/// `PathBuf::with_extension` gets this wrong the moment a key is called
/// `id_ed25519.old`: that becomes `id_ed25519.pub`, an existing and completely
/// different key. So it is spelled out here once, and used everywhere.
pub fn public_half(private: &Path) -> PathBuf {
    let mut name = private.file_name().unwrap_or_default().to_os_string();
    name.push(".pub");
    private.with_file_name(name)
}

/// Fills in the `%`-tokens sshctl can be sure about, and leaves the rest.
///
/// `%d` is your home directory and `%%` a literal percent sign; both are the
/// same no matter which host you connect to. `%h`, `%r` and `%p` depend on the
/// connection and are deliberately left standing — a guess there would be worse
/// than saying nothing.
fn expand_tokens(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('d') => out.push_str(&home().to_string_lossy()),
            Some('%') => out.push('%'),
            Some(other) => {
                out.push('%');
                out.push(other);
            }
            None => out.push('%'),
        }
    }
    out
}

/// Turns ~ and bare filenames into an absolute path.
pub fn expand(raw: &str) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/") {
        home().join(rest)
    } else if raw.starts_with('/') {
        PathBuf::from(raw)
    } else {
        ssh_dir().join(raw)
    }
}

/// One `key = ["…", "…"]` line, or nothing at all for an empty list.
fn toml_list(out: &mut String, key: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    let quoted: Vec<String> = items.iter().map(|s| toml_string(s)).collect();
    out.push_str(&format!("{key} = [{}]\n", quoted.join(", ")));
}

/// A TOML basic string: quotes, backslashes and control characters escaped.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Source {
    /// Writes the snapshot out. Fails silently: this file is a convenience,
    /// not state, so it must never hold up a session.
    pub fn write_work_copy(&self) {
        let path = work_path();
        if let Some(parent) = path.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            return;
        }
        let header = "# Snapshot of what sshctl currently holds in memory.\n\
                      # Wiped on startup and on exit; only there to look at.\n\
                      # The real configuration is ~/.ssh/config.\n\n";
        let _ = std::fs::write(&path, format!("{header}{}", self.snapshot()));
    }

    /// Renders the snapshot as TOML by hand. A serialisation library used to
    /// do this, but nothing ever reads the file back — see `work_path` — and
    /// fourteen crates was a steep price for one write-only convenience.
    fn snapshot(&self) -> String {
        let mut out = String::new();
        // Root values have to stand before the first table to belong to it.
        toml_list(&mut out, "unsupported", &self.unsupported);
        toml_list(&mut out, "leading", &self.leading);
        let d = &self.defaults;
        out.push_str("[defaults]\n");
        out.push_str(&format!("add_keys_to_agent = {}\n", d.add_keys_to_agent));
        out.push_str(&format!("use_keychain = {}\n", d.use_keychain));
        out.push_str(&format!("identities_only = {}\n", d.identities_only));
        out.push_str(&format!(
            "server_alive_interval = {}\n",
            d.server_alive_interval
        ));
        for h in &self.hosts {
            out.push_str("\n[[host]]\n");
            out.push_str(&format!("alias = {}\n", toml_string(&h.alias)));
            out.push_str(&format!("hostname = {}\n", toml_string(&h.hostname)));
            out.push_str(&format!("hostname_explicit = {}\n", h.hostname_explicit));
            out.push_str(&format!("user = {}\n", toml_string(&h.user)));
            if let Some(key) = &h.key {
                out.push_str(&format!("key = {}\n", toml_string(key)));
            }
            if let Some(port) = h.port {
                out.push_str(&format!("port = {port}\n"));
            }
            if let Some(jump) = &h.proxy_jump {
                out.push_str(&format!("proxy_jump = {}\n", toml_string(jump)));
            }
            toml_list(&mut out, "aliases", &h.aliases);
            toml_list(&mut out, "options", &h.options);
            if let Some(group) = &h.group {
                out.push_str(&format!("group = {}\n", toml_string(group)));
            }
            if let Some(comment) = &h.comment {
                out.push_str(&format!("comment = {}\n", toml_string(comment)));
            }
            toml_list(&mut out, "trailing", &h.trailing);
        }
        out
    }

    /// Duplicate aliases are silently fatal: ssh takes the first match and
    /// ignores the rest without a word.
    pub fn validate(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for host in &self.hosts {
            for name in std::iter::once(&host.alias).chain(host.aliases.iter()) {
                if seen.contains(&name.as_str()) {
                    problems.push(format!(
                        "alias '{name}' appears more than once — ssh only uses the first"
                    ));
                }
                seen.push(name);
            }
            if host.alias.trim().is_empty() {
                problems.push("a host has an empty alias".to_string());
            }
            // No complaint about whitespace in an alias: `Host "my server"`
            // is legal ssh, and the generator puts the quotes back. The GUI
            // and `add` refuse to *create* such names — free text with a
            // space in it is nearly always two names typed as one — but a
            // file that already has one is not broken.
            // No complaint about a missing HostName: that is valid ssh and
            // means "use the name you typed".
        }
        problems
    }
}
