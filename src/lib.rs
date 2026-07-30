//! The core of sshctl, shared by the CLI and the GUI.
//!
//! `~/.ssh/config` is the single source of truth. The chain is:
//!
//! ```text
//!   ~/.ssh/config  --parser-->  Source  --generate-->  ~/.ssh/config
//!                       \                  /
//!                        `-- fidelity ----'      (what does not survive that round trip?)
//! ```
//!
//! Neither shell may know anything about ssh of its own: all the truth lives
//! here, so the two cannot possibly drift apart.

pub mod catalog;
pub mod doctor;
pub mod effective;
pub mod fidelity;
pub mod generate;
pub mod keys;
pub mod known;
pub mod model;
pub mod parser;
pub mod pattern;
pub mod proof;
pub mod proxy;

use model::Source;

/// Reads the system-wide file, if there is one. It applies to *every*
/// connection yet appears nowhere in the user's own file — exactly the kind of
/// setting you never get to see.
pub fn open_system() -> Option<(String, Source)> {
    const PATH: &str = "/etc/ssh/ssh_config";
    let text = std::fs::read_to_string(PATH).ok()?;
    Some((PATH.to_string(), parser::parse(&text)))
}

/// What [`open`] found. A struct rather than a tuple, because the third field
/// is the one you must not forget.
pub struct Opened {
    /// The file exactly as it is on disk. The round-trip check and the
    /// comparison before saving both need it.
    pub original: String,
    pub source: Source,
    /// Set when the file is there but could not be read as text. Then
    /// `original` is empty and `source` has no hosts — which looks exactly
    /// like a fresh, empty config, and that is the danger: writing would
    /// replace a file we never saw.
    ///
    /// A file that simply does not exist is not a problem but the normal
    /// starting point, so this stays `None`.
    pub unreadable: Option<String>,
}

impl Opened {
    /// May sshctl write to this file? Not being able to read it is exactly the
    /// case where the answer has to be no.
    pub fn writable(&self) -> bool {
        self.unreadable.is_none()
    }
}

/// Reads the configuration.
pub fn open() -> Opened {
    open_at(&model::ssh_config_path())
}

/// The same, on any path. Kept apart so that the "cannot read it" case can be
/// tested without going near a real `~/.ssh`.
pub fn open_at(path: &std::path::Path) -> Opened {
    let (original, unreadable) = match std::fs::read_to_string(path) {
        // Read fine, but is it really a config? A UTF-16 file whose text is
        // all ASCII is *valid* UTF-8 — every other byte is simply a NUL — so
        // read_to_string is happy and the parser finds nothing. That silence
        // is worse than an error, because the next step is writing.
        Ok(text) if text.contains('\0') => (
            String::new(),
            Some(format!(
                "{}: contains NUL bytes, so this is not a plain-text config \
                 (a file saved as UTF-16 looks like this)",
                path.display()
            )),
        ),
        Ok(text) => (text, None),
        // Not there yet: that is a starting point, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), None),
        // Anything else — no permission, or not text at all. A UTF-16 file
        // *with* a byte-order mark lands here, and that is not exotic:
        // PowerShell's `>` produces one by default.
        Err(e) => (String::new(), Some(format!("{}: {e}", path.display()))),
    };
    let source = parser::parse(&original);
    Opened {
        original,
        source,
        unreadable,
    }
}

/// Writes next to the target and then renames.
///
/// `fs::write` truncates first and then fills. A crash, a full disk or a
/// pulled plug in between leaves you with half a config — and half an ssh
/// config is worse than none, because ssh reads it and acts on it. A rename
/// within the same directory either happens or it does not.
pub fn write_atomically(target: &std::path::Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    let temp = target.with_extension("sshctl-new");
    {
        let mut file = create_private(&temp)?;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
        // Without this the rename can land before the contents do.
        file.sync_all()
            .map_err(|e| format!("cannot flush {}: {e}", temp.display()))?;
    }
    std::fs::rename(&temp, target).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("cannot put {} in place: {e}", target.display())
    })
}

/// 0600 straight away, so the file is never briefly readable by others.
#[cfg(unix)]
fn create_private(path: &std::path::Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn create_private(path: &std::path::Path) -> Result<std::fs::File, String> {
    std::fs::File::create(path).map_err(|e| format!("cannot create {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("sshctl-test-{name}"));
        let mut f = std::fs::File::create(&path).expect("could not create temp file");
        f.write_all(bytes).expect("could not write temp file");
        path
    }

    #[test]
    fn a_config_that_is_not_there_is_a_starting_point_not_a_problem() {
        let path = std::env::temp_dir().join("sshctl-test-does-not-exist");
        let _ = std::fs::remove_file(&path);
        let opened = open_at(&path);
        assert!(opened.writable(), "a first run has to be able to write");
        assert!(opened.source.hosts.is_empty());
    }

    fn as_utf16(text: &str, bom: bool) -> Vec<u8> {
        let mut out = if bom { vec![0xff, 0xfe] } else { vec![] };
        out.extend(text.encode_utf16().flat_map(|c| c.to_le_bytes()));
        out
    }

    #[test]
    fn a_utf16_config_with_a_byte_order_mark_blocks_writing() {
        // The worst silence there was: read_to_string fails, sshctl sees an
        // empty config, and writing replaces a file nobody ever saw. A UTF-16
        // config is not exotic — PowerShell's `>` produces one.
        let path = temp(
            "utf16-bom-config",
            &as_utf16("Host alfa\n  HostName alfa.example\n", true),
        );
        let opened = open_at(&path);
        assert!(
            !opened.writable(),
            "sshctl must not overwrite a file it could not read"
        );
        assert!(opened.source.hosts.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_utf16_config_without_a_byte_order_mark_blocks_writing_too() {
        // The nastier half: with ASCII text and no mark, UTF-16 is *valid*
        // UTF-8 — every other byte is a NUL. So reading succeeds, the parser
        // finds nothing, and without this check writing would go ahead.
        let path = temp(
            "utf16-plain-config",
            &as_utf16("Host alfa\n  HostName alfa.example\n", false),
        );
        let opened = open_at(&path);
        assert!(
            !opened.writable(),
            "reading it successfully is not the same as understanding it"
        );
        assert!(opened.source.hosts.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_readable_config_is_simply_read() {
        let path = temp("plain-config", b"Host alfa\n  HostName alfa.example\n");
        let opened = open_at(&path);
        assert!(opened.writable());
        assert_eq!(opened.source.hosts.len(), 1);
        assert_eq!(opened.source.hosts[0].hostname, "alfa.example");
        let _ = std::fs::remove_file(&path);
    }
}
