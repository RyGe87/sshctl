//! The model back into ssh_config text.
//!
//! This file belongs to the user, not to sshctl. So there is no "generated, do
//! not touch" header on top of it: you may keep editing it by hand, and next
//! time we simply read it in again.
//!
//! The output is deterministic: no timestamps, fixed order. That makes "read
//! it in and write it back yields the same thing" a usable check (see
//! [`crate::fidelity`]) instead of noise in a diff.

use crate::model::{Host, Source};

/// The heading above the shared `Host *` block. The parser has to recognise
/// this exact text again, otherwise sshctl rejects its own output — so it lives
/// here once instead of twice.
pub const SHARED_HEADING: &str = "applies to everything";

pub fn render(source: &Source) -> String {
    let mut out = String::new();
    let mut current_group: Option<&str> = None;
    let mut first = true;

    // Whatever stood before the first block goes back at the front. An
    // `Include` up there pulls its file in before everything else, and moving
    // it would change which value wins.
    for line in trimmed(&source.leading) {
        out.push_str(line);
        out.push('\n');
        first = false;
    }

    for host in &source.hosts {
        let group = host.group.as_deref();
        if group != current_group {
            if let Some(name) = group {
                if !first {
                    out.push('\n');
                }
                out.push_str(&format!("# ---------- {name} ----------\n\n"));
            } else if !first {
                out.push('\n');
            }
            current_group = group;
        } else if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(&render_host(host));
    }

    let defaults = render_defaults(source);
    if !defaults.is_empty() {
        if !first {
            out.push('\n');
        }
        out.push_str(&defaults);
    }
    out
}

fn render_host(host: &Host) -> String {
    let mut block = String::new();
    if let Some(comment) = &host.comment {
        block.push_str(&format!("# {comment}\n"));
    }

    let mut names = vec![host.alias.clone()];
    names.extend(host.aliases.iter().cloned());
    // A name with a space goes back inside quotes, or one pattern would
    // come out as two.
    let names: Vec<String> = names
        .iter()
        .map(|n| {
            if n.contains(char::is_whitespace) {
                format!("\"{n}\"")
            } else {
                n.clone()
            }
        })
        .collect();
    block.push_str(&format!("Host {}\n", names.join(" ")));
    // Alleen uitschrijven als het er stond. Zie Host::hostname_explicit.
    if host.hostname_explicit {
        block.push_str(&format!("  HostName {}\n", host.hostname));
    }
    if !host.user.is_empty() {
        block.push_str(&format!("  User {}\n", host.user));
    }
    if let Some(port) = host.port {
        block.push_str(&format!("  Port {port}\n"));
    }
    if let Some(key) = host.key_for_config() {
        block.push_str(&format!("  IdentityFile {key}\n"));
    }
    if let Some(via) = &host.proxy_jump {
        block.push_str(&format!("  ProxyJump {via}\n"));
    }
    for option in &host.options {
        block.push_str(&format!("  {option}\n"));
    }
    // Anything sshctl does not model follows the block unchanged, in the order
    // it was read. A `Match` section belongs where it stood: it applies to
    // everything after it, so moving it would change its reach.
    let trailing = trimmed(&host.trailing);
    if !trailing.is_empty() {
        block.push('\n');
    }
    for line in trailing {
        block.push_str(line);
        block.push('\n');
    }
    block
}

/// The same lines without the blank ones at either end. Blank lines in the
/// middle stay: those are the author's own layout.
fn trimmed(lines: &[String]) -> &[String] {
    let start = lines
        .iter()
        .position(|l| !l.trim().is_empty())
        .unwrap_or(lines.len());
    let end = lines
        .iter()
        .rposition(|l| !l.trim().is_empty())
        .map(|i| i + 1)
        .unwrap_or(start);
    &lines[start..end]
}

/// The `Host *` block goes at the bottom. That is not taste: ssh applies
/// "first value wins", so specific blocks have to come first or the defaults
/// will overwrite them.
fn render_defaults(source: &Source) -> String {
    let d = &source.defaults;
    let mut lines = String::new();
    if d.add_keys_to_agent {
        lines.push_str("  AddKeysToAgent yes\n");
    }
    if d.use_keychain {
        lines.push_str("  UseKeychain yes\n");
    }
    if d.identities_only {
        lines.push_str("  IdentitiesOnly yes\n");
    }
    if d.server_alive_interval > 0 {
        lines.push_str(&format!(
            "  ServerAliveInterval {}\n",
            d.server_alive_interval
        ));
    }
    // An empty `Host *` is not a neutral line but noise suggesting that
    // something has been configured.
    if lines.is_empty() {
        return String::new();
    }
    format!("# ---------- {SHARED_HEADING} ----------\n\nHost *\n{lines}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Defaults, Host};

    fn host(alias: &str, group: Option<&str>) -> Host {
        Host {
            alias: alias.to_string(),
            hostname: format!("{alias}.example"),
            user: "admin".to_string(),
            key: Some(format!("id_ed25519_{alias}")),
            group: group.map(String::from),
            ..Default::default()
        }
    }

    fn source() -> Source {
        Source {
            defaults: Defaults {
                identities_only: true,
                ..Default::default()
            },
            hosts: vec![host("unraid", Some("home")), host("server", Some("home"))],
            unsupported: vec![],
            leading: vec![],
        }
    }

    #[test]
    fn the_output_is_deterministic() {
        assert_eq!(render(&source()), render(&source()));
    }

    #[test]
    fn no_marker_any_more_because_the_file_belongs_to_the_user() {
        let out = render(&source());
        assert!(!out.contains("sshctl:managed"));
        assert!(!out.to_lowercase().contains("generated"));
    }

    #[test]
    fn defaults_go_last_because_the_first_value_wins() {
        let out = render(&source());
        let star = out.find("Host *").expect("Host * is missing");
        let last_host = out.rfind("Host server").expect("host is missing");
        assert!(star > last_host);
    }

    #[test]
    fn the_key_path_is_written_out_with_a_tilde() {
        assert!(render(&source()).contains("IdentityFile ~/.ssh/id_ed25519_unraid"));
    }

    #[test]
    fn a_group_heading_appears_once_for_two_hosts_in_the_same_group() {
        let out = render(&source());
        assert_eq!(out.matches("---------- home ----------").count(), 1);
    }

    #[test]
    fn an_empty_star_block_is_left_out() {
        let mut s = source();
        s.defaults = Defaults::default();
        let out = render(&s);
        assert!(
            !out.contains("Host *"),
            "an empty Host * block is noise:\n{out}"
        );
    }

    #[test]
    fn a_host_without_a_user_gets_no_empty_user_line() {
        let s = Source {
            hosts: vec![Host {
                alias: "x".into(),
                hostname: "x.nl".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(!render(&s).contains("User \n"));
    }

    #[test]
    fn a_duplicate_alias_is_reported() {
        let mut s = source();
        s.hosts.push(host("unraid", None));
        assert!(s.validate().iter().any(|p| p.contains("unraid")));
    }

    #[test]
    fn an_alias_with_a_space_is_written_back_in_quotes() {
        // `Host "my server"` is one pattern to ssh; without the quotes the
        // written file would suddenly hold two.
        let mut s = source();
        s.hosts[0].alias = "my server".into();
        assert!(render(&s).contains("Host \"my server\""), "{}", render(&s));
    }
}
