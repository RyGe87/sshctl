//! What actually applies when you type `ssh <host>` — and where does it come
//! from?
//!
//! The file proposes, `ssh -G` decides. OpenSSH works out the complete
//! configuration itself, after all `Host` patterns, `Match` blocks, `Include`
//! files and built-in defaults. We do not want to reimplement that: one subtle
//! difference and the display would lie about what really happens.
//!
//! What sshctl *does* add is **provenance**. `ssh -G` only says *that*
//! `identitiesonly yes` applies, not that it comes out of your own `Host *`.
//! That question — why is this happening? — is exactly the one a text file
//! leaves you stuck on, so we answer it by laying our own parse next to it.

use crate::model::{Source, ssh_config_path};
use crate::pattern::host_line_matches;
use std::process::Command;

/// Where an applicable value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// From a `Host` block in the user's own file. Carries the name of that
    /// block, which need not be the host you asked about: `Host web*` applies
    /// to web1 as well.
    ThisBlock(String),
    /// From the `Host *` block in your own file.
    UserDefaults,
    /// From a file outside the user's own, e.g. /etc/ssh/ssh_config.
    Elsewhere(String),
    /// ssh's built-in default.
    SshDefault,
}

impl Origin {
    pub fn describe(&self) -> String {
        match self {
            Origin::ThisBlock(alias) => format!("the block 'Host {alias}' in your config"),
            Origin::UserDefaults => "Host * in your config".to_string(),
            Origin::Elsewhere(path) => path.clone(),
            Origin::SshDefault => "ssh's own default".to_string(),
        }
    }

    /// Does this value come from somewhere the user never looks? That is the
    /// kind of setting that applies without anyone knowing why.
    pub fn is_invisible(&self) -> bool {
        matches!(self, Origin::Elsewhere(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    /// Lowercased, the way `ssh -G` hands it back.
    pub keyword: String,
    pub value: String,
    pub origin: Origin,
}

#[derive(Debug, Clone, Default)]
pub struct Effective {
    pub settings: Vec<Setting>,
    /// The blocks that apply to this host, in order.
    pub matching_blocks: Vec<Block>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// The patterns on the `Host` line.
    pub patterns: Vec<String>,
    pub source_file: String,
    /// Whether this is the `Host *` safety net.
    pub is_wildcard: bool,
}

impl Effective {
    pub fn get(&self, keyword: &str) -> Option<&Setting> {
        self.settings.iter().find(|s| s.keyword == keyword)
    }

    /// Everything coming from a file the user does not have in front of them.
    pub fn invisible(&self) -> Vec<&Setting> {
        self.settings
            .iter()
            .filter(|s| s.origin.is_invisible())
            .collect()
    }
}

/// Asks ssh itself for the computed configuration for this host.
pub fn ask_ssh(alias: &str) -> Result<Vec<(String, String)>, String> {
    let out = Command::new("ssh")
        .arg("-G")
        .arg(alias)
        .output()
        .map_err(|e| format!("could not start ssh: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(parse_g(&String::from_utf8_lossy(&out.stdout)))
}

/// `ssh -G` gives "keyword value" per line, everything lowercased. Some
/// keywords appear more than once (identityfile); we keep all of them, in
/// order.
pub fn parse_g(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            match line.split_once(char::is_whitespace) {
                Some((k, v)) => Some((k.to_ascii_lowercase(), v.trim().to_string())),
                // Keywords without a value exist too.
                None => Some((line.to_ascii_lowercase(), String::new())),
            }
        })
        .collect()
}

/// Lays the outcome of `ssh -G` next to our own parse to determine where each
/// value comes from.
///
/// `system` is the parse of /etc/ssh/ssh_config, or empty if there is none.
/// Whatever we cannot place anywhere but that *does* differ from nothing, we
/// honestly call "from elsewhere" instead of inventing a block for it.
pub fn attribute(
    alias: &str,
    resolved: &[(String, String)],
    user: &Source,
    system: Option<(&str, &Source)>,
) -> Effective {
    let mut settings = Vec::new();

    for (keyword, value) in resolved {
        // 'host' is the question itself, not a setting.
        if keyword == "host" {
            continue;
        }
        let origin = attribute_one(alias, keyword, value, user, system);
        settings.push(Setting {
            keyword: keyword.clone(),
            value: value.clone(),
            origin,
        });
    }

    Effective {
        settings,
        matching_blocks: matching_blocks(alias, user, system),
    }
}

fn attribute_one(
    alias: &str,
    keyword: &str,
    value: &str,
    user: &Source,
    system: Option<(&str, &Source)>,
) -> Origin {
    // 1. Does one of the blocks that apply to this host set it?
    //
    // Every one of them, in order, and not just the first. `Host web1` followed
    // by `Host web*` both apply to web1, and a User from the second block used
    // to come out as "ssh's own default" — which sends you looking in entirely
    // the wrong place.
    for host in user
        .hosts
        .iter()
        .filter(|h| host_line_matches(&all_patterns(h), alias))
    {
        if sets_keyword(&host_directives(host), keyword, value) {
            return Origin::ThisBlock(host.alias.clone());
        }
    }

    // 2. Does it come from your own Host *?
    if sets_keyword(&defaults_directives(user), keyword, value) {
        return Origin::UserDefaults;
    }

    // 3. From the system file?
    if let Some((path, sys)) = system {
        let mut directives = defaults_directives(sys);
        for host in &sys.hosts {
            if host_line_matches(&all_patterns(host), alias) {
                directives.extend(host_directives(host));
            }
        }
        if sets_keyword(&directives, keyword, value) {
            return Origin::Elsewhere(path.to_string());
        }
    }

    Origin::SshDefault
}

/// All the names a block matches on.
fn all_patterns(host: &crate::model::Host) -> Vec<String> {
    let mut v = vec![host.alias.clone()];
    v.extend(host.aliases.iter().cloned());
    v
}

/// The lines a host block sets, in "keyword value" form.
fn host_directives(host: &crate::model::Host) -> Vec<String> {
    let mut out = Vec::new();
    if !host.hostname.is_empty() {
        out.push(format!("hostname {}", host.hostname));
    }
    if !host.user.is_empty() {
        out.push(format!("user {}", host.user));
    }
    if let Some(port) = host.port {
        out.push(format!("port {port}"));
    }
    if let Some(key) = host.key_for_config() {
        out.push(format!("identityfile {key}"));
    }
    for option in &host.options {
        out.push(option.to_ascii_lowercase());
    }
    out
}

/// The lines the `Host *` block sets. Including whatever the parser does not
/// model: that lands in `unsupported` with a "Host *: " prefix, and it is
/// precisely there that you find the kind of setting that silently applies
/// everywhere.
fn defaults_directives(source: &Source) -> Vec<String> {
    let d = &source.defaults;
    let mut out: Vec<String> = source
        .unsupported
        .iter()
        .filter_map(|u| u.strip_prefix("Host *: "))
        .map(|u| u.to_ascii_lowercase())
        .collect();
    if d.add_keys_to_agent {
        out.push("addkeystoagent yes".to_string());
    }
    if d.use_keychain {
        out.push("usekeychain yes".to_string());
    }
    if d.identities_only {
        out.push("identitiesonly yes".to_string());
    }
    if d.server_alive_interval > 0 {
        out.push(format!("serveraliveinterval {}", d.server_alive_interval));
    }
    out
}

/// Does one of these lines set this keyword to this value? The comparison is
/// loose: `ssh -G` normalises paths and writes everything in lowercase.
fn sets_keyword(directives: &[String], keyword: &str, value: &str) -> bool {
    directives.iter().any(|d| {
        let d = d.to_ascii_lowercase();
        let Some((k, v)) = d.split_once(char::is_whitespace) else {
            return false;
        };
        if k != keyword {
            return false;
        }
        let v = v.trim();
        let value = value.to_ascii_lowercase();
        if v == value {
            return true;
        }
        // Some keywords take several values on one line but get written out
        // one by one by `ssh -G`: `SendEnv LANG LC_*` becomes two lines.
        // Without this only the last one made it home.
        if v.split_whitespace().any(|part| part == value) {
            return true;
        }
        // ssh -G sometimes fills in ~, so paths also match on their tail end.
        // Only paths: `Port 22` in a block must not claim a resolved
        // `port 2222` just because one number is a suffix of the other.
        let path_like = v.contains('/') || value.contains('/');
        path_like && (value.ends_with(v.trim_start_matches("~/")) || v.ends_with(&value))
    })
}

/// The blocks that apply to this host, in the order ssh reads them: your own
/// file first, then the system file.
fn matching_blocks(alias: &str, user: &Source, system: Option<(&str, &Source)>) -> Vec<Block> {
    let path = ssh_config_path().display().to_string();
    let mut out = Vec::new();

    for host in &user.hosts {
        if host_line_matches(&all_patterns(host), alias) {
            out.push(Block {
                patterns: all_patterns(host),
                source_file: path.clone(),
                is_wildcard: false,
            });
        }
    }
    if !defaults_directives(user).is_empty() {
        out.push(Block {
            patterns: vec!["*".to_string()],
            source_file: path,
            is_wildcard: true,
        });
    }
    if let Some((path, sys)) = system {
        for host in &sys.hosts {
            if host_line_matches(&all_patterns(host), alias) {
                out.push(Block {
                    patterns: all_patterns(host),
                    source_file: path.to_string(),
                    is_wildcard: false,
                });
            }
        }
        if !defaults_directives(sys).is_empty() {
            out.push(Block {
                patterns: vec!["*".to_string()],
                source_file: path.to_string(),
                is_wildcard: true,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;

    const G_OUTPUT: &str = "\
host unraid
user root
hostname 192.0.2.10
port 22
identityfile ~/.ssh/id_ed25519_unraid_new
identitiesonly yes
addkeystoagent yes
sendenv LANG LC_*
compression no
";

    fn user_config() -> Source {
        parser::parse(
            "Host unraid\n  HostName 192.0.2.10\n  User root\n\
             \x20 IdentityFile ~/.ssh/id_ed25519_unraid_new\n\
             Host *\n  IdentitiesOnly yes\n  AddKeysToAgent yes\n",
        )
    }

    fn system_config() -> Source {
        parser::parse("Host *\n    SendEnv LANG LC_*\n")
    }

    #[test]
    fn reads_the_output_of_ssh_g() {
        let pairs = parse_g(G_OUTPUT);
        assert_eq!(pairs[0], ("host".into(), "unraid".into()));
        assert!(pairs.contains(&("hostname".into(), "192.0.2.10".into())));
        // Values with spaces stay intact.
        assert!(pairs.contains(&("sendenv".into(), "LANG LC_*".into())));
    }

    #[test]
    fn a_value_from_the_hosts_own_block() {
        let e = attribute("unraid", &parse_g(G_OUTPUT), &user_config(), None);
        assert_eq!(
            e.get("hostname").unwrap().origin,
            Origin::ThisBlock("unraid".into())
        );
    }

    #[test]
    fn a_value_from_your_own_star_block() {
        let e = attribute("unraid", &parse_g(G_OUTPUT), &user_config(), None);
        assert_eq!(
            e.get("identitiesonly").unwrap().origin,
            Origin::UserDefaults
        );
    }

    #[test]
    fn an_untouched_value_is_an_ssh_default() {
        let e = attribute("unraid", &parse_g(G_OUTPUT), &user_config(), None);
        assert_eq!(e.get("compression").unwrap().origin, Origin::SshDefault);
    }

    #[test]
    fn a_port_nobody_sets_is_a_default_and_not_a_mystery() {
        // A heuristic that was too coarse used to label this "from elsewhere",
        // producing a warning about something entirely ordinary.
        let sys = system_config();
        let e = attribute(
            "unraid",
            &parse_g(G_OUTPUT),
            &user_config(),
            Some(("/etc/ssh/ssh_config", &sys)),
        );
        assert_eq!(e.get("port").unwrap().origin, Origin::SshDefault);
    }

    #[test]
    fn a_value_from_the_system_file_is_reported_as_invisible() {
        // The real case on this machine: SendEnv sits in /etc/ssh/ssh_config
        // and nowhere in the user's own file.
        let sys = system_config();
        let e = attribute(
            "unraid",
            &parse_g(G_OUTPUT),
            &user_config(),
            Some(("/etc/ssh/ssh_config", &sys)),
        );
        let s = e.get("sendenv").unwrap();
        assert_eq!(s.origin, Origin::Elsewhere("/etc/ssh/ssh_config".into()));
        assert!(s.origin.is_invisible());
        assert_eq!(e.invisible().len(), 1, "got {:?}", e.invisible());
    }

    #[test]
    fn a_multi_value_line_gets_attributed_per_value() {
        // `SendEnv LANG LC_*` sits on one line but comes back out as two.
        let sys = system_config();
        let e = attribute(
            "unraid",
            &parse_g("host unraid\nsendenv LANG\nsendenv LC_*\n"),
            &user_config(),
            Some(("/etc/ssh/ssh_config", &sys)),
        );
        assert_eq!(e.invisible().len(), 2, "got {:?}", e.invisible());
    }

    #[test]
    fn the_host_line_itself_is_not_a_setting() {
        let e = attribute("unraid", &parse_g(G_OUTPUT), &user_config(), None);
        assert!(e.get("host").is_none());
    }

    #[test]
    fn applicable_blocks_are_listed_in_reading_order() {
        let sys = system_config();
        let e = attribute(
            "unraid",
            &parse_g(G_OUTPUT),
            &user_config(),
            Some(("/etc/ssh/ssh_config", &sys)),
        );
        assert_eq!(e.matching_blocks.len(), 3);
        assert_eq!(e.matching_blocks[0].patterns, vec!["unraid"]);
        assert!(e.matching_blocks[1].is_wildcard);
        assert!(e.matching_blocks[2].source_file.starts_with("/etc/ssh"));
    }

    #[test]
    fn a_value_from_a_second_matching_block_is_placed_correctly() {
        // `Host web1` and `Host web*` both apply to web1. Only looking at the
        // first one made the User come out as "ssh's own default", which sends
        // you looking in entirely the wrong place.
        let src = parser::parse("Host web1\n  HostName web1.example\nHost web*\n  User deploy\n");
        let g = parse_g("host web1\nhostname web1.example\nuser deploy\n");
        let e = attribute("web1", &g, &src, None);
        assert_eq!(
            e.get("user").unwrap().origin,
            Origin::ThisBlock("web*".into()),
            "settings: {:?}",
            e.settings
        );
        assert_eq!(
            e.get("hostname").unwrap().origin,
            Origin::ThisBlock("web1".into())
        );
    }

    #[test]
    fn a_numeric_value_is_not_claimed_by_its_suffix() {
        // Something we do not model (a Match block, say) set port 2222; the
        // host's own block says 22. Suffix matching blamed the block for a
        // value it never set — while the block literally says otherwise.
        let src = parser::parse("Host b\n  HostName b.example\n  Port 22\n");
        let g = parse_g("host b\nhostname b.example\nport 2222\n");
        let e = attribute("b", &g, &src, None);
        assert_eq!(e.get("port").unwrap().origin, Origin::SshDefault);
    }

    #[test]
    fn a_pattern_block_counts_too() {
        let src = parser::parse("Host *.example\n  User admin\n");
        let g = parse_g("host nas.example\nuser admin\n");
        let e = attribute("nas.example", &g, &src, None);
        assert_eq!(
            e.get("user").unwrap().origin,
            Origin::ThisBlock("*.example".into())
        );
    }
}
