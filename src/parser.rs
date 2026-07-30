//! Reading ~/.ssh/config into a model.
//!
//! Deliberately a simple parser: it understands the handful of keywords that
//! sshctl models and keeps the rest unchanged as a raw option. What it really
//! cannot handle (`Match`, `Include`) ends up in `unsupported`, so the
//! round-trip check can complain about it instead of losing it silently.
//!
//! **A setting stays where it stands.** This parser used to lift
//! `IdentitiesOnly` and relatives out of individual hosts into a shared
//! `Host *`. That looked tidier but changed the meaning: a host without an
//! `IdentityFile` that inherits `IdentitiesOnly yes` then offers no key at
//! all. Only a genuine `Host *` block fills in the defaults now.

use crate::generate;
use crate::model::{Host, Source};

/// Constructs that change the structure of the file and therefore must not be
/// stuffed into a Host block as an ordinary option.
const STRUCTURAL: [&str; 2] = ["match", "include"];

/// Keywords whose value is the whole rest of the line, `#` and all. Verified
/// against `ssh -G`: `ProxyCommand ssh -W %h:%p jump # via the hop` really does
/// keep that comment as part of the command. Cutting it off here would change
/// what gets executed.
const REST_OF_LINE: [&str; 4] = [
    "proxycommand",
    "localcommand",
    "remotecommand",
    "knownhostscommand",
];

pub fn parse(text: &str) -> Source {
    let mut source = Source::default();
    let mut current: Option<Host> = None;
    // `Host *` on its own is the defaults section, and then the settings go
    // somewhere else entirely. Kept as a flag rather than read back off
    // `alias == "*"`, because `Host * !prod` also starts with a `*` and is a
    // perfectly ordinary block.
    let mut in_defaults = false;
    // Inside a `Match` section every line goes through verbatim: what it means
    // depends on where it stands, so sshctl must not try to model it.
    let mut in_verbatim = false;

    // A comment sitting right above a Host line belongs to that block.
    let mut pending_comment: Option<String> = None;
    // The last group heading read applies to every host that follows.
    let mut current_group: Option<String> = None;

    for raw in text.lines() {
        let line = raw.trim();

        if in_verbatim {
            // A new Host block ends the verbatim section; a new Match keeps it
            // going.
            let starts_host = line
                .split_whitespace()
                .next()
                .map(|w| w.eq_ignore_ascii_case("host"))
                .unwrap_or(false);
            if !starts_host {
                keep_verbatim(&mut source, &mut current, raw);
                continue;
            }
            in_verbatim = false;
        }

        if line.is_empty() {
            pending_comment = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix('#') {
            let rest = rest.trim();
            // A group heading that the generator wrote itself. Without reading
            // it back, sshctl rejected its own output: the blank line below it
            // turned it into a loose comment, and then `write` refused.
            if let Some(name) = group_heading(rest) {
                current_group = Some(name);
                pending_comment = None;
                continue;
            }
            pending_comment = Some(rest.to_string());
            continue;
        }

        let Some((keyword, raw_value)) = split(line) else {
            continue;
        };
        let lower = keyword.to_ascii_lowercase();
        let value = &clean_value(&lower, raw_value);
        if value.is_empty() {
            // Everything after the keyword turned out to be a comment. ssh
            // rejects that, so we must not quietly make something of it.
            source.unsupported.push(line.to_string());
            continue;
        }
        let value = value.as_str();

        if STRUCTURAL.contains(&lower.as_str()) {
            // Deliberately not stored as an option in the previous block: that
            // would change the meaning. It goes back exactly where it stood.
            source.unsupported.push(line.to_string());
            keep_verbatim(&mut source, &mut current, raw);
            // `Match` opens a section of its own; everything up to the next
            // `Host` belongs to it.
            in_verbatim = lower == "match";
            in_defaults = false;
            pending_comment = None;
            continue;
        }

        if lower == "host" {
            if let Some(done) = current.take() {
                push(&mut source, done);
            }
            in_verbatim = false;
            let names: Vec<&str> = value.split_whitespace().collect();

            // `Host *` and nothing else is the defaults section. `Host * !prod`
            // is not: ssh applies that to everything except prod, and treating
            // it as the defaults would widen it back to prod as well.
            in_defaults = names == ["*"];
            if in_defaults {
                pending_comment = None;
                continue;
            }

            current = Some(Host {
                alias: names[0].to_string(),
                aliases: names[1..].iter().map(|s| s.to_string()).collect(),
                comment: pending_comment.take(),
                group: current_group.clone(),
                ..Default::default()
            });
            continue;
        }

        if in_defaults {
            match lower.as_str() {
                "addkeystoagent" => source.defaults.add_keys_to_agent = is_yes(value),
                "usekeychain" => source.defaults.use_keychain = is_yes(value),
                "identitiesonly" => source.defaults.identities_only = is_yes(value),
                "serveraliveinterval" => {
                    source.defaults.server_alive_interval = value.parse().unwrap_or(0)
                }
                _ => source.unsupported.push(format!("Host *: {line}")),
            }
            continue;
        }

        let Some(host) = current.as_mut() else {
            // In ssh a setting outside any block applies to everything that
            // follows. We do not model that, so it goes through unchanged.
            source.unsupported.push(line.to_string());
            keep_verbatim(&mut source, &mut current, raw);
            continue;
        };

        match lower.as_str() {
            "hostname" => {
                host.hostname = value.to_string();
                host.hostname_explicit = true;
            }
            "user" => host.user = value.to_string(),
            // ssh tries every IdentityFile in turn, so a second one is not a
            // correction but an addition. The model holds one; the rest stay
            // on as raw options, in order, so nothing is lost.
            "identityfile" if host.key.is_none() => host.key = Some(shorten(value)),
            "port" => match value.parse() {
                Ok(p) => host.port = Some(p),
                // Not silently to 22: that would send you somewhere else.
                Err(_) => source.unsupported.push(line.to_string()),
            },
            "proxyjump" => host.proxy_jump = Some(value.to_string()),
            _ => host.options.push(format!("{keyword} {value}")),
        }
    }

    if let Some(done) = current.take() {
        push(&mut source, done);
    }

    source
}

/// Recognises `# ---------- name ----------` and gives back the name.
/// Has to mirror exactly what `generate::render` writes.
fn group_heading(rest: &str) -> Option<String> {
    let bare = rest.trim();
    if !bare.starts_with("----------") || !bare.ends_with("----------") {
        return None;
    }
    let name = bare.trim_matches('-').trim();
    // The section with shared settings is not a group but a fixed heading.
    if name.is_empty() || name == generate::SHARED_HEADING {
        return None;
    }
    Some(name.to_string())
}

/// Keeps a raw line exactly where it stood: after the block being read, or
/// before the first block if there is none yet.
fn keep_verbatim(source: &mut Source, current: &mut Option<Host>, raw: &str) {
    let line = raw.trim_end().to_string();
    match current {
        Some(host) => host.trailing.push(line),
        None => match source.hosts.last_mut() {
            Some(host) => host.trailing.push(line),
            None => source.leading.push(line),
        },
    }
}

fn push(source: &mut Source, mut host: Host) {
    // In ssh a block without a HostName means: use the name you typed. We fill
    // it in so readers have a usable value, but `hostname_explicit` stays false
    // so the generator does not write it out.
    if host.hostname.is_empty() {
        host.hostname = host.alias.clone();
    }
    source.hosts.push(host);
}

/// "  IdentityFile ~/.ssh/x" -> ("IdentityFile", "~/.ssh/x").
/// ssh accepts both spaces and '=' as the separator.
fn split(line: &str) -> Option<(&str, &str)> {
    let line = line.trim();
    if let Some((k, v)) = line.split_once('=') {
        // Only if the '=' comes before the first space, otherwise it is part
        // of the value (e.g. "SetEnv FOO=bar").
        if !k.trim().contains(char::is_whitespace) {
            return Some((k.trim(), v.trim()));
        }
    }
    let mut parts = line.splitn(2, char::is_whitespace);
    let keyword = parts.next()?.trim();
    let value = parts.next()?.trim();
    if keyword.is_empty() || value.is_empty() {
        return None;
    }
    Some((keyword, value))
}

/// Cuts a trailing comment off a value and takes the quotes off.
///
/// Both behaviours are copied from ssh, not invented: `Port 2222 # the odd
/// port` really is port 2222, and `IdentityFile "~/.ssh/my key"` really is a
/// path with a space in it. sshctl used to lose the port entirely on the first
/// and mangle the path on the second.
fn clean_value(lower_keyword: &str, value: &str) -> String {
    let cut = if REST_OF_LINE.contains(&lower_keyword) {
        value
    } else {
        strip_comment(value)
    };
    unquote(cut.trim()).to_string()
}

/// A `#` only starts a comment when whitespace comes before it. `User foo#bar`
/// and `IdentityFile ~/.ssh/x#y` keep their `#` — checked against `ssh -G`.
fn strip_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'#' && i > 0 && (bytes[i - 1] as char).is_whitespace() {
            return &value[..i];
        }
    }
    value
}

/// Takes off a matching pair of surrounding double quotes. ssh uses them to
/// hold a value together that contains spaces.
fn unquote(value: &str) -> &str {
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

/// Key paths inside ~/.ssh are kept as a bare filename; that keeps the model
/// readable and portable.
///
/// A path with a `%` in it stays exactly as it is: those are ssh's own tokens
/// (`%d` for your home directory, `%u` for your username) and rewriting them is
/// the one thing you must not do.
fn shorten(value: &str) -> String {
    if value.contains('%') {
        return value.to_string();
    }
    value
        .strip_prefix("~/.ssh/")
        .map(String::from)
        .unwrap_or_else(|| value.to_string())
}

fn is_yes(value: &str) -> bool {
    value.eq_ignore_ascii_case("yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Host server.example
  HostName server.example
  User admin

Host nas.example
  HostName nas.example
  User root
  HostKeyAlgorithms +ssh-rsa
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519_github
  IdentitiesOnly yes
  AddKeysToAgent yes
Host laptop laptop.example
  HostName laptop.example
  User laptop
";

    #[test]
    fn reads_every_block() {
        let s = parse(SAMPLE);
        assert_eq!(s.hosts.len(), 4);
        assert_eq!(s.hosts[0].alias, "server.example");
        assert_eq!(s.hosts[2].user, "git");
    }

    #[test]
    fn extra_names_become_aliases() {
        let s = parse(SAMPLE);
        let laptop = s.hosts.iter().find(|h| h.alias == "laptop").unwrap();
        assert_eq!(laptop.aliases, vec!["laptop.example"]);
    }

    #[test]
    fn unknown_options_are_kept() {
        let s = parse(SAMPLE);
        let nas = s.hosts.iter().find(|h| h.alias == "nas.example").unwrap();
        assert_eq!(nas.options, vec!["HostKeyAlgorithms +ssh-rsa"]);
    }

    #[test]
    fn the_key_path_is_shortened() {
        let s = parse(SAMPLE);
        let gh = s.hosts.iter().find(|h| h.alias == "github.com").unwrap();
        assert_eq!(gh.key.as_deref(), Some("id_ed25519_github"));
    }

    #[test]
    fn per_host_settings_stay_with_their_own_host() {
        // Lifting them into `Host *` would force them onto *every* host. For a
        // host without an IdentityFile, `IdentitiesOnly yes` means no key gets
        // offered at all — that breaks the connection.
        let s = parse(SAMPLE);
        assert!(!s.defaults.identities_only, "must not be lifted up");
        assert!(!s.defaults.add_keys_to_agent);

        let gh = s.hosts.iter().find(|h| h.alias == "github.com").unwrap();
        assert!(gh.options.iter().any(|o| o == "IdentitiesOnly yes"));
        assert!(gh.options.iter().any(|o| o == "AddKeysToAgent yes"));

        let server = s
            .hosts
            .iter()
            .find(|h| h.alias == "server.example")
            .unwrap();
        assert!(
            server.options.is_empty(),
            "this host had nothing and must not be handed anything"
        );
    }

    #[test]
    fn with_a_real_star_block_only_that_block_counts() {
        let s = parse(
            "Host a\n  HostName a.nl\n  IdentitiesOnly yes\nHost *\n  ServerAliveInterval 30\n",
        );
        assert!(!s.defaults.identities_only);
        assert_eq!(s.defaults.server_alive_interval, 30);
    }

    #[test]
    fn a_star_block_yields_no_pseudo_host() {
        let s = parse(
            "Host a\n  HostName a.nl\nHost *\n  IdentitiesOnly yes\nHost b\n  HostName b.nl\n",
        );
        let names: Vec<&str> = s.hosts.iter().map(|h| h.alias.as_str()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn a_block_without_hostname_falls_back_to_the_alias() {
        let s = parse("Host bare\n  User someone\n");
        assert_eq!(s.hosts[0].hostname, "bare");
    }

    #[test]
    fn the_equals_sign_notation_is_fine_too() {
        let s = parse("Host x\n  HostName=1.2.3.4\n  User=root\n");
        assert_eq!(s.hosts[0].hostname, "1.2.3.4");
        assert_eq!(s.hosts[0].user, "root");
    }

    #[test]
    fn an_equals_sign_inside_a_value_breaks_nothing() {
        let s = parse("Host x\n  HostName y\n  SetEnv FOO=bar\n");
        assert_eq!(s.hosts[0].options, vec!["SetEnv FOO=bar"]);
    }

    #[test]
    fn a_group_header_is_read_back_and_applies_to_what_follows() {
        // Without this, sshctl rejected its own output.
        let s = parse(
            "# ---------- home ----------\n\nHost a\n  HostName a.nl\n\n\
             Host b\n  HostName b.nl\n",
        );
        assert_eq!(s.hosts[0].group.as_deref(), Some("home"));
        assert_eq!(s.hosts[1].group.as_deref(), Some("home"));
    }

    #[test]
    fn the_fixed_header_of_the_shared_section_is_not_a_group() {
        let s = parse(
            "# ---------- applies to everything ----------\n\nHost *\n  IdentitiesOnly yes\n",
        );
        assert!(s.hosts.is_empty());
        assert!(s.defaults.identities_only);
    }

    #[test]
    fn an_ordinary_row_of_dashes_is_not_a_group_header() {
        let s = parse("# ----------\nHost a\n  HostName a.nl\n");
        assert_eq!(s.hosts[0].group, None);
    }

    #[test]
    fn a_comment_above_a_block_belongs_to_that_block() {
        let s = parse("# the media server\nHost unraid\n  HostName 192.0.2.10\n");
        assert_eq!(s.hosts[0].comment.as_deref(), Some("the media server"));
    }

    #[test]
    fn a_standalone_comment_does_not_stick_to_the_next_block() {
        // A blank line in between means the comment stands on its own.
        let s = parse("# passing thought\n\nHost unraid\n  HostName 192.0.2.10\n");
        assert_eq!(s.hosts[0].comment, None);
    }

    #[test]
    fn a_match_block_is_not_stuffed_into_a_host() {
        // Match opens a new section; storing it as an option in the previous
        // block would silently change the meaning. It is kept verbatim
        // instead, in the place where it stood.
        let s = parse("Host a\n  HostName a.nl\nMatch host b\n  User someoneelse\n");
        assert_eq!(s.hosts.len(), 1);
        assert!(s.hosts[0].options.is_empty());
        assert!(s.unsupported.iter().any(|l| l.starts_with("Match")));
        assert_eq!(
            s.hosts[0].trailing,
            vec!["Match host b", "  User someoneelse"]
        );
    }

    #[test]
    fn everything_in_a_match_section_stays_together() {
        // Not just the Match line: a keyword sshctl does model, such as User,
        // must not be pulled back into the host above it.
        let s = parse(
            "Host a\n  HostName a.nl\nMatch host b\n  User x\n  Port 22\nHost c\n  HostName c.nl\n",
        );
        assert_eq!(s.hosts.len(), 2);
        assert!(s.hosts[0].trailing.iter().any(|l| l.contains("Port 22")));
        assert_eq!(s.hosts[1].alias, "c");
        assert!(s.hosts[1].trailing.is_empty());
    }

    #[test]
    fn an_include_before_the_first_block_stays_at_the_front() {
        // Position matters: an Include pulls its file in where it stands, and
        // the first value wins.
        let s = parse("Include ~/.ssh/extra\nHost a\n  HostName a.nl\n");
        assert_eq!(s.leading, vec!["Include ~/.ssh/extra"]);
        let rendered = crate::generate::render(&s);
        assert!(
            rendered.starts_with("Include ~/.ssh/extra"),
            "got:\n{rendered}"
        );
    }

    // The five cases below were all checked against `ssh -G` first: what ssh
    // itself makes of the line is the yardstick, not what looks reasonable.

    #[test]
    fn a_trailing_comment_does_not_swallow_the_port() {
        // `ssh -G` says port 2222. sshctl parsed "2222 # the odd port", failed,
        // and silently fell back to 22 — so you connected somewhere else.
        let s = parse("Host a\n  HostName a.example\n  Port 2222 # the odd port\n");
        assert_eq!(s.hosts[0].port, Some(2222));
    }

    #[test]
    fn a_hash_without_a_space_before_it_belongs_to_the_value() {
        // Also straight from `ssh -G`: user stays foo#bar.
        let s = parse("Host a\n  HostName a.example\n  User foo#bar\n");
        assert_eq!(s.hosts[0].user, "foo#bar");
    }

    #[test]
    fn a_command_keeps_its_whole_line_including_the_hash() {
        // ProxyCommand takes the rest of the line verbatim — cutting a comment
        // off it would change what gets executed.
        let s = parse("Host a\n  HostName a.example\n  ProxyCommand ssh -W %h:%p jump # via\n");
        assert_eq!(
            s.hosts[0].options,
            vec!["ProxyCommand ssh -W %h:%p jump # via"]
        );
    }

    #[test]
    fn quotes_come_off_and_go_back_on() {
        let s = parse("Host a\n  HostName a.example\n  IdentityFile \"~/.ssh/my key\"\n");
        assert_eq!(s.hosts[0].key.as_deref(), Some("my key"));
        assert_eq!(
            s.hosts[0].key_for_config().as_deref(),
            Some("\"~/.ssh/my key\"")
        );
    }

    #[test]
    fn a_key_path_with_tokens_is_left_exactly_as_it_is() {
        // %d is ssh's own token for your home directory. Rewriting it to
        // ~/.ssh/%d/.ssh/... would break the path outright.
        let s = parse("Host a\n  HostName a.example\n  IdentityFile %d/.ssh/id_ed25519\n");
        assert_eq!(s.hosts[0].key.as_deref(), Some("%d/.ssh/id_ed25519"));
        assert_eq!(
            s.hosts[0].key_for_config().as_deref(),
            Some("%d/.ssh/id_ed25519")
        );
    }

    #[test]
    fn a_second_identityfile_is_an_addition_not_a_correction() {
        // ssh tries both, in order. Keeping only the last one threw a key away.
        let s = parse(
            "Host a\n  HostName a.example\n  IdentityFile ~/.ssh/one\n  IdentityFile ~/.ssh/two\n",
        );
        assert_eq!(s.hosts[0].key.as_deref(), Some("one"));
        assert!(
            s.hosts[0]
                .options
                .iter()
                .any(|o| o == "IdentityFile ~/.ssh/two"),
            "the second key must survive, got {:?}",
            s.hosts[0].options
        );
    }

    #[test]
    fn host_star_with_an_exclusion_is_an_ordinary_block() {
        // `Host * !prod` applies to everything except prod. Reading it as the
        // defaults section did two things wrong at once: the block disappeared,
        // and its settings were handed to prod after all.
        let s =
            parse("Host * !prod\n  ServerAliveInterval 30\nHost prod\n  HostName prod.example\n");
        assert_eq!(
            s.defaults.server_alive_interval, 0,
            "must not become a shared default"
        );
        let block = s.hosts.iter().find(|h| h.alias == "*").expect("block gone");
        assert_eq!(block.aliases, vec!["!prod"]);
        assert_eq!(block.options, vec!["ServerAliveInterval 30"]);
    }

    #[test]
    fn a_pattern_block_survives_the_round_trip_unchanged() {
        let text = "Host * !prod\n  ServerAliveInterval 30\n";
        let rendered = crate::generate::render(&parse(text));
        assert!(rendered.contains("Host * !prod"), "got:\n{rendered}");
    }

    #[test]
    fn an_unreadable_port_is_kept_instead_of_thrown_away() {
        let s = parse("Host a\n  HostName a.example\n  Port twentytwo\n");
        assert_eq!(s.hosts[0].port, None);
        assert!(s.unsupported.iter().any(|l| l.contains("twentytwo")));
    }

    #[test]
    fn include_is_kept_aside() {
        let s = parse("Include ~/.ssh/extra\nHost a\n  HostName a.nl\n");
        assert!(s.unsupported.iter().any(|l| l.starts_with("Include")));
        assert_eq!(s.hosts.len(), 1);
    }
}
