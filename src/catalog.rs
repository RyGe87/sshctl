//! Which options can you set, and what are they for?
//!
//! Not all hundred and three: this is the selection you could reasonably want
//! to find without opening the manual. Everything else you can still put in
//! the file by hand — those get kept unchanged.
//!
//! You search here by intent, not by name: "I want reopening to be faster"
//! leads to ControlMaster.

pub struct OptionSpec {
    pub keyword: &'static str,
    pub group: &'static str,
    pub explanation: &'static str,
    /// Fixed choices, if there are any. Empty = free text.
    pub choices: &'static [&'static str],
}

pub const GROUPS: [&str; 6] = [
    "Connection",
    "Authentication",
    "Trust",
    "Forwarding",
    "Reuse",
    "Session",
];

pub fn all() -> &'static [OptionSpec] {
    &[
        // --- Connection ---
        OptionSpec {
            keyword: "ProxyJump",
            group: "Connection",
            choices: &[],
            explanation: "Jump via another machine. May be an alias from this file.",
        },
        OptionSpec {
            keyword: "ProxyCommand",
            group: "Connection",
            choices: &[],
            explanation: "A freer form of jumping: you supply the command.",
        },
        OptionSpec {
            keyword: "ConnectTimeout",
            group: "Connection",
            choices: &[],
            explanation: "Seconds to wait for a connection before it gives up.",
        },
        OptionSpec {
            keyword: "ConnectionAttempts",
            group: "Connection",
            choices: &[],
            explanation: "How often to retry before it gives up.",
        },
        OptionSpec {
            keyword: "AddressFamily",
            group: "Connection",
            choices: &["any", "inet", "inet6"],
            explanation: "IPv4, IPv6, or both.",
        },
        OptionSpec {
            keyword: "ServerAliveInterval",
            group: "Connection",
            choices: &[],
            explanation: "Seconds between signs of life; keeps a quiet connection open.",
        },
        OptionSpec {
            keyword: "ServerAliveCountMax",
            group: "Connection",
            choices: &[],
            explanation: "How many signs of life may go unanswered.",
        },
        OptionSpec {
            keyword: "TCPKeepAlive",
            group: "Connection",
            choices: &["yes", "no"],
            explanation: "Let the operating system watch over the connection.",
        },
        OptionSpec {
            keyword: "Compression",
            group: "Connection",
            choices: &["yes", "no"],
            explanation: "Compress; only worth it on a slow line.",
        },
        // --- Authentication ---
        OptionSpec {
            keyword: "IdentityAgent",
            group: "Authentication",
            choices: &[],
            explanation: "Which agent gets used. 'none' switches the agent off.",
        },
        OptionSpec {
            keyword: "CertificateFile",
            group: "Authentication",
            choices: &[],
            explanation: "Your key as signed by an authority.",
        },
        OptionSpec {
            keyword: "PreferredAuthentications",
            group: "Authentication",
            choices: &[],
            explanation: "In which order the methods get tried.",
        },
        OptionSpec {
            keyword: "PubkeyAuthentication",
            group: "Authentication",
            choices: &["yes", "no"],
            explanation: "Log in with keys.",
        },
        OptionSpec {
            keyword: "PasswordAuthentication",
            group: "Authentication",
            choices: &["yes", "no"],
            explanation: "Log in with a password.",
        },
        OptionSpec {
            keyword: "NumberOfPasswordPrompts",
            group: "Authentication",
            choices: &[],
            explanation: "How often it asks for a password.",
        },
        OptionSpec {
            keyword: "PKCS11Provider",
            group: "Authentication",
            choices: &[],
            explanation: "Library for a smartcard or token.",
        },
        // --- Trust ---
        OptionSpec {
            keyword: "StrictHostKeyChecking",
            group: "Trust",
            choices: &["yes", "accept-new", "ask", "no", "off"],
            explanation: "What happens on an unknown or changed host key.",
        },
        OptionSpec {
            keyword: "HostKeyAlias",
            group: "Trust",
            choices: &[],
            explanation: "The name the trust is looked up under, separate from the address.",
        },
        OptionSpec {
            keyword: "UserKnownHostsFile",
            group: "Trust",
            choices: &[],
            explanation: "Which file keeps track of the trust.",
        },
        OptionSpec {
            keyword: "CheckHostIP",
            group: "Trust",
            choices: &["yes", "no"],
            explanation: "Track by IP address as well as by name.",
        },
        OptionSpec {
            keyword: "UpdateHostKeys",
            group: "Trust",
            choices: &["yes", "no", "ask"],
            explanation: "May the server quietly add keys of its own.",
        },
        OptionSpec {
            keyword: "RevokedHostKeys",
            group: "Trust",
            choices: &[],
            explanation: "File with keys that must never be accepted.",
        },
        OptionSpec {
            keyword: "VerifyHostKeyDNS",
            group: "Trust",
            choices: &["yes", "no", "ask"],
            explanation: "Trust via SSHFP records in DNS.",
        },
        // --- Forwarding ---
        OptionSpec {
            keyword: "LocalForward",
            group: "Forwarding",
            choices: &[],
            explanation: "Forward a port here to the other side: 8080 localhost:80",
        },
        OptionSpec {
            keyword: "RemoteForward",
            group: "Forwarding",
            choices: &[],
            explanation: "Forward a port over there back to here.",
        },
        OptionSpec {
            keyword: "DynamicForward",
            group: "Forwarding",
            choices: &[],
            explanation: "Creates a SOCKS proxy on the given port.",
        },
        OptionSpec {
            keyword: "ForwardAgent",
            group: "Forwarding",
            choices: &["yes", "no"],
            explanation: "Lend your agent to the other side. Be careful with this one.",
        },
        OptionSpec {
            keyword: "ForwardX11",
            group: "Forwarding",
            choices: &["yes", "no"],
            explanation: "Graphical programs from over there on your own screen.",
        },
        OptionSpec {
            keyword: "ExitOnForwardFailure",
            group: "Forwarding",
            choices: &["yes", "no"],
            explanation: "Stop the connection if forwarding fails.",
        },
        // --- Reuse ---
        OptionSpec {
            keyword: "ControlMaster",
            group: "Reuse",
            choices: &["no", "yes", "ask", "auto", "autoask"],
            explanation: "Reuse one connection for several sessions; reopening becomes instant.",
        },
        OptionSpec {
            keyword: "ControlPath",
            group: "Reuse",
            choices: &[],
            explanation: "Where that connection file lives. Use %r@%h:%p, or hosts will share one.",
        },
        OptionSpec {
            keyword: "ControlPersist",
            group: "Reuse",
            choices: &[],
            explanation: "How long the connection stays open after your last session.",
        },
        // --- Session ---
        OptionSpec {
            keyword: "RequestTTY",
            group: "Session",
            choices: &["no", "yes", "force", "auto"],
            explanation: "Whether a terminal gets requested.",
        },
        OptionSpec {
            keyword: "RemoteCommand",
            group: "Session",
            choices: &[],
            explanation: "Command that runs immediately after logging in.",
        },
        OptionSpec {
            keyword: "SessionType",
            group: "Session",
            choices: &["none", "subsystem", "default"],
            explanation: "Kind of session; 'none' is handy for forwarding only.",
        },
        OptionSpec {
            keyword: "SetEnv",
            group: "Session",
            choices: &[],
            explanation: "Set an environment variable over there: NAME=value",
        },
        OptionSpec {
            keyword: "LogLevel",
            group: "Session",
            choices: &["QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG"],
            explanation: "How much ssh itself tells you.",
        },
        OptionSpec {
            keyword: "BatchMode",
            group: "Session",
            choices: &["yes", "no"],
            explanation: "Never ask anything; needed for scripts.",
        },
    ]
}

/// Searches on the keyword or on words in the explanation, so you can search
/// by intent instead of by name.
pub fn search(term: &str) -> Vec<&'static OptionSpec> {
    let t = term.trim().to_ascii_lowercase();
    all()
        .iter()
        .filter(|o| {
            t.is_empty()
                || o.keyword.to_ascii_lowercase().contains(&t)
                || o.explanation.to_ascii_lowercase().contains(&t)
        })
        .collect()
}

/// Keywords ssh gathers instead of overwriting.
///
/// Checked against `ssh -G`, because the rule is not obvious from the outside:
/// two `LocalForward` lines give two forwards, two `SetEnv` lines give one.
/// It matters here because the option picker used to remove the existing line
/// with the same keyword before adding the new one — which silently threw away
/// a port forward or a second key.
const REPEATABLE: [&str; 6] = [
    "identityfile",
    "certificatefile",
    "localforward",
    "remoteforward",
    "dynamicforward",
    "sendenv",
];

/// May this keyword appear more than once in a block?
pub fn is_repeatable(keyword: &str) -> bool {
    REPEATABLE.contains(&keyword.trim().to_ascii_lowercase().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_accumulating_keywords_are_recognised() {
        // Two LocalForwards give two forwards; two SetEnvs give one. Both
        // verified against `ssh -G`.
        assert!(is_repeatable("LocalForward"));
        assert!(is_repeatable("identityfile"));
        assert!(!is_repeatable("SetEnv"));
        assert!(!is_repeatable("Ciphers"));
    }

    #[test]
    fn every_option_belongs_to_a_known_group() {
        for o in all() {
            assert!(GROUPS.contains(&o.group), "unknown group on {}", o.keyword);
        }
    }

    #[test]
    fn no_duplicate_keywords() {
        let mut seen: Vec<&str> = Vec::new();
        for o in all() {
            assert!(
                !seen.contains(&o.keyword),
                "{} is in there twice",
                o.keyword
            );
            seen.push(o.keyword);
        }
    }

    #[test]
    fn searching_by_intent_works() {
        // You do not know it is called ControlMaster, but you know what you
        // want.
        let r = search("instant");
        assert!(
            r.iter().any(|o| o.keyword == "ControlMaster"),
            "got {:?}",
            r.iter().map(|o| o.keyword).collect::<Vec<_>>()
        );
        let r = search("agent off");
        assert!(r.iter().any(|o| o.keyword == "IdentityAgent"));
    }

    #[test]
    fn an_empty_search_term_returns_everything() {
        assert_eq!(search("").len(), all().len());
    }
}
