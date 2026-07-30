//! Checks whether the source still matches reality.
//!
//! Three layers, in increasing cost:
//!   1. the file itself (does the key exist, are the permissions right)
//!   2. the network     (does the name resolve, does the port answer)
//!   3. the real login  (does the host accept this key)
//!
//! Each layer only runs if the previous one succeeded: a ten-second timeout
//! per dead host would otherwise make the whole thing unusably slow.

use crate::model::{Host, Source, ssh_dir};
use std::io::ErrorKind;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    pub fn label(&self) -> &'static str {
        match self {
            Level::Ok => "  OK ",
            Level::Warn => "NOTE ",
            Level::Fail => "FAIL ",
        }
    }
}

#[derive(Debug)]
pub struct Finding {
    pub level: Level,
    pub subject: String,
    pub message: String,
}

impl Finding {
    fn new(level: Level, subject: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            level,
            subject: subject.into(),
            message: message.into(),
        }
    }
}

pub struct Options {
    /// Skip the real login test. Handy when you are offline.
    pub offline: bool,
    pub connect_timeout: Duration,
    /// Limit to a single alias.
    pub only: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            offline: false,
            connect_timeout: Duration::from_secs(5),
            only: None,
        }
    }
}

pub fn run(source: &Source, original: &str, opts: &Options) -> Vec<Finding> {
    let mut findings = Vec::new();
    run_streaming(source, original, opts, &mut |f| findings.push(f));
    findings
}

/// The same checks, but every result is handed over right away. The GUI needs
/// that: one unreachable host costs seconds, and the window must not look
/// frozen for that long.
pub fn run_streaming(
    source: &Source,
    original: &str,
    opts: &Options,
    emit: &mut dyn FnMut(Finding),
) {
    for problem in source.validate() {
        emit(Finding::new(Level::Fail, "config", problem));
    }

    // The round-trip check belongs up front: if rewriting would wreck
    // something, you want to know that before starting on the rest.
    for loss in crate::fidelity::check(original, source) {
        emit(Finding::new(
            Level::Warn,
            "round-trip",
            format!("{} — {}", loss.line, loss.reason.describe()),
        ));
    }

    // Ask once which known_hosts files apply; every hop of a jump chain and
    // the ledger check further down both use this list. Offline nobody does,
    // and finding it costs one `ssh -G` per host.
    let known_files = if opts.offline {
        Vec::new()
    } else {
        crate::known::files_for_all(source)
    };

    for host in &source.hosts {
        if let Some(only) = &opts.only
            && &host.alias != only
        {
            continue;
        }
        for finding in check_host(host, opts, &known_files) {
            emit(finding);
        }
    }

    for host in &source.hosts {
        if let Some(only) = &opts.only
            && &host.alias != only
        {
            continue;
        }
        for finding in check_pitfalls(host) {
            emit(finding);
        }
    }

    for finding in check_orphan_keys(source) {
        emit(finding);
    }
    for finding in check_portability(source) {
        emit(finding);
    }
    if !opts.offline {
        for finding in check_known_hosts(source, opts, &known_files) {
            emit(finding);
        }
    }
    for finding in check_hygiene() {
        emit(finding);
    }
}

fn check_host(host: &Host, opts: &Options, known_files: &[std::path::PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = host.alias.clone();

    // Layer 1: the key as a file.
    match host.key_path() {
        // There is a key, but its path holds tokens only ssh can fill in
        // (`%h` for the host you are connecting to, `%r` for the remote user).
        // Saying "does not exist" here would be a lie.
        None if host.key_has_tokens() => {
            out.push(Finding::new(
                Level::Warn,
                &subject,
                format!(
                    "key path {} contains %-tokens that only ssh fills in — not checked",
                    host.key.as_deref().unwrap_or_default()
                ),
            ));
        }
        None => {
            // This is exactly the trap server.example was caught in: a block
            // without a key falls back on whatever the agent offers, and you
            // get "Permission denied" without knowing which key failed.
            out.push(Finding::new(
                Level::Warn,
                &subject,
                "no IdentityFile — ssh will then try arbitrary agent keys",
            ));
        }
        Some(path) => {
            if !path.exists() {
                out.push(Finding::new(
                    Level::Fail,
                    &subject,
                    format!("key {} does not exist", path.display()),
                ));
            } else {
                if let Some(f) = check_key_permissions(&path, &subject) {
                    out.push(f);
                }
                let pubkey = crate::model::public_half(&path);
                if !pubkey.exists() {
                    out.push(Finding::new(
                        Level::Warn,
                        &subject,
                        format!(
                            "public half {} is missing — needed to authorise the key elsewhere",
                            pubkey.file_name().unwrap_or_default().to_string_lossy()
                        ),
                    ));
                }
                if is_encrypted(&path) {
                    out.push(Finding::new(
                        Level::Warn,
                        &subject,
                        "key is encrypted with a passphrase — automatic login needs the agent",
                    ));
                }
            }
        }
    }

    if opts.offline {
        return out;
    }

    // Layer 1b: the jump chain. Without this the doctor can only say "no
    // answer"; with the chain you know *which* hop gives out — and that is
    // usually the only thing you want to know.
    let chain = host
        .proxy_jump
        .as_deref()
        .map(crate::proxy::parse_chain)
        .unwrap_or_default();
    if !chain.is_empty() {
        for (i, hop) in chain.iter().enumerate() {
            // A hop may be an alias from your own config. Then *those*
            // settings apply, and ssh looks the trust up under the HostName of
            // that block — not under the alias you typed.
            let (lookup_name, port) = resolve_hop(hop);
            match reachable(&lookup_name, port, opts.connect_timeout) {
                Ok(()) => {
                    out.push(Finding::new(
                        Level::Ok,
                        &subject,
                        format!("hop {} of {}: {} answers", i + 1, chain.len(), hop.label()),
                    ));
                    // Every hop is a full-blown ssh connection, so every hop
                    // gets checked separately for its host key. The
                    // intermediate machine does *not* need to know the final
                    // destination: it only forwards TCP with `ssh -W`.
                    if !known_files.is_empty()
                        && crate::known::lookup(&lookup_name, port, known_files).is_empty()
                    {
                        out.push(Finding::new(
                            Level::Warn,
                            &subject,
                            format!(
                                "hop {}: '{lookup_name}' is not in known_hosts — it will ask \
                                 for trust on the first jump",
                                i + 1
                            ),
                        ));
                    }
                }
                Err(reason) => {
                    out.push(Finding::new(
                        Level::Fail,
                        &subject,
                        format!(
                            "unreachable via hop {} of {}: {} — {reason}",
                            i + 1,
                            chain.len(),
                            hop.label()
                        ),
                    ));
                    // Testing any further is pointless: the route is already
                    // broken.
                    return out;
                }
            }
        }
    }

    // If a route runs through a jump host, then the final destination is by
    // definition not directly reachable — that is the very reason to use
    // ProxyJump. The same goes for a ProxyCommand, whatever it runs: testing
    // the port directly reported exactly the hosts that need a detour as
    // broken. Skip layer 2; layer 3 goes via the alias and therefore does
    // follow the route.
    let has_proxy_command = host.options.iter().any(|o| {
        let lower = o.to_ascii_lowercase();
        // `ProxyCommand none` explicitly means: no detour after all.
        lower.starts_with("proxycommand") && lower.split_whitespace().nth(1) != Some("none")
    });
    if !chain.is_empty() || has_proxy_command {
        return layer_three(host, opts, out, true);
    }

    // Layer 2: the network.
    if let Err(reason) = reachable(&host.hostname, host.port_or_default(), opts.connect_timeout) {
        out.push(Finding::new(Level::Fail, &subject, reason));
        return out;
    }

    layer_three(host, opts, out, false)
}

/// Layer 3: does the host really accept this key? `via_route` means there is a
/// jump chain, so we address the host by its alias and let ssh build the whole
/// route itself.
fn layer_three(
    host: &Host,
    opts: &Options,
    mut out: Vec<Finding>,
    via_route: bool,
) -> Vec<Finding> {
    let subject = host.alias.clone();
    let key_usable = host.key_path().map(|p| p.exists()).unwrap_or(false);
    if !key_usable && !via_route {
        return out;
    }
    match try_login(host, opts, via_route) {
        Ok(Login::Accepted) => out.push(Finding::new(Level::Ok, &subject, "login works")),
        Ok(Login::AcceptedNoShell) => out.push(Finding::new(
            Level::Ok,
            &subject,
            "key is accepted (this host gives no shell)",
        )),
        Ok(Login::Denied) => out.push(Finding::new(
            Level::Fail,
            &subject,
            "host answers, but the key is refused",
        )),
        Ok(Login::UnknownHost) => out.push(Finding::new(
            Level::Warn,
            &subject,
            "host key not trusted yet — look at the fingerprint and add it \
             deliberately; this check will not do that for you",
        )),
        Ok(Login::Unclear(said)) => out.push(Finding::new(
            Level::Warn,
            &subject,
            format!("could not tell whether the login works — ssh said: {said}"),
        )),
        Err(e) => out.push(Finding::new(
            Level::Warn,
            &subject,
            format!("could not test the login: {e}"),
        )),
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum Login {
    Accepted,
    /// Authenticated, but the host does not run commands. GitHub does this:
    /// "successfully authenticated, but does not provide shell access". Going
    /// purely by the exit status would label this as failed.
    AcceptedNoShell,
    Denied,
    /// The host key is unknown. Deliberately not an outcome in which we accept
    /// it: a check that signs for trust itself is no longer a check.
    UnknownHost,
    /// ssh failed and the message matches nothing we know. Deliberately not
    /// counted as accepted: "Connection closed by ..." is fail2ban or
    /// MaxStartups, not a working key. Carries what ssh said, so the finding
    /// can show it.
    Unclear(String),
}

/// Tells "key refused" apart from "command failed". That is not nitpicking: on
/// the exit status alone, every host without a shell would be reported broken.
///
/// Matching is on substrings on purpose. ssh's `do_log()` formats every line
/// on stderr with `\r\n`, on every platform including Unix — so anything that
/// compares whole lines or uses `ends_with` breaks on some messages and not
/// others.
pub fn classify_login(success: bool, stderr: &str) -> Login {
    if success {
        return Login::Accepted;
    }
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("host key verification failed")
        || lower.contains("no matching host key")
        || lower.contains("no rsa host key is known")
    {
        return Login::UnknownHost;
    }
    if lower.contains("permission denied")
        || lower.contains("too many authentication failures")
        || lower.contains("no supported authentication methods")
    {
        return Login::Denied;
    }
    // Only an explicit sign of success counts as "authenticated, no shell".
    // The old fallback *assumed* it — and then a usage error, or a
    // "Connection closed by ..." from fail2ban, came out as "key is accepted"
    // without ssh ever having been past the front door.
    if lower.contains("successfully authenticated")
        || lower.contains("does not provide shell access")
        || lower.contains("shell access is disabled")
    {
        return Login::AcceptedNoShell;
    }
    let said = stderr
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or("no output")
        .to_string();
    Login::Unclear(said)
}

/// We test with explicit flags instead of via the alias, so that the outcome
/// says whether the SOURCE is right — even if a sync has not run yet.
fn try_login(host: &Host, opts: &Options, via_route: bool) -> Result<Login, String> {
    // With a route we address the alias, so that ssh builds the whole chain
    // itself; without a route we pass the key explicitly so that the outcome
    // says something about the SOURCE and not about an already synced config.
    if via_route {
        let result = Command::new("ssh")
            .args(["-o", "BatchMode=yes"])
            .args(["-o", "StrictHostKeyChecking=yes"])
            .args([
                "-o",
                &format!("ConnectTimeout={}", opts.connect_timeout.as_secs()),
            ])
            .arg(&host.alias)
            .arg("true")
            .output()
            .map_err(|e| e.to_string())?;
        return Ok(classify_login(
            result.status.success(),
            &String::from_utf8_lossy(&result.stderr),
        ));
    }
    let key = host.key_path().ok_or("no key")?;
    let out = Command::new("ssh")
        .arg("-i")
        .arg(&key)
        .args(["-o", "IdentitiesOnly=yes"])
        .args(["-o", "BatchMode=yes"])
        // Deliberately `yes` and not `accept-new`: otherwise a check would
        // write an unknown host key away and the warning it gave one line
        // earlier would disappear. Granting trust should be a deliberate act,
        // via the screen that shows the fingerprint.
        .args(["-o", "StrictHostKeyChecking=yes"])
        .args([
            "-o",
            &format!("ConnectTimeout={}", opts.connect_timeout.as_secs()),
        ])
        .arg("-p")
        .arg(host.port_or_default().to_string())
        .arg(destination(host))
        .arg("true")
        .output()
        .map_err(|e| e.to_string())?;
    Ok(classify_login(
        out.status.success(),
        &String::from_utf8_lossy(&out.stderr),
    ))
}

/// `user@host`, or just the host when no User is set — ssh then takes the
/// local username, which is exactly what a block without a User means.
/// `@host` with the user simply missing is not the same thing: ssh rejects
/// that before it even connects, and the old fallback in [`classify_login`]
/// then read the usage error as "key is accepted".
fn destination(host: &Host) -> String {
    if host.user.is_empty() {
        host.hostname.clone()
    } else {
        format!("{}@{}", host.user, host.hostname)
    }
}

/// Where does a hop really point, and under which name is the trust looked up?
///
/// We ask ssh itself: a hop may be an alias from your config, and then the
/// HostName, Port and HostKeyAlias of *that* block apply. Naively using the
/// name you typed produces false alarms.
fn resolve_hop(hop: &crate::proxy::Hop) -> (String, u16) {
    let Ok(resolved) = crate::effective::ask_ssh(&hop.host) else {
        return (hop.host.clone(), hop.port.unwrap_or(22));
    };
    let get = |kw: &str| {
        resolved
            .iter()
            .find(|(k, _)| k == kw)
            .map(|(_, v)| v.clone())
    };
    // HostKeyAlias wins: determining the name to look up is exactly its job.
    let name = get("hostkeyalias")
        .filter(|s| !s.is_empty())
        .or_else(|| get("hostname"))
        .unwrap_or_else(|| hop.host.clone());
    let port = hop
        .port
        .or_else(|| get("port").and_then(|p| p.parse().ok()));
    (name, port.unwrap_or(22))
}

/// Resolves a name and checks whether the port answers. Every resolved
/// address gets a turn, the way ssh itself connects: a host that resolves
/// IPv6-first but only answers over IPv4 is reachable, not broken. On failure
/// it returns a sentence saying *what* went wrong, about the last address
/// tried.
fn reachable(hostname: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let addrs: Vec<_> = match (hostname, port).to_socket_addrs() {
        Ok(a) => a.collect(),
        Err(_) => return Err(format!("name '{hostname}' does not resolve")),
    };
    if addrs.is_empty() {
        return Err(format!("name '{hostname}' yields no address"));
    }
    let mut reason = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, timeout) {
            Ok(_) => return Ok(()),
            Err(e) => {
                reason = match e.kind() {
                    ErrorKind::TimedOut => format!("{} port {port} gives no answer", addr.ip()),
                    ErrorKind::ConnectionRefused => format!("{} refuses port {port}", addr.ip()),
                    _ => e.to_string(),
                }
            }
        }
    }
    Err(reason)
}

fn check_key_permissions(path: &Path, subject: &str) -> Option<Finding> {
    // `None` on Windows: there are no Unix modes there to judge.
    let mode = crate::model::mode_of(path)?;
    if mode & 0o077 != 0 {
        return Some(Finding::new(
            Level::Fail,
            subject,
            format!("key has permissions {mode:o} — ssh refuses anything wider than 600"),
        ));
    }
    None
}

/// An encrypted key holds no plain-text "openssh-key-v1" after the header;
/// cheaper is to check whether the file names a cipher.
fn is_encrypted(path: &Path) -> bool {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return false;
    };
    if raw.contains("ENCRYPTED") {
        return true; // classic PEM keys
    }
    // In the OpenSSH format the cipher name sits inside the base64 blob; the
    // cheap test is whether ssh-keygen reads the key with an empty passphrase.
    !Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(path)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(true)
}

/// Keys in ~/.ssh that no host mentions.
/// Keys that no host in THIS config points at.
///
/// Deliberately worded with care: sshctl only knows `~/.ssh/config`. A key can
/// perfectly well be in use by something that is not in there — Xcode, an
/// Apple service, a script, another machine. Claiming "unused" would therefore
/// be a statement this tool cannot make.
fn check_orphan_keys(source: &Source) -> Vec<Finding> {
    crate::keys::inventory(source)
        .into_iter()
        .filter(|k| k.is_orphan())
        .map(|k| {
            Finding::new(
                Level::Warn,
                "orphan",
                format!(
                    "key '{}' is not used by any host in this config \
                     (it may well be in use elsewhere)",
                    k.name
                ),
            )
        })
        .collect()
}

/// Lays the ledger next to your config. `config` says where you want to go,
/// `known_hosts` says which machines you have ever recognised — and those two
/// drift apart without anything saying so.
fn check_known_hosts(
    source: &Source,
    opts: &Options,
    files: &[std::path::PathBuf],
) -> Vec<Finding> {
    let mut out = Vec::new();

    // The files come from the caller, who asked ssh — never guess a path
    // yourself: next to known_hosts there is often a known_hosts.old with
    // revoked keys. And asking costs one `ssh -G` per host, so it happens
    // once per run, not once per check.
    if files.is_empty() {
        return out;
    }
    let ledger = crate::known::Ledger::load(files);

    // 1. Hosts you have never recognised.
    let mut claimed: Vec<String> = Vec::new();
    for host in &source.hosts {
        if let Some(only) = &opts.only
            && &host.alias != only
        {
            continue;
        }
        let hits = crate::known::lookup(&host.hostname, host.port_or_default(), files);
        if hits.is_empty() {
            out.push(Finding::new(
                Level::Warn,
                &host.alias,
                format!(
                    "'{}' is not in known_hosts — the first connection will ask for trust",
                    host.hostname
                ),
            ));
        }
        claimed.extend(hits);
    }

    // 2. Entries that no host points at any more.
    if opts.only.is_none() {
        // An entry with the same fingerprint as a known host is not an unknown
        // machine but the same machine under a different name. That belongs
        // under point 3, not here.
        let known_fingerprints: Vec<&str> = ledger
            .entries
            .iter()
            .filter(|e| claimed.contains(&e.raw_names))
            .map(|e| e.fingerprint.as_str())
            .collect();

        // Judge per NAME, not per key: one machine usually has an RSA, an
        // ECDSA *and* an Ed25519 key, and it is enough for one of them to
        // belong to a known host for the name to be accounted for.
        let mut names: Vec<String> = Vec::new();
        for entry in &ledger.entries {
            let name = entry.label();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        for name in names {
            let lines: Vec<&crate::known::Entry> = ledger
                .entries
                .iter()
                .filter(|e| e.label() == name)
                .collect();
            let accounted_for = lines.iter().any(|e| {
                claimed.contains(&e.raw_names)
                    || known_fingerprints.contains(&e.fingerprint.as_str())
            });
            if accounted_for {
                continue;
            }
            let description = if lines.iter().all(|e| e.hashed) {
                "a hashed entry belongs to no host in your config".to_string()
            } else {
                format!("'{name}' is in known_hosts but with no host in your config")
            };
            out.push(Finding::new(Level::Warn, "ledger", description));
        }

        // 3. The same machine under several names.
        for (_, names) in ledger.duplicates() {
            out.push(Finding::new(
                Level::Warn,
                "ledger",
                format!(
                    "the same machine is in there under several names: {}",
                    names.join(" and ")
                ),
            ));
        }
    }

    out
}

/// Options that quietly wreck something. Four cases that often go wrong and
/// that you never see as long as you only look at "does it work".
fn check_pitfalls(host: &Host) -> Vec<Finding> {
    let mut out = Vec::new();
    let subject = host.alias.clone();

    for option in &host.options {
        let lower = option.to_ascii_lowercase();
        let value = lower.split_whitespace().nth(1).unwrap_or("");

        // 1. Turning off the whole known_hosts protection.
        if lower.starts_with("stricthostkeychecking ") && matches!(value, "no" | "off") {
            out.push(Finding::new(
                Level::Fail,
                &subject,
                "StrictHostKeyChecking is off — this drops your only protection \
                 against a machine passing itself off as this one",
            ));
        }

        // 2. Lending your agent to the other side.
        if lower.starts_with("forwardagent ") && value == "yes" {
            out.push(Finding::new(
                Level::Warn,
                &subject,
                "ForwardAgent is on — for as long as you are connected that machine can \
                 use your agent to pass itself off as you elsewhere; ProxyJump is usually \
                 the better choice",
            ));
        }

        // 3. One connection file for all hosts.
        if lower.starts_with("controlpath ") {
            let path = option.split_whitespace().nth(1).unwrap_or("");
            let has_token = ["%h", "%r", "%p", "%C", "%n"]
                .iter()
                .any(|t| path.contains(t));
            if !has_token {
                out.push(Finding::new(
                    Level::Fail,
                    &subject,
                    format!(
                        "ControlPath '{path}' contains no %h/%r/%p — several hosts will then \
                         share the same file and therefore the same connection"
                    ),
                ));
            }
        }

        // 4. Algorithms this ssh does not know.
        for (keyword, query) in [
            ("ciphers ", "cipher"),
            ("macs ", "mac"),
            ("kexalgorithms ", "kex"),
            ("hostkeyalgorithms ", "key-sig"),
            ("pubkeyacceptedalgorithms ", "key-sig"),
        ] {
            if !lower.starts_with(keyword) {
                continue;
            }
            let list = option.split_whitespace().nth(1).unwrap_or("");
            let known = ssh_knows(query);
            if known.is_empty() {
                // `ssh -Q key-sig` only arrived in OpenSSH 8.2. On an older
                // ssh this check simply did nothing, and silently — which is
                // exactly what this tool is against.
                out.push(Finding::new(
                    Level::Warn,
                    &subject,
                    format!(
                        "this ssh cannot list '{query}' names (needs OpenSSH 8.2 or newer), \
                         so the names in {} have not been checked",
                        option.split_whitespace().next().unwrap_or("")
                    ),
                ));
                continue;
            }
            for name in list.split(',') {
                // +name / -name / ^name add to or remove from the default.
                let bare = name.trim_start_matches(['+', '-', '^']);
                if bare.is_empty() || bare == "any" {
                    continue;
                }
                if !known.iter().any(|b| b == bare) {
                    out.push(Finding::new(
                        Level::Warn,
                        &subject,
                        format!(
                            "'{bare}' is listed in {} but this ssh does not know it — the line \
                             then does nothing",
                            option.split_whitespace().next().unwrap_or("")
                        ),
                    ));
                }
            }
        }
    }
    out
}

/// Settings that work here but not everywhere.
///
/// Once for the whole file, not once per host: this says something about the
/// file, and repeating it four times makes it noise instead of information.
fn check_portability(source: &Source) -> Vec<Finding> {
    let uses_keychain = source.defaults.use_keychain
        || source.hosts.iter().any(|h| {
            h.options
                .iter()
                .any(|o| o.to_ascii_lowercase().starts_with("usekeychain "))
        });
    if !uses_keychain {
        return Vec::new();
    }
    // The whole file is rejected, not just the line: OpenSSH checks keywords
    // before it decides which block applies, so an unknown keyword anywhere
    // stops the parse. `IgnoreUnknown` has to stand outside any block to help;
    // inside one it comes too late.
    vec![Finding::new(
        Level::Warn,
        "portability",
        "UseKeychain only exists in Apple's ssh — on Linux or Windows this whole config \
         is refused, not just that line; 'IgnoreUnknown UseKeychain' as the very first \
         line of the file fixes that",
    )]
}

/// Which values does this ssh know? Out of `ssh -Q`, so the list never goes
/// stale.
fn ssh_knows(kind: &str) -> Vec<String> {
    Command::new("ssh")
        .arg("-Q")
        .arg(kind)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Clutter that piles up in ~/.ssh.
fn check_hygiene() -> Vec<Finding> {
    let dir = ssh_dir();
    let mut out = Vec::new();

    if let Some(mode) = crate::model::mode_of(&dir)
        && mode & 0o077 != 0
    {
        out.push(Finding::new(
            Level::Warn,
            "hygiene",
            format!("~/.ssh has permissions {mode:o}; 700 is the convention"),
        ));
    }

    for (name, explanation) in [
        ("known_hosts.old", "leftover from an earlier migration"),
        (".DS_Store", "Finder clutter"),
    ] {
        if dir.join(name).exists() {
            out.push(Finding::new(
                Level::Warn,
                "hygiene",
                format!("{name} is in ~/.ssh — {explanation}"),
            ));
        }
    }

    // Orphaned agent sockets: the directory is managed by the system, but
    // sockets from finished sessions stay behind.
    if let Ok(entries) = std::fs::read_dir(dir.join("agent")) {
        let count = entries.flatten().count();
        if count > 1 {
            out.push(Finding::new(
                Level::Warn,
                "hygiene",
                format!("~/.ssh/agent holds {count} sockets; old sessions do not always clean up"),
            ));
        }
    }
    out
}

pub fn worst(findings: &[Finding]) -> Level {
    findings.iter().map(|f| f.level).max().unwrap_or(Level::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_loss_is_reported_before_the_rest() {
        // A loss has to come first, because it decides whether you can save
        // safely at all. `Port twentytwo` is not something sshctl can hold on
        // to, so the line drops out of the rewrite.
        let original = "Host a\n  HostName a.nl\n  Port twentytwo\n";
        let source = crate::parser::parse(original);
        let f = run(
            &source,
            original,
            &Options {
                offline: true,
                ..Default::default()
            },
        );
        let first_round_trip = f.iter().position(|x| x.subject == "round-trip");
        let first_host = f.iter().position(|x| x.subject == "a");
        assert!(first_round_trip.is_some(), "round-trip loss not reported");
        assert!(first_round_trip < first_host, "round-trip belongs up front");
    }

    #[test]
    fn a_carriage_return_at_the_end_changes_nothing() {
        // ssh puts \r\n on stderr on every platform, Unix included.
        assert_eq!(
            classify_login(false, "Permission denied (publickey).\r\n"),
            Login::Denied
        );
        assert_eq!(
            classify_login(false, "Host key verification failed.\r\n"),
            Login::UnknownHost
        );
    }

    #[test]
    fn usekeychain_is_reported_once_and_not_per_host() {
        let source = crate::parser::parse(
            "Host a\n  HostName a.nl\n  UseKeychain yes\n\
             Host b\n  HostName b.nl\n  UseKeychain yes\n",
        );
        let findings = check_portability(&source);
        assert_eq!(findings.len(), 1, "got {findings:?}");
        assert!(findings[0].message.contains("IgnoreUnknown"));
    }

    #[test]
    fn a_config_without_usekeychain_says_nothing_about_portability() {
        let source = crate::parser::parse("Host a\n  HostName a.nl\n");
        assert!(check_portability(&source).is_empty());
    }

    #[test]
    fn a_tidy_config_produces_no_round_trip_report() {
        let original = "Host a\n  HostName a.nl\n  User root\n";
        let source = crate::parser::parse(original);
        let f = run(
            &source,
            original,
            &Options {
                offline: true,
                ..Default::default()
            },
        );
        assert!(!f.iter().any(|x| x.subject == "round-trip"), "got {f:?}");
    }

    #[test]
    fn the_worst_level_wins() {
        let f = vec![
            Finding::new(Level::Ok, "a", ""),
            Finding::new(Level::Fail, "b", ""),
            Finding::new(Level::Warn, "c", ""),
        ];
        assert_eq!(worst(&f), Level::Fail);
    }

    #[test]
    fn an_empty_list_is_ok() {
        assert_eq!(worst(&[]), Level::Ok);
    }

    #[test]
    fn a_successful_command_is_simply_accepted() {
        assert_eq!(classify_login(true, ""), Login::Accepted);
    }

    #[test]
    fn github_without_a_shell_counts_as_accepted() {
        // Exactly what GitHub sends back; the exit status here is 1.
        let stderr = "Hi RyGe87! You've successfully authenticated, \
                      but GitHub does not provide shell access.";
        assert_eq!(classify_login(false, stderr), Login::AcceptedNoShell);
    }

    #[test]
    fn a_refused_key_is_a_real_failure() {
        let stderr = "root@192.0.2.10: Permission denied (publickey,password).";
        assert_eq!(classify_login(false, stderr), Login::Denied);
    }

    #[test]
    fn an_unrecognised_error_is_not_reported_as_accepted() {
        // fail2ban and MaxStartups close the connection before authentication;
        // the old fallback read that as "key is accepted".
        match classify_login(false, "Connection closed by 192.0.2.10 port 22\r\n") {
            Login::Unclear(said) => assert!(said.contains("Connection closed"), "got {said}"),
            other => panic!("must be unclear, got {other:?}"),
        }
    }

    #[test]
    fn a_usage_error_is_not_reported_as_accepted() {
        // `ssh @host` (empty user) fails before connecting, with a usage
        // message that matches no known pattern.
        assert!(matches!(
            classify_login(false, "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] ..."),
            Login::Unclear(_)
        ));
    }

    #[test]
    fn a_host_without_a_user_is_addressed_without_an_at_sign() {
        // `@host` is not "empty user" to ssh but a usage error — and that
        // error then came out of the classifier as "key is accepted".
        use crate::model::Host;
        let mut h = Host {
            hostname: "alfa.example".into(),
            ..Default::default()
        };
        assert_eq!(destination(&h), "alfa.example");
        h.user = "root".into();
        assert_eq!(destination(&h), "root@alfa.example");
    }

    #[test]
    fn too_many_attempts_also_counts_as_refused() {
        assert_eq!(
            classify_login(
                false,
                "Received disconnect: Too many authentication failures"
            ),
            Login::Denied
        );
    }
}
