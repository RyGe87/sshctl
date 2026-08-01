//! sshctl — show, check and update your SSH configuration, tidied up.
//!
//! `~/.ssh/config` is the single source of truth. There is no second file, and
//! therefore no question about which of the two is right.

use sshctl::doctor::{self, Level};
use sshctl::model::{self, Host, ssh_config_path};
use sshctl::{effective, fidelity, generate, proof};
use std::process::ExitCode;
use std::time::Duration;

// The grammar is six commands and a handful of flags; parsing it by hand
// keeps the whole CLI free of dependencies — see `print_diff` for the same
// trade made small.

const HELP: &str = "\
Shows, checks and writes ~/.ssh/config

Usage: sshctl <COMMAND>

Commands:
  list     Short table of your hosts
  show     Shows your configuration tidied up, the way `write` would save it
  write    Writes the tidied-up version back to ~/.ssh/config
  doctor   Checks the configuration and actual reachability
  explain  Shows what really applies to a host, and where it comes from
  add      Adds a host and writes it out right away

Options:
  -h, --help     Print help
  -V, --version  Print version

`sshctl <command> --help` lists the flags of one command.
";

const HELP_WRITE: &str = "\
Writes the tidied-up version back to ~/.ssh/config

Usage: sshctl write [OPTIONS]

Options:
      --dry-run  Show the difference without writing anything
      --force    Write even when the proof reports a change, or could not run
  -h, --help     Print help
";

const HELP_DOCTOR: &str = "\
Checks the configuration and actual reachability

Usage: sshctl doctor [OPTIONS] [ALIAS]

Arguments:
  [ALIAS]  Limit to a single alias

Options:
      --offline            Skip the network and login tests
      --timeout <SECONDS>  Seconds per connection attempt [default: 5]
  -h, --help               Print help
";

const HELP_EXPLAIN: &str = "\
Shows what really applies to a host, and where it comes from

Usage: sshctl explain [OPTIONS] <ALIAS>

Options:
      --all   Also show the values that are simply ssh's own defaults
  -h, --help  Print help
";

const HELP_ADD: &str = "\
Adds a host and writes it out right away

Usage: sshctl add --hostname <HOSTNAME> --user <USER> [OPTIONS] <ALIAS>

Options:
      --hostname <HOSTNAME>  The real address or IP
      --user <USER>          The login name on that machine
      --generate-key         Create a new ed25519 key without a passphrase
      --group <GROUP>        Free-form group name, for readability
      --comment <COMMENT>    Comment placed right above the block
  -h, --help                 Print help
";

fn wants_help(rest: &[String]) -> bool {
    rest.iter().any(|a| a == "-h" || a == "--help")
}

fn unexpected(what: &str) -> String {
    format!("unexpected argument '{what}'\ntry 'sshctl --help'")
}

/// Splits `--flag=value` into the flag and its glued-on value.
fn split_flag(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((flag, value)) if flag.starts_with("--") => (flag, Some(value)),
        _ => (arg, None),
    }
}

/// The value of a flag: either glued on with `=` or the next argument.
fn flag_value<'a>(
    flag: &str,
    inline: Option<&'a str>,
    it: &mut std::slice::Iter<'a, String>,
) -> Result<&'a str, String> {
    match inline {
        Some(value) => Ok(value),
        None => it
            .next()
            .map(String::as_str)
            .ok_or_else(|| format!("{flag} needs a value\ntry 'sshctl --help'")),
    }
}

/// `list` and `show` take nothing; saying so beats silently ignoring input.
fn no_arguments(name: &str, about: &str, rest: &[String]) -> Result<Option<()>, String> {
    if wants_help(rest) {
        print!("{about}\n\nUsage: sshctl {name}\n");
        return Ok(None);
    }
    match rest.first() {
        None => Ok(Some(())),
        Some(arg) => Err(unexpected(arg)),
    }
}

fn parse_write(rest: &[String]) -> Result<Option<(bool, bool)>, String> {
    if wants_help(rest) {
        print!("{HELP_WRITE}");
        return Ok(None);
    }
    let (mut dry_run, mut force) = (false, false);
    for arg in rest {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--force" => force = true,
            other => return Err(unexpected(other)),
        }
    }
    Ok(Some((dry_run, force)))
}

type DoctorArgs = (Option<String>, bool, u64);

fn parse_doctor(rest: &[String]) -> Result<Option<DoctorArgs>, String> {
    if wants_help(rest) {
        print!("{HELP_DOCTOR}");
        return Ok(None);
    }
    let (mut alias, mut offline, mut timeout) = (None, false, 5u64);
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let (flag, inline) = split_flag(arg);
        match (flag, inline) {
            ("--offline", None) => offline = true,
            ("--timeout", _) => {
                let value = flag_value("--timeout", inline, &mut it)?;
                timeout = value
                    .parse()
                    .map_err(|_| format!("--timeout wants a number of seconds, not '{value}'"))?;
            }
            _ if !arg.starts_with('-') && alias.is_none() => alias = Some(arg.clone()),
            _ => return Err(unexpected(arg)),
        }
    }
    Ok(Some((alias, offline, timeout)))
}

fn parse_explain(rest: &[String]) -> Result<Option<(String, bool)>, String> {
    if wants_help(rest) {
        print!("{HELP_EXPLAIN}");
        return Ok(None);
    }
    let (mut alias, mut all) = (None, false);
    for arg in rest {
        match arg.as_str() {
            "--all" => all = true,
            other if !other.starts_with('-') && alias.is_none() => alias = Some(other.to_string()),
            other => return Err(unexpected(other)),
        }
    }
    let alias = alias.ok_or("explain needs an alias\ntry 'sshctl explain --help'")?;
    Ok(Some((alias, all)))
}

type AddArgs = (String, String, String, bool, Option<String>, Option<String>);

fn parse_add(rest: &[String]) -> Result<Option<AddArgs>, String> {
    if wants_help(rest) {
        print!("{HELP_ADD}");
        return Ok(None);
    }
    let (mut alias, mut hostname, mut user) = (None, None, None);
    let (mut generate_key, mut group, mut comment) = (false, None, None);
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let (flag, inline) = split_flag(arg);
        match (flag, inline) {
            ("--hostname", _) => {
                hostname = Some(flag_value("--hostname", inline, &mut it)?.to_string())
            }
            ("--user", _) => user = Some(flag_value("--user", inline, &mut it)?.to_string()),
            ("--generate-key", None) => generate_key = true,
            ("--group", _) => group = Some(flag_value("--group", inline, &mut it)?.to_string()),
            ("--comment", _) => {
                comment = Some(flag_value("--comment", inline, &mut it)?.to_string())
            }
            _ if !arg.starts_with('-') && alias.is_none() => alias = Some(arg.clone()),
            _ => return Err(unexpected(arg)),
        }
    }
    let missing = |what: &str| format!("add needs {what}\ntry 'sshctl add --help'");
    let alias = alias.ok_or_else(|| missing("an alias"))?;
    let hostname = hostname.ok_or_else(|| missing("--hostname"))?;
    let user = user.ok_or_else(|| missing("--user"))?;
    Ok(Some((alias, hostname, user, generate_key, group, comment)))
}

fn main() -> ExitCode {
    // The CLI is short-lived: never leave a working copy lying around.
    model::wipe_work_files();
    let code = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sshctl: {e}");
            ExitCode::FAILURE
        }
    };
    model::wipe_work_files();
    code
}

fn run() -> Result<ExitCode, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        print!("{HELP}");
        return Ok(ExitCode::SUCCESS);
    };
    // Help printed = done; the `None` from a parser means exactly that.
    macro_rules! parsed {
        ($e:expr) => {
            match $e? {
                Some(value) => value,
                None => return Ok(ExitCode::SUCCESS),
            }
        };
    }
    match command.as_str() {
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            Ok(ExitCode::SUCCESS)
        }
        "-V" | "--version" => {
            println!("sshctl {}", env!("CARGO_PKG_VERSION"));
            Ok(ExitCode::SUCCESS)
        }
        "list" => {
            parsed!(no_arguments("list", "Short table of your hosts", rest));
            cmd_list()
        }
        "show" => {
            parsed!(no_arguments(
                "show",
                "Shows your configuration tidied up, the way `write` would save it",
                rest
            ));
            cmd_show()
        }
        "write" => {
            let (dry_run, force) = parsed!(parse_write(rest));
            cmd_write(dry_run, force)
        }
        "doctor" => {
            let (alias, offline, timeout) = parsed!(parse_doctor(rest));
            cmd_doctor(alias, offline, timeout)
        }
        "explain" => {
            let (alias, all) = parsed!(parse_explain(rest));
            cmd_explain(alias, all)
        }
        "add" => {
            let (alias, hostname, user, generate_key, group, comment) = parsed!(parse_add(rest));
            cmd_add(alias, hostname, user, generate_key, group, comment)
        }
        other => Err(format!("unknown command '{other}'\ntry 'sshctl --help'")),
    }
}

fn cmd_list() -> Result<ExitCode, String> {
    let opened = sshctl::open();
    let source = &opened.source;
    if let Some(why) = &opened.unreadable {
        return Err(unreadable_message(why));
    }
    if source.hosts.is_empty() {
        println!("No hosts found in {}.", ssh_config_path().display());
        return Ok(ExitCode::SUCCESS);
    }
    let width = source
        .hosts
        .iter()
        .map(|h| h.alias.len())
        .max()
        .unwrap_or(10);
    for host in &source.hosts {
        println!(
            "{:<width$}  {}@{}  {}",
            host.alias,
            host.user,
            host.hostname,
            host.key.as_deref().unwrap_or("(no key)"),
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_show() -> Result<ExitCode, String> {
    let sshctl::Opened {
        original,
        source,
        unreadable,
    } = sshctl::open();
    if let Some(why) = &unreadable {
        return Err(unreadable_message(why));
    }
    print!("{}", generate::render(&source));
    let losses = fidelity::check(&original, &source);
    if !losses.is_empty() {
        eprintln!("\n{}", round_trip_warning(&losses));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_write(dry_run: bool, force: bool) -> Result<ExitCode, String> {
    let sshctl::Opened {
        original,
        source,
        unreadable,
    } = sshctl::open();
    // The one case where --force must not help either: we cannot show what
    // would be lost, because we never saw it.
    if let Some(why) = &unreadable {
        return Err(unreadable_message(why));
    }

    let problems = source.validate();
    if !problems.is_empty() {
        for p in &problems {
            eprintln!("error: {p}");
        }
        return Err("configuration is not valid; nothing written".to_string());
    }

    let rendered = generate::render(&source);
    if rendered == original {
        println!("{} is already tidy.", ssh_config_path().display());
        return Ok(ExitCode::SUCCESS);
    }

    // The real question is not "does every line survive" but "does ssh still
    // do the same thing". Only ssh itself can answer that.
    let verdict = proof::compare(&original, &rendered, &source);
    let comments = proof::lost_comments(&original, &rendered);
    let losses = fidelity::check(&original, &source);

    if dry_run {
        println!("--- difference ---");
        print_diff(&original, &rendered);
        println!("\n{}", verdict_report(&verdict, &comments, &losses));
        return Ok(ExitCode::SUCCESS);
    }

    // This file belongs to the user, so we do not touch it unless we can show
    // that nothing changes about the way it behaves. Not being able to ask is
    // not a pass: an unproved rewrite needs --force just like a refuted one.
    let blocked = match &verdict {
        proof::Verdict::Same { .. } => None,
        proof::Verdict::Changed(_) => Some("ssh would behave differently afterwards"),
        proof::Verdict::Unknown(_) => Some("ssh could not be asked, so nothing was proved"),
    };
    match blocked {
        None => {
            for comment in &comments {
                eprintln!("note: the comment \"{comment}\" disappears from the file");
            }
        }
        Some(why) => {
            // Never silently: whoever forces still deserves the full story.
            eprintln!("{}", verdict_report(&verdict, &comments, &losses));
            if !force {
                return Err(format!(
                    "nothing written — {why}; fix it by hand, or use --force"
                ));
            }
            eprintln!("note: writing anyway because of --force");
        }
    }
    write_out(&rendered, source.hosts.len())
}

/// Reports what the proof found, with the text check underneath it as detail.
fn verdict_report(
    verdict: &proof::Verdict,
    comments: &[String],
    losses: &[fidelity::Loss],
) -> String {
    let mut out = String::new();
    match verdict {
        proof::Verdict::Same { probed } => {
            out.push_str(&format!(
                "Proved: ssh gives the same answer for all {probed} names before and after.\n"
            ));
        }
        proof::Verdict::Changed(diffs) => {
            out.push_str("ssh would behave differently afterwards:\n");
            for d in diffs {
                out.push_str(&format!("  {}\n", d.describe()));
            }
        }
        proof::Verdict::Unknown(why) => {
            out.push_str(&format!("Could not prove anything: {why}\n"));
            if !losses.is_empty() {
                out.push_str(&round_trip_warning(losses));
            }
        }
    }
    for comment in comments {
        out.push_str(&format!("Comment disappears: {comment}\n"));
    }
    out
}

fn write_out(rendered: &str, count: usize) -> Result<ExitCode, String> {
    let target = ssh_config_path();
    if target.exists() {
        let backup = target.with_extension("before-sshctl");
        std::fs::copy(&target, &backup).map_err(|e| format!("could not make a backup: {e}"))?;
        println!("backup: {}", backup.display());
    }
    sshctl::write_atomically(&target, rendered)?;
    println!("{} updated ({count} hosts)", target.display());
    Ok(ExitCode::SUCCESS)
}

fn round_trip_warning(losses: &[fidelity::Loss]) -> String {
    let mut out = String::from("These lines will not survive the rewrite:\n");
    for loss in losses {
        out.push_str(&format!(
            "  {}\n    ({})\n",
            loss.line,
            loss.reason.describe()
        ));
    }
    out
}

/// Deliberately a simple line comparison instead of a real diff: the file is
/// small and an extra crate is not worth it.
fn print_diff(old: &str, new: &str) {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    for line in &old_lines {
        if !new_lines.contains(line) && !line.trim().is_empty() {
            println!("- {line}");
        }
    }
    for line in &new_lines {
        if !old_lines.contains(line) && !line.trim().is_empty() {
            println!("+ {line}");
        }
    }
}

fn cmd_doctor(alias: Option<String>, offline: bool, timeout: u64) -> Result<ExitCode, String> {
    let sshctl::Opened {
        original,
        source,
        unreadable,
    } = sshctl::open();
    if let Some(why) = &unreadable {
        return Err(unreadable_message(why));
    }
    let opts = doctor::Options {
        offline,
        connect_timeout: Duration::from_secs(timeout),
        only: alias,
    };
    let findings = doctor::run(&source, &original, &opts);

    let width = findings
        .iter()
        .map(|f| f.subject.len())
        .max()
        .unwrap_or(8)
        .max(8);
    for f in &findings {
        println!("{} {:<width$}  {}", f.level.label(), f.subject, f.message);
    }

    let worst = doctor::worst(&findings);
    println!();
    match worst {
        Level::Ok => println!("All in order."),
        Level::Warn => println!("Things to note, but nothing broken."),
        Level::Fail => println!("There are real problems."),
    }
    Ok(match worst {
        Level::Fail => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    })
}

/// The first two steps of a connection: which rules apply, and where it goes.
/// With, for every value, where it comes from.
fn cmd_explain(alias: String, all: bool) -> Result<ExitCode, String> {
    let source = sshctl::open().source;
    let system = sshctl::open_system();
    let resolved = effective::ask_ssh(&alias)?;
    let eff = effective::attribute(
        &alias,
        &resolved,
        &source,
        system.as_ref().map(|(p, s)| (p.as_str(), s)),
    );

    println!("\n\u{2460} WHICH RULES APPLY");
    if eff.matching_blocks.is_empty() {
        println!("   (no block matches — everything is default)");
    }
    for b in &eff.matching_blocks {
        let mark = if b.source_file.starts_with("/etc/") {
            "   <- system-wide"
        } else {
            ""
        };
        println!(
            "   Host {:<24} {}{mark}",
            b.patterns.join(" "),
            b.source_file
        );
    }

    println!("\n\u{2461} WHERE TO");
    show(
        &eff,
        &["hostname", "port", "addressfamily", "bindaddress"],
        all,
    );

    println!("\n\u{2462} WHO AM I");
    show(
        &eff,
        &[
            "user",
            "identityfile",
            "identitiesonly",
            "addkeystoagent",
            "identityagent",
            "certificatefile",
        ],
        all,
    );

    let invisible = eff.invisible();
    if !invisible.is_empty() {
        println!("\nSYSTEM-WIDE");
        for s in invisible {
            println!("   {} {}   <- {}", s.keyword, s.value, s.origin.describe());
        }
    }
    println!();
    Ok(ExitCode::SUCCESS)
}

/// Shows a group of settings. Default values stay out unless you ask for them:
/// otherwise the handful you set yourself drowns.
fn show(eff: &effective::Effective, keywords: &[&str], all: bool) {
    let mut shown = 0;
    for kw in keywords {
        for s in eff.settings.iter().filter(|s| &s.keyword == kw) {
            let is_default = s.origin == effective::Origin::SshDefault;
            if is_default && !all {
                continue;
            }
            println!(
                "   {:<18} {:<34} <- {}",
                s.keyword,
                s.value,
                s.origin.describe()
            );
            shown += 1;
        }
    }
    if shown == 0 {
        println!("   (all defaults)");
    }
}

fn cmd_add(
    alias: String,
    hostname: String,
    user: String,
    generate_key: bool,
    group: Option<String>,
    comment: Option<String>,
) -> Result<ExitCode, String> {
    let sshctl::Opened {
        original,
        mut source,
        unreadable,
    } = sshctl::open();
    if let Some(why) = &unreadable {
        return Err(unreadable_message(why));
    }

    if alias.trim().is_empty() || alias.contains(char::is_whitespace) {
        return Err(format!(
            "alias '{alias}' is not usable — it must be one word, without spaces"
        ));
    }
    if source.hosts.iter().any(|h| h.alias == alias) {
        return Err(format!("alias '{alias}' already exists"));
    }
    // Adding means rewriting the whole file, so the same caution applies as
    // for `write` — with the same nuance: a standalone comment is a note
    // there, not a refusal, and one `# note to self` at the top of the file
    // must not make `add` refuse while `write` carries on.
    let losses = fidelity::check(&original, &source);
    let (comment_losses, real_losses): (Vec<_>, Vec<_>) = losses
        .into_iter()
        .partition(|l| l.reason == fidelity::Reason::Comment);
    if !real_losses.is_empty() {
        eprintln!("{}", round_trip_warning(&real_losses));
        return Err("nothing written — add this host by hand".to_string());
    }
    for loss in &comment_losses {
        eprintln!("note: {} — {}", loss.line, loss.reason.describe());
    }

    // The naming rule lives here in the code, not in your head: key and alias
    // belong together, so they can no longer drift apart.
    let key_name = format!("id_ed25519_{alias}");
    let key_path = model::ssh_dir().join(&key_name);

    if generate_key {
        if key_path.exists() {
            return Err(format!("{} already exists", key_path.display()));
        }
        let status = std::process::Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", "", "-C", &format!("sshctl-{alias}")])
            .arg("-f")
            .arg(&key_path)
            .status()
            .map_err(|e| format!("could not start ssh-keygen: {e}"))?;
        if !status.success() {
            return Err("ssh-keygen failed".to_string());
        }
    }

    source.hosts.push(Host {
        alias: alias.clone(),
        hostname,
        // The user typed it in, so it belongs in the file.
        hostname_explicit: true,
        user,
        key: key_path.exists().then_some(key_name),
        group,
        comment,
        ..Default::default()
    });

    let count = source.hosts.len();
    write_out(&generate::render(&source), count)?;

    if generate_key {
        let pubkey =
            std::fs::read_to_string(sshctl::model::public_half(&key_path)).unwrap_or_default();
        println!("\nPut this line in authorized_keys on the target machine:\n\n{pubkey}");
    }
    println!("Check with: sshctl doctor {alias}");
    Ok(ExitCode::SUCCESS)
}

/// One wording for every command, because the thing that matters is the same
/// everywhere: sshctl has not seen the file, so it will not touch it.
fn unreadable_message(why: &str) -> String {
    format!(
        "cannot read the config, so sshctl will not touch it: {why}\n\
         hint: a file saved as UTF-16 (PowerShell's `>` does this) reads as \
         unusable here; save it as UTF-8."
    )
}
