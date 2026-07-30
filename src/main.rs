//! sshctl — show, check and update your SSH configuration, tidied up.
//!
//! `~/.ssh/config` is the single source of truth. There is no second file, and
//! therefore no question about which of the two is right.

use clap::{Parser, Subcommand};
use sshctl::doctor::{self, Level};
use sshctl::model::{self, Host, ssh_config_path};
use sshctl::{effective, fidelity, generate, proof};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "sshctl",
    version,
    about = "Shows, checks and writes ~/.ssh/config"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Short table of your hosts.
    List,
    /// Shows your configuration tidied up, the way `write` would save it.
    Show,
    /// Writes the tidied-up version back to ~/.ssh/config.
    Write {
        /// Show the difference without writing anything.
        #[arg(long)]
        dry_run: bool,
        /// Write even when the round-trip check reports a loss.
        #[arg(long)]
        force: bool,
    },
    /// Checks the configuration and actual reachability.
    Doctor {
        /// Limit to a single alias.
        alias: Option<String>,
        /// Skip the network and login tests.
        #[arg(long)]
        offline: bool,
        /// Seconds per connection attempt.
        #[arg(long, default_value_t = 5)]
        timeout: u64,
    },
    /// Shows what really applies to a host, and where it comes from.
    Explain {
        alias: String,
        /// Also show the values that are simply ssh's own defaults.
        #[arg(long)]
        all: bool,
    },
    /// Adds a host and writes it out right away.
    Add {
        alias: String,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        user: String,
        /// Create a new ed25519 key without a passphrase.
        #[arg(long)]
        generate_key: bool,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        comment: Option<String>,
    },
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
    match Cli::parse().command {
        Commands::List => cmd_list(),
        Commands::Show => cmd_show(),
        Commands::Write { dry_run, force } => cmd_write(dry_run, force),
        Commands::Doctor {
            alias,
            offline,
            timeout,
        } => cmd_doctor(alias, offline, timeout),
        Commands::Explain { alias, all } => cmd_explain(alias, all),
        Commands::Add {
            alias,
            hostname,
            user,
            generate_key,
            group,
            comment,
        } => cmd_add(alias, hostname, user, generate_key, group, comment),
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
    // that nothing changes about the way it behaves.
    let blocked = match &verdict {
        proof::Verdict::Same { .. } => None,
        proof::Verdict::Changed(_) => Some("ssh would behave differently afterwards"),
        // ssh could not be asked, so nothing is proved. Then the text check
        // has the last word again — the old behaviour, no worse than before.
        proof::Verdict::Unknown(_) if losses.is_empty() => None,
        proof::Verdict::Unknown(_) => Some("lines would be lost and ssh could not be asked"),
    };
    if let Some(why) = blocked
        && !force
    {
        eprintln!("{}", verdict_report(&verdict, &comments, &losses));
        return Err(format!(
            "nothing written — {why}; fix it by hand, or use --force"
        ));
    }

    for comment in &comments {
        eprintln!("note: the comment \"{comment}\" disappears from the file");
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
            "   <- not in your own file"
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
        println!("\nAPPLIES WITHOUT BEING IN YOUR OWN FILE");
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

    if source.hosts.iter().any(|h| h.alias == alias) {
        return Err(format!("alias '{alias}' already exists"));
    }
    // Adding means rewriting the whole file, so the same condition applies as
    // for `write`.
    let losses = fidelity::check(&original, &source);
    if !losses.is_empty() {
        eprintln!("{}", round_trip_warning(&losses));
        return Err("nothing written — add this host by hand".to_string());
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
