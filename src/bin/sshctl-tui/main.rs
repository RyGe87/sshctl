//! Terminal shell on the same core as the CLI and the GUI.
//!
//! Three shells, one library: nothing in here knows ssh. What this shell
//! adds is a place to *work* where a window cannot follow: over ssh, in
//! tmux, on the machine with no screen — which is usually the machine whose
//! config has been lying the longest.
//!
//! The shape mirrors the GUI deliberately, tab for tab and modal for modal.
//! Same four tabs, same rule that the first is for looking and the other
//! three are for changing, same save screen with its two separate questions.
//! Where the GUI needs a thread and a repaint, this event loop simply polls;
//! where egui had to *draw* its status dots because ● is missing from its
//! font, a terminal just prints the character.

mod term;

use sshctl::doctor::{self, Finding, Level};
use sshctl::effective::{self, Effective, Origin};
use sshctl::fidelity::{self, Loss};
use sshctl::generate;
use sshctl::keys::{self, KeyEntry};
use sshctl::known;
use sshctl::model::{self, Host, ssh_config_path};
use sshctl::proof;
use sshctl::proxy;
use std::io;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;
use term::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use term::{
    Block, Clear, Color, Constraint, DefaultTerminal, Frame, Layout, Line, Modifier, Paragraph,
    Rect, Span, Style, Tabs, Text, Wrap,
};

fn main() -> io::Result<()> {
    // Never start with leftovers from a previous session.
    model::wipe_work_files();
    let terminal = term::init();
    let result = App::new().run(terminal);
    term::restore();
    model::wipe_work_files();
    result
}

/// What comes out of the checking thread.
enum Msg {
    Found(Finding),
    Done,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    Config,
    Keys,
    Known,
}

const TABS: [Tab; 4] = [Tab::Overview, Tab::Config, Tab::Keys, Tab::Known];

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Overview => "overview",
            Tab::Config => "config",
            Tab::Keys => "keys",
            Tab::Known => "known_hosts",
        }
    }
}

/// The editable fields of a host block, in the order they appear.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HostField {
    Alias,
    Hostname,
    User,
    Port,
    Key,
    ProxyJump,
    Comment,
}

const HOST_FIELDS: [HostField; 7] = [
    HostField::Alias,
    HostField::Hostname,
    HostField::User,
    HostField::Port,
    HostField::Key,
    HostField::ProxyJump,
    HostField::Comment,
];

impl HostField {
    fn label(self) -> &'static str {
        match self {
            HostField::Alias => "Alias",
            HostField::Hostname => "Hostname",
            HostField::User => "User",
            HostField::Port => "Port",
            HostField::Key => "Key",
            HostField::ProxyJump => "Via (ProxyJump)",
            HostField::Comment => "Comment",
        }
    }

    fn current(self, host: &Host) -> String {
        match self {
            HostField::Alias => host.alias.clone(),
            HostField::Hostname => host.hostname.clone(),
            HostField::User => host.user.clone(),
            HostField::Port => host.port.map(|p| p.to_string()).unwrap_or_default(),
            HostField::Key => host.key.clone().unwrap_or_default(),
            HostField::ProxyJump => host.proxy_jump.clone().unwrap_or_default(),
            HostField::Comment => host.comment.clone().unwrap_or_default(),
        }
    }
}

/// One key from ssh-keyscan, with its fingerprint worked out once.
struct Scanned {
    name: String,
    kind: String,
    line: String,
    fingerprint: String,
}

/// `ssh-keygen -l` over stdin, so the line never has to touch the disk.
fn fingerprint_of(line: &str) -> String {
    std::process::Command::new("ssh-keygen")
        .args(["-l", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .ok()
        .and_then(|mut c| {
            use std::io::Write;
            c.stdin.as_mut()?.write_all(line.as_bytes()).ok()?;
            let o = c.wait_with_output().ok()?;
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .unwrap_or_default()
}

/// A one-line text editor: the whole event handling a terminal needs for a
/// field, and nothing more.
#[derive(Default)]
struct Input {
    text: String,
    cursor: usize,
}

impl Input {
    fn from(text: &str) -> Self {
        Self {
            text: text.to_string(),
            cursor: text.chars().count(),
        }
    }

    fn byte_at(&self, chars: usize) -> usize {
        self.text
            .char_indices()
            .nth(chars)
            .map(|(i, _)| i)
            .unwrap_or(self.text.len())
    }

    /// Returns true when the key was consumed.
    fn handle(&mut self, key: &KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                let at = self.byte_at(self.cursor);
                self.text.insert(at, c);
                self.cursor += 1;
                true
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    let at = self.byte_at(self.cursor - 1);
                    self.text.remove(at);
                    self.cursor -= 1;
                }
                true
            }
            KeyCode::Delete => {
                if self.cursor < self.text.chars().count() {
                    let at = self.byte_at(self.cursor);
                    self.text.remove(at);
                }
                true
            }
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                true
            }
            KeyCode::Right => {
                self.cursor = (self.cursor + 1).min(self.text.chars().count());
                true
            }
            KeyCode::Home => {
                self.cursor = 0;
                true
            }
            KeyCode::End => {
                self.cursor = self.text.chars().count();
                true
            }
            _ => false,
        }
    }

    /// The text with a visible cursor block when focused.
    fn line(&self, label: &str, focused: bool) -> Line<'static> {
        let mut spans = vec![Span::styled(
            format!("{label:<10} "),
            Style::new().fg(Color::DarkGray),
        )];
        if focused {
            let head: String = self.text.chars().take(self.cursor).collect();
            let at: String = self.text.chars().skip(self.cursor).take(1).collect();
            let tail: String = self.text.chars().skip(self.cursor + 1).collect();
            spans.push(Span::raw(head));
            spans.push(Span::styled(
                if at.is_empty() { " ".to_string() } else { at },
                Style::new().add_modifier(Modifier::REVERSED),
            ));
            spans.push(Span::raw(tail));
        } else {
            spans.push(Span::raw(self.text.clone()));
        }
        Line::from(spans)
    }
}

/// Which value-entry stage the option picker is in.
enum OptStage {
    Search,
    Value {
        spec: &'static sshctl::catalog::OptionSpec,
        value: Input,
        choice: usize,
    },
}

enum Modal {
    None,
    Help,
    ConfirmQuit,
    ConfirmReload,
    Save {
        rendered: String,
        removed: Vec<String>,
        added: Vec<String>,
        disk_changed: bool,
        outcome: Option<proof::SaveJudgement>,
        lost_comments: Vec<String>,
        losses: Vec<Loss>,
        /// The "I know — write anyway" tick, armed with `f`.
        armed: bool,
    },
    EditField {
        field: HostField,
        input: Input,
    },
    PickKey {
        sel: usize,
    },
    AddHost {
        focus: usize,
        alias: Input,
        hostname: Input,
        user: Input,
        generate: bool,
        existing_key: Option<String>,
    },
    PickOption {
        search: Input,
        sel: usize,
        stage: OptStage,
    },
    PickHop {
        sel: usize,
        free: Input,
        append: bool,
    },
    NewKey {
        focus: usize,
        name: Input,
        comment: Input,
    },
    ConfirmDeleteKey(String),
    KeyMade {
        name: String,
        detail: Option<keys::KeyDetail>,
    },
    EditKeyComment {
        input: Input,
    },
    ScanHost {
        input: Input,
    },
    ConfirmForget(String),
    PinEntry {
        name: String,
        sel: usize,
    },
}

/// What a modal asks the app to do once the borrow of the modal is released.
enum Act {
    Close,
    Quit,
    Reload,
    Write(String),
    ApplyEdit(HostField, String),
    SetKey(Option<String>),
    AddHost {
        alias: String,
        hostname: String,
        user: String,
        generate: bool,
        existing: Option<String>,
    },
    AddOption(String),
    SetHop {
        hop: String,
        append: bool,
    },
    MakeKey {
        name: String,
        comment: String,
    },
    DeleteKey(String),
    SetKeyComment(String),
    Forget(String),
    Scan(String),
    AddScanned,
    Pin {
        alias: String,
        name: String,
    },
}

struct App {
    original: String,
    source: sshctl::model::Source,
    losses: Vec<Loss>,
    unreadable: Option<String>,
    dirty: bool,

    tab: Tab,
    /// Which pane has focus on the config tab: the host list or the fields.
    config_fields_focused: bool,
    selected: usize,
    config_row: usize,

    effective: Option<Effective>,
    effective_for: Option<String>,
    effective_error: Option<String>,
    known_types: Vec<String>,

    keys: Vec<KeyEntry>,
    key_sel: usize,
    key_detail: Option<keys::KeyDetail>,

    ledger: known::Ledger,
    tree: Vec<known::Branch>,
    ledger_loading: bool,
    entry_sel: usize,

    findings: Vec<Finding>,
    findings_scroll: usize,
    checking: bool,
    doctor_rx: Option<Receiver<Msg>>,
    proof_rx: Option<Receiver<proof::SaveJudgement>>,
    ledger_rx: Option<Receiver<(known::Ledger, Vec<known::Branch>)>>,

    scan_result: Vec<Scanned>,
    scan_target: Option<PathBuf>,

    modal: Modal,
    toast: Option<(String, Level)>,
    quit: bool,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            original: String::new(),
            source: sshctl::model::Source::default(),
            losses: Vec::new(),
            unreadable: None,
            dirty: false,
            tab: Tab::Overview,
            config_fields_focused: false,
            selected: 0,
            config_row: 0,
            effective: None,
            effective_for: None,
            effective_error: None,
            known_types: Vec::new(),
            keys: Vec::new(),
            key_sel: 0,
            key_detail: None,
            ledger: known::Ledger::default(),
            tree: Vec::new(),
            ledger_loading: false,
            entry_sel: 0,
            findings: Vec::new(),
            findings_scroll: 0,
            checking: false,
            doctor_rx: None,
            proof_rx: None,
            ledger_rx: None,
            scan_result: Vec::new(),
            scan_target: None,
            modal: Modal::None,
            toast: None,
            quit: false,
        };
        app.reload();
        app
    }

    fn run(mut self, mut terminal: DefaultTerminal) -> io::Result<()> {
        self.start_check();
        loop {
            self.drain();
            let alias = self
                .source
                .hosts
                .get(self.selected)
                .map(|h| h.alias.clone());
            if alias != self.effective_for {
                self.refresh_effective();
            }
            terminal.draw(|f| ui(f, &self))?;
            if event::poll(Duration::from_millis(150))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                self.handle_key(key);
            }
            if self.quit {
                return Ok(());
            }
        }
    }

    /// Reads ~/.ssh/config in again. Throws away unsaved work, so only call
    /// it on opening or after an explicit confirmation.
    fn reload(&mut self) {
        let opened = sshctl::open();
        self.unreadable = opened.unreadable;
        self.losses = fidelity::check(&opened.original, &opened.source);
        self.original = opened.original;
        self.source = opened.source;
        self.dirty = false;
        self.selected = 0;
        self.config_row = 0;
        self.keys = keys::inventory(&self.source);
        self.key_sel = 0;
        self.refresh_key_detail();
        self.refresh_ledger();
        self.source.write_work_copy();
    }

    fn say(&mut self, message: impl Into<String>, level: Level) {
        self.toast = Some((message.into(), level));
    }

    /// Marks an edit and refreshes what depends on the model.
    fn touched(&mut self) {
        self.dirty = true;
        self.keys = keys::inventory(&self.source);
        self.losses = fidelity::check(&self.original, &self.source);
        self.effective_for = None;
        self.source.write_work_copy();
    }

    fn drain(&mut self) {
        if let Some(rx) = &self.doctor_rx {
            let mut done = false;
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Msg::Found(f) => self.findings.push(f),
                    Msg::Done => done = true,
                }
            }
            if done {
                self.checking = false;
                self.doctor_rx = None;
            }
        }
        if let Some(rx) = &self.proof_rx
            && let Ok(judgement) = rx.try_recv()
        {
            self.proof_rx = None;
            if let Modal::Save { outcome, .. } = &mut self.modal
                && outcome.is_none()
            {
                *outcome = Some(judgement);
            }
        }
        if let Some(rx) = &self.ledger_rx
            && let Ok((ledger, tree)) = rx.try_recv()
        {
            self.ledger_rx = None;
            self.ledger_loading = false;
            self.ledger = ledger;
            self.tree = tree;
        }
    }

    /// Starts the checks on a thread; results trickle into the findings pane.
    fn start_check(&mut self) {
        let copy = self.source.clone();
        let original = self.original.clone();
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let opts = doctor::Options::default();
            doctor::run_streaming(&copy, &original, &opts, &mut |f| {
                let _ = tx.send(Msg::Found(f));
            });
            let _ = tx.send(Msg::Done);
        });
        self.findings.clear();
        self.findings_scroll = 0;
        self.checking = true;
        self.doctor_rx = Some(rx);
    }

    /// Reads the ledger on a thread — one `ssh -G` per host adds up.
    fn refresh_ledger(&mut self) {
        let source = self.source.clone();
        let (tx, rx) = channel();
        self.ledger_loading = true;
        self.ledger_rx = Some(rx);
        std::thread::spawn(move || {
            let files = known::files_for_all(&source);
            let (ledger, tree) = if files.is_empty() {
                (known::Ledger::default(), Vec::new())
            } else {
                let ledger = known::Ledger::load(&files);
                let per_host = known::lookup_per_host(&source, &files);
                let tree = known::tree(&per_host, &ledger);
                (ledger, tree)
            };
            let _ = tx.send((ledger, tree));
        });
    }

    /// Asks ssh what applies to the selected host. ~7 ms, so fine on a
    /// selection change; never per frame.
    fn refresh_effective(&mut self) {
        let Some(alias) = self
            .source
            .hosts
            .get(self.selected)
            .map(|h| h.alias.clone())
        else {
            self.effective = None;
            self.effective_for = None;
            self.effective_error = None;
            return;
        };
        self.effective_for = Some(alias.clone());
        self.known_types.clear();
        match effective::ask_ssh(&alias) {
            Ok(resolved) => {
                let files = known::files_in_use(&resolved);
                if let Some(host) = self.source.hosts.iter().find(|h| h.alias == alias) {
                    let raw = known::lookup(&host.hostname, host.port_or_default(), &files);
                    let ledger = known::Ledger::load(&files);
                    for entry in &ledger.entries {
                        if raw.contains(&entry.raw_names)
                            && !self.known_types.contains(&entry.key_type)
                        {
                            self.known_types.push(entry.key_type.clone());
                        }
                    }
                }
                let system = sshctl::open_system();
                self.effective = Some(effective::attribute(
                    &alias,
                    &resolved,
                    &self.source,
                    system.as_ref().map(|(p, s)| (p.as_str(), s)),
                ));
                self.effective_error = None;
            }
            Err(e) => {
                self.effective = None;
                self.effective_error = Some(e);
            }
        }
    }

    fn refresh_key_detail(&mut self) {
        self.key_detail = self
            .keys
            .get(self.key_sel)
            .map(|k| k.name.clone())
            .and_then(|n| keys::detail(&n, &self.source));
    }

    /// The losses worth a banner: lines of the file that would really go.
    /// An `Added` line is not one of them — that is usually this session's
    /// own edit, and the save screen judges those with ssh.
    fn banner_losses(&self) -> usize {
        self.losses
            .iter()
            .filter(|l| l.reason != fidelity::Reason::Added)
            .count()
    }

    /// The worst verdict per host, so the list can carry a dot.
    fn level_for(&self, alias: &str) -> Option<Level> {
        self.findings
            .iter()
            .filter(|f| f.subject == alias)
            .map(|f| f.level)
            .max()
    }

    fn open_save_preview(&mut self) {
        if self.unreadable.is_some() {
            self.say(
                "sshctl cannot read your config, so it will not overwrite it either",
                Level::Fail,
            );
            return;
        }
        let problems = self.source.validate();
        if !problems.is_empty() {
            self.say(problems.join("; "), Level::Fail);
            return;
        }
        let rendered = generate::render(&self.source);
        let on_disk = std::fs::read_to_string(ssh_config_path()).unwrap_or_default();
        let disk_changed = on_disk != self.original;

        let old: Vec<&str> = on_disk.lines().collect();
        let new: Vec<&str> = rendered.lines().collect();
        let removed = old
            .iter()
            .filter(|l| !new.contains(*l) && !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();
        let added = new
            .iter()
            .filter(|l| !old.contains(*l) && !l.trim().is_empty())
            .map(|l| l.to_string())
            .collect();
        let lost_comments = proof::lost_comments(&on_disk, &rendered);
        let losses = fidelity::check(&on_disk, &self.source);

        // The proof runs on a thread; the modal says "checking" meanwhile.
        let (tx, rx) = channel();
        let source = self.source.clone();
        let target = rendered.clone();
        std::thread::spawn(move || {
            let _ = tx.send(proof::judge_save(&on_disk, &target, &source));
        });
        self.proof_rx = Some(rx);
        self.modal = Modal::Save {
            rendered,
            removed,
            added,
            disk_changed,
            outcome: None,
            lost_comments,
            losses,
            armed: false,
        };
    }

    fn apply_save(&mut self, rendered: &str) {
        self.proof_rx = None;
        let target = ssh_config_path();
        if target.exists() {
            let backup = target.with_extension("before-sshctl");
            if let Err(e) = std::fs::copy(&target, &backup) {
                self.say(format!("backup failed, nothing written: {e}"), Level::Fail);
                return;
            }
        }
        match sshctl::write_atomically(&target, rendered) {
            Ok(()) => {
                self.original = rendered.to_string();
                self.losses = fidelity::check(&self.original, &self.source);
                self.dirty = false;
                self.effective_for = None;
                self.refresh_ledger();
                self.say("~/.ssh/config updated (backup alongside)", Level::Ok);
            }
            Err(e) => self.say(format!("writing failed: {e}"), Level::Fail),
        }
        self.modal = Modal::None;
    }

    fn add_host(
        &mut self,
        alias: &str,
        hostname: &str,
        user: &str,
        generate: bool,
        existing: Option<String>,
    ) {
        let alias = alias.trim().to_string();
        if alias.is_empty() {
            self.say("alias must not be empty", Level::Fail);
            return;
        }
        if alias.contains(char::is_whitespace) {
            self.say(
                "an alias must be one word — ssh reads spaces as several patterns",
                Level::Fail,
            );
            return;
        }
        if hostname.trim().is_empty() {
            self.say("hostname must not be empty", Level::Fail);
            return;
        }
        if self.source.hosts.iter().any(|h| h.alias == alias) {
            self.say(format!("alias '{alias}' already exists"), Level::Fail);
            return;
        }
        let key_name = existing
            .clone()
            .unwrap_or_else(|| format!("id_ed25519_{alias}"));
        if generate
            && existing.is_none()
            && let Err(e) = keys::generate(&alias, &format!("sshctl-{alias}"))
        {
            self.say(e, Level::Fail);
            return;
        }
        let key_path = model::ssh_dir().join(&key_name);
        self.source.hosts.push(Host {
            alias: alias.clone(),
            hostname: hostname.trim().to_string(),
            // The user typed it in, so it belongs in the file.
            hostname_explicit: true,
            user: user.trim().to_string(),
            key: key_path.exists().then_some(key_name),
            ..Default::default()
        });
        self.selected = self.source.hosts.len() - 1;
        self.modal = Modal::None;
        self.touched();
        self.say(format!("'{alias}' added — not saved yet"), Level::Ok);
    }

    fn apply_field_edit(&mut self, field: HostField, value: String) {
        let Some(host) = self.source.hosts.get_mut(self.selected) else {
            return;
        };
        let value = value.trim().to_string();
        match field {
            HostField::Alias => host.alias = value,
            HostField::Hostname => {
                host.hostname = value;
                host.hostname_explicit = !host.hostname.is_empty();
            }
            HostField::User => host.user = value,
            HostField::Port => host.port = value.parse().ok(),
            HostField::Key => host.key = (!value.is_empty()).then_some(value),
            HostField::ProxyJump => host.proxy_jump = (!value.is_empty()).then_some(value),
            HostField::Comment => host.comment = (!value.is_empty()).then_some(value),
        }
        self.modal = Modal::None;
        self.touched();
    }

    fn add_option(&mut self, line: String) {
        let Some(host) = self.source.hosts.get_mut(self.selected) else {
            return;
        };
        // Same rule as the GUI: a repeatable keyword accumulates, any other
        // replaces its earlier line — ssh only reads the first.
        let keyword = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !sshctl::catalog::is_repeatable(&keyword) {
            host.options
                .retain(|o| !o.to_ascii_lowercase().starts_with(&format!("{keyword} ")));
        }
        host.options.push(line.clone());
        self.modal = Modal::None;
        self.touched();
        self.say(format!("'{line}' added — not saved yet"), Level::Ok);
    }

    fn set_hop(&mut self, hop: &str, append: bool) {
        if let Some(host) = self.source.hosts.get_mut(self.selected) {
            let updated = match (&host.proxy_jump, append) {
                (Some(existing), true) if !existing.trim().is_empty() => {
                    format!("{existing},{hop}")
                }
                _ => hop.to_string(),
            };
            host.proxy_jump = Some(updated);
            self.touched();
            self.say(format!("hop '{hop}' set — not saved yet"), Level::Ok);
        }
        self.modal = Modal::None;
    }

    fn remove_host(&mut self) {
        if self.selected < self.source.hosts.len() {
            let alias = self.source.hosts[self.selected].alias.clone();
            self.source.hosts.remove(self.selected);
            self.selected = self.selected.min(self.source.hosts.len().saturating_sub(1));
            self.config_row = 0;
            self.touched();
            self.say(format!("'{alias}' removed — not saved yet"), Level::Warn);
        }
    }

    /// Sets `HostKeyAlias` so ssh looks the trust up under that name — the
    /// only safe way to tie a host and an entry together.
    fn pin_host_key(&mut self, alias: &str, name: &str) {
        let Some(host) = self.source.hosts.iter_mut().find(|h| h.alias == alias) else {
            return;
        };
        host.options
            .retain(|o| !o.to_ascii_lowercase().starts_with("hostkeyalias "));
        host.options.push(format!("HostKeyAlias {name}"));
        self.touched();
        self.say(
            format!("'{alias}' now looks up under '{name}' — not saved yet"),
            Level::Ok,
        );
        self.modal = Modal::None;
    }

    fn forget_entry(&mut self, name: &str) {
        let raw = self
            .ledger
            .entries
            .iter()
            .find(|e| e.label() == name)
            .map(|e| e.raw_names.clone());
        match raw {
            Some(raw) => match known::remove_entry(&self.ledger.files.clone(), &raw) {
                Ok(n) => {
                    self.refresh_ledger();
                    self.entry_sel = 0;
                    self.effective_for = None;
                    self.say(
                        format!("{n} line(s) removed from known_hosts (backup alongside)"),
                        Level::Ok,
                    );
                }
                Err(e) => self.say(e, Level::Fail),
            },
            None => self.say("entry no longer found", Level::Fail),
        }
        self.modal = Modal::None;
    }

    fn scan(&mut self, input: &str) {
        let input = input.trim().to_string();
        let (host, port) = match proxy::parse_chain(&input).into_iter().next() {
            Some(hop) => (hop.host, hop.port.unwrap_or(22)),
            None => (input.clone(), 22),
        };
        match known::scan(&host, port) {
            Ok(r) => {
                self.scan_result = r
                    .into_iter()
                    .map(|(name, kind, line)| Scanned {
                        fingerprint: fingerprint_of(&line),
                        name,
                        kind,
                        line,
                    })
                    .collect();
                self.scan_target = effective::ask_ssh(&host)
                    .ok()
                    .and_then(|resolved| known::append_target(&resolved));
                self.say(
                    format!("{} key(s) fetched", self.scan_result.len()),
                    Level::Ok,
                );
            }
            Err(e) => {
                self.scan_result.clear();
                self.scan_target = None;
                self.say(e, Level::Fail);
            }
        }
    }

    fn add_scanned(&mut self) {
        let lines: Vec<String> = self.scan_result.iter().map(|s| s.line.clone()).collect();
        match self.scan_target.clone() {
            Some(target) => match known::append(&target, &lines) {
                Ok(n) => {
                    self.refresh_ledger();
                    self.modal = Modal::None;
                    self.say(format!("{n} line(s) added (backup alongside)"), Level::Ok);
                }
                Err(e) => self.say(e, Level::Fail),
            },
            None => self.say(
                "ssh did not name a known_hosts file for this host",
                Level::Fail,
            ),
        }
    }

    fn make_key(&mut self, name: &str, comment: &str) {
        match keys::generate(name, comment) {
            Ok(made) => {
                self.keys = keys::inventory(&self.source);
                self.modal = Modal::KeyMade {
                    detail: keys::detail(&made, &self.source),
                    name: made.clone(),
                };
                self.say(format!("{made} created"), Level::Ok);
            }
            Err(e) => self.say(e, Level::Fail),
        }
    }

    fn delete_key(&mut self, name: &str) {
        match keys::delete(name) {
            Ok(target) => {
                self.keys = keys::inventory(&self.source);
                self.key_sel = self.key_sel.min(self.keys.len().saturating_sub(1));
                self.refresh_key_detail();
                self.modal = Modal::None;
                self.say(format!("moved to {}", target.display()), Level::Warn);
            }
            Err(e) => self.say(e, Level::Fail),
        }
    }

    fn set_key_comment(&mut self, comment: &str) {
        let Some(name) = self.keys.get(self.key_sel).map(|k| k.name.clone()) else {
            return;
        };
        match keys::set_comment(&name, comment) {
            Ok(()) => {
                self.refresh_key_detail();
                self.say("comment updated", Level::Ok);
            }
            Err(e) => self.say(e, Level::Fail),
        }
        self.modal = Modal::None;
    }

    // ------------------------------------------------------------------
    // Input handling
    // ------------------------------------------------------------------

    fn handle_key(&mut self, key: KeyEvent) {
        self.toast = None;
        if !matches!(self.modal, Modal::None) {
            if let Some(act) = self.modal_key(&key) {
                self.perform(act);
            }
            return;
        }
        match key.code {
            KeyCode::Char('q') => {
                if self.dirty {
                    self.modal = Modal::ConfirmQuit;
                } else {
                    self.quit = true;
                }
            }
            KeyCode::Char('1') => self.tab = Tab::Overview,
            KeyCode::Char('2') => self.tab = Tab::Config,
            KeyCode::Char('3') => {
                self.tab = Tab::Keys;
                self.refresh_key_detail();
            }
            KeyCode::Char('4') => self.tab = Tab::Known,
            KeyCode::Tab => {
                let i = TABS.iter().position(|t| *t == self.tab).unwrap_or(0);
                self.tab = TABS[(i + 1) % TABS.len()];
                if self.tab == Tab::Keys {
                    self.refresh_key_detail();
                }
            }
            KeyCode::Char('C') => self.start_check(),
            KeyCode::Char('S') => self.open_save_preview(),
            KeyCode::Char('R') => {
                if self.dirty {
                    self.modal = Modal::ConfirmReload;
                } else {
                    self.reload();
                    self.say("~/.ssh/config read in again", Level::Ok);
                }
            }
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::PageUp => self.findings_scroll += 5,
            KeyCode::PageDown => self.findings_scroll = self.findings_scroll.saturating_sub(5),
            _ => self.tab_key(&key),
        }
    }

    fn tab_key(&mut self, key: &KeyEvent) {
        match self.tab {
            Tab::Overview => {
                if let Some(step) = list_step(key) {
                    self.selected = step_index(self.selected, step, self.source.hosts.len());
                }
            }
            Tab::Config => self.config_key(key),
            Tab::Keys => match key.code {
                KeyCode::Char('n') => {
                    self.modal = Modal::NewKey {
                        focus: 0,
                        name: Input::default(),
                        comment: Input::from(&format!("new@{}", machine_name())),
                    };
                }
                KeyCode::Char('d') => {
                    if let Some(k) = self.keys.get(self.key_sel) {
                        self.modal = Modal::ConfirmDeleteKey(k.name.clone());
                    }
                }
                KeyCode::Char('c') => {
                    let current = self
                        .key_detail
                        .as_ref()
                        .map(|d| d.comment.clone())
                        .unwrap_or_default();
                    if self.keys.get(self.key_sel).is_some() {
                        self.modal = Modal::EditKeyComment {
                            input: Input::from(&current),
                        };
                    }
                }
                KeyCode::Char('H') => {
                    // Adopt an orphan: open the add-host form with this key
                    // already attached, alias suggested from the filename.
                    if let Some(k) = self.keys.get(self.key_sel).cloned()
                        && k.is_orphan()
                    {
                        self.modal = Modal::AddHost {
                            focus: 1,
                            alias: Input::from(&k.suggested_alias()),
                            hostname: Input::default(),
                            user: Input::default(),
                            generate: false,
                            existing_key: Some(k.name),
                        };
                    }
                }
                _ => {
                    if let Some(step) = list_step(key) {
                        let before = self.key_sel;
                        self.key_sel = step_index(self.key_sel, step, self.keys.len());
                        if before != self.key_sel {
                            self.refresh_key_detail();
                        }
                    }
                }
            },
            Tab::Known => match key.code {
                KeyCode::Char('f') => {
                    self.scan_result.clear();
                    self.scan_target = None;
                    self.modal = Modal::ScanHost {
                        input: Input::default(),
                    };
                }
                KeyCode::Char('d') => {
                    if let Some((name, _)) = self.ledger.per_name().get(self.entry_sel) {
                        self.modal = Modal::ConfirmForget(name.clone());
                    }
                }
                KeyCode::Char('p') => {
                    if let Some((name, _)) = self.ledger.per_name().get(self.entry_sel)
                        && !self.source.hosts.is_empty()
                    {
                        self.modal = Modal::PinEntry {
                            name: name.clone(),
                            sel: 0,
                        };
                    }
                }
                _ => {
                    if let Some(step) = list_step(key) {
                        self.entry_sel =
                            step_index(self.entry_sel, step, self.ledger.per_name().len());
                    }
                }
            },
        }
    }

    fn config_key(&mut self, key: &KeyEvent) {
        let option_count = self
            .source
            .hosts
            .get(self.selected)
            .map(|h| h.options.len())
            .unwrap_or(0);
        let rows = HOST_FIELDS.len() + option_count;
        if key.code == KeyCode::Char('a') {
            self.modal = Modal::AddHost {
                focus: 0,
                alias: Input::default(),
                hostname: Input::default(),
                user: Input::default(),
                generate: true,
                existing_key: None,
            };
            return;
        }
        if !self.config_fields_focused {
            match key.code {
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => {
                    if !self.source.hosts.is_empty() {
                        self.config_fields_focused = true;
                    }
                }
                _ => {
                    if let Some(step) = list_step(key) {
                        self.selected = step_index(self.selected, step, self.source.hosts.len());
                        self.config_row = 0;
                    }
                }
            }
            return;
        }
        match key.code {
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Esc => {
                self.config_fields_focused = false;
            }
            KeyCode::Enter => {
                if self.config_row < HOST_FIELDS.len() {
                    let field = HOST_FIELDS[self.config_row];
                    let Some(host) = self.source.hosts.get(self.selected) else {
                        return;
                    };
                    if field == HostField::Key {
                        self.modal = Modal::PickKey { sel: 0 };
                    } else {
                        self.modal = Modal::EditField {
                            field,
                            input: Input::from(&field.current(host)),
                        };
                    }
                }
            }
            KeyCode::Char('x') => {
                if self.config_row >= HOST_FIELDS.len()
                    && let Some(host) = self.source.hosts.get_mut(self.selected)
                {
                    let i = self.config_row - HOST_FIELDS.len();
                    if i < host.options.len() {
                        host.options.remove(i);
                        self.config_row = self
                            .config_row
                            .min((HOST_FIELDS.len() + host.options.len()).saturating_sub(1));
                        self.touched();
                    }
                }
            }
            KeyCode::Char('o') => {
                self.modal = Modal::PickOption {
                    search: Input::default(),
                    sel: 0,
                    stage: OptStage::Search,
                };
            }
            KeyCode::Char('p') => {
                self.modal = Modal::PickHop {
                    sel: 0,
                    free: Input::default(),
                    append: false,
                };
            }
            KeyCode::Char('D') => {
                self.config_fields_focused = false;
                self.remove_host();
            }
            _ => {
                if let Some(step) = list_step(key) {
                    self.config_row = step_index(self.config_row, step, rows);
                }
            }
        }
    }

    /// Handles a key while a modal is open. Returns the action to perform
    /// once the borrow of the modal is released.
    fn modal_key(&mut self, key: &KeyEvent) -> Option<Act> {
        match &mut self.modal {
            Modal::None => None,
            Modal::Help | Modal::KeyMade { .. } => match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => Some(Act::Close),
                _ => None,
            },
            Modal::ConfirmQuit => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => Some(Act::Quit),
                KeyCode::Esc | KeyCode::Char('n') => Some(Act::Close),
                _ => None,
            },
            Modal::ConfirmReload => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => Some(Act::Reload),
                KeyCode::Esc | KeyCode::Char('n') => Some(Act::Close),
                _ => None,
            },
            Modal::ConfirmDeleteKey(name) => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => Some(Act::DeleteKey(name.clone())),
                KeyCode::Esc | KeyCode::Char('n') => Some(Act::Close),
                _ => None,
            },
            Modal::ConfirmForget(name) => match key.code {
                KeyCode::Char('y') | KeyCode::Enter => Some(Act::Forget(name.clone())),
                KeyCode::Esc | KeyCode::Char('n') => Some(Act::Close),
                _ => None,
            },
            Modal::Save {
                rendered,
                outcome,
                armed,
                ..
            } => {
                let blocked = save_blocked(outcome);
                match key.code {
                    KeyCode::Esc => Some(Act::Close),
                    KeyCode::Char('f') if blocked.is_some() => {
                        *armed = !*armed;
                        None
                    }
                    KeyCode::Char('w') | KeyCode::Enter => {
                        if outcome.is_none() {
                            None
                        } else if blocked.is_none() || *armed {
                            Some(Act::Write(rendered.clone()))
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            Modal::EditField { field, input } => match key.code {
                KeyCode::Esc => Some(Act::Close),
                KeyCode::Enter => Some(Act::ApplyEdit(*field, input.text.clone())),
                _ => {
                    input.handle(key);
                    None
                }
            },
            Modal::PickKey { sel } => {
                // Row 0 is "(none)", the rest is the inventory.
                let count = self.keys.len() + 1;
                match key.code {
                    KeyCode::Esc => Some(Act::Close),
                    KeyCode::Enter => {
                        let choice = if *sel == 0 {
                            None
                        } else {
                            self.keys.get(*sel - 1).map(|k| k.name.clone())
                        };
                        Some(Act::SetKey(choice))
                    }
                    _ => {
                        if let Some(step) = list_step(key) {
                            *sel = step_index(*sel, step, count);
                        }
                        None
                    }
                }
            }
            Modal::AddHost {
                focus,
                alias,
                hostname,
                user,
                generate,
                existing_key,
            } => match key.code {
                KeyCode::Esc => Some(Act::Close),
                KeyCode::Enter => Some(Act::AddHost {
                    alias: alias.text.clone(),
                    hostname: hostname.text.clone(),
                    user: user.text.clone(),
                    generate: *generate,
                    existing: existing_key.clone(),
                }),
                KeyCode::Tab | KeyCode::Down => {
                    *focus = (*focus + 1) % 4;
                    None
                }
                KeyCode::BackTab | KeyCode::Up => {
                    *focus = (*focus + 3) % 4;
                    None
                }
                KeyCode::Char(' ') if *focus == 3 => {
                    if existing_key.is_none() {
                        *generate = !*generate;
                    }
                    None
                }
                _ => {
                    match focus {
                        0 => alias.handle(key),
                        1 => hostname.handle(key),
                        2 => user.handle(key),
                        _ => false,
                    };
                    None
                }
            },
            Modal::PickOption { search, sel, stage } => match stage {
                OptStage::Search => {
                    let hits = sshctl::catalog::search(&search.text);
                    match key.code {
                        KeyCode::Esc => Some(Act::Close),
                        KeyCode::Up => {
                            *sel = sel.saturating_sub(1);
                            None
                        }
                        KeyCode::Down => {
                            *sel = (*sel + 1).min(hits.len().saturating_sub(1));
                            None
                        }
                        KeyCode::Enter => {
                            if let Some(spec) = hits.get(*sel) {
                                *stage = OptStage::Value {
                                    spec,
                                    value: Input::default(),
                                    choice: 0,
                                };
                            }
                            None
                        }
                        _ => {
                            if search.handle(key) {
                                *sel = 0;
                            }
                            None
                        }
                    }
                }
                OptStage::Value {
                    spec,
                    value,
                    choice,
                } => match key.code {
                    KeyCode::Esc => {
                        *stage = OptStage::Search;
                        None
                    }
                    KeyCode::Enter => {
                        let v = if spec.choices.is_empty() {
                            value.text.trim().to_string()
                        } else {
                            spec.choices.get(*choice).unwrap_or(&"").to_string()
                        };
                        if v.is_empty() {
                            None
                        } else {
                            Some(Act::AddOption(format!("{} {}", spec.keyword, v)))
                        }
                    }
                    KeyCode::Up if !spec.choices.is_empty() => {
                        *choice = choice.saturating_sub(1);
                        None
                    }
                    KeyCode::Down if !spec.choices.is_empty() => {
                        *choice = (*choice + 1).min(spec.choices.len() - 1);
                        None
                    }
                    _ => {
                        if spec.choices.is_empty() {
                            value.handle(key);
                        }
                        None
                    }
                },
            },
            Modal::PickHop { sel, free, append } => {
                let own: Vec<String> = self
                    .source
                    .hosts
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != self.selected)
                    .map(|(_, h)| h.alias.clone())
                    .collect();
                // The last row is the freeform input.
                let rows = own.len() + 1;
                match key.code {
                    KeyCode::Esc => Some(Act::Close),
                    KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        *append = !*append;
                        None
                    }
                    KeyCode::Enter => {
                        let hop = if *sel < own.len() {
                            own[*sel].clone()
                        } else {
                            free.text.trim().to_string()
                        };
                        if hop.is_empty() {
                            None
                        } else {
                            Some(Act::SetHop {
                                hop,
                                append: *append,
                            })
                        }
                    }
                    KeyCode::Up => {
                        *sel = sel.saturating_sub(1);
                        None
                    }
                    KeyCode::Down => {
                        *sel = (*sel + 1).min(rows - 1);
                        None
                    }
                    _ => {
                        if *sel == own.len() {
                            free.handle(key);
                        }
                        None
                    }
                }
            }
            Modal::NewKey {
                focus,
                name,
                comment,
            } => match key.code {
                KeyCode::Esc => Some(Act::Close),
                KeyCode::Enter => Some(Act::MakeKey {
                    name: name.text.clone(),
                    comment: comment.text.clone(),
                }),
                KeyCode::Tab | KeyCode::Down | KeyCode::Up | KeyCode::BackTab => {
                    *focus = 1 - *focus;
                    None
                }
                _ => {
                    if *focus == 0 {
                        name.handle(key);
                    } else {
                        comment.handle(key);
                    }
                    None
                }
            },
            Modal::EditKeyComment { input } => match key.code {
                KeyCode::Esc => Some(Act::Close),
                KeyCode::Enter => Some(Act::SetKeyComment(input.text.clone())),
                _ => {
                    input.handle(key);
                    None
                }
            },
            Modal::ScanHost { input } => match key.code {
                KeyCode::Esc => Some(Act::Close),
                KeyCode::Enter => Some(Act::Scan(input.text.clone())),
                KeyCode::Char('a') if !self.scan_result.is_empty() => Some(Act::AddScanned),
                _ => {
                    input.handle(key);
                    None
                }
            },
            Modal::PinEntry { name, sel } => match key.code {
                KeyCode::Esc => Some(Act::Close),
                KeyCode::Enter => self.source.hosts.get(*sel).map(|h| Act::Pin {
                    alias: h.alias.clone(),
                    name: name.clone(),
                }),
                _ => {
                    if let Some(step) = list_step(key) {
                        *sel = step_index(*sel, step, self.source.hosts.len());
                    }
                    None
                }
            },
        }
    }

    fn perform(&mut self, act: Act) {
        match act {
            Act::Close => {
                self.modal = Modal::None;
                self.proof_rx = None;
            }
            Act::Quit => self.quit = true,
            Act::Reload => {
                self.reload();
                self.modal = Modal::None;
                self.say("changes thrown away; read in again", Level::Ok);
            }
            Act::Write(rendered) => self.apply_save(&rendered),
            Act::ApplyEdit(field, value) => self.apply_field_edit(field, value),
            Act::SetKey(choice) => {
                if let Some(host) = self.source.hosts.get_mut(self.selected) {
                    host.key = choice;
                    self.touched();
                }
                self.modal = Modal::None;
            }
            Act::AddHost {
                alias,
                hostname,
                user,
                generate,
                existing,
            } => self.add_host(&alias, &hostname, &user, generate, existing),
            Act::AddOption(line) => self.add_option(line),
            Act::SetHop { hop, append } => self.set_hop(&hop, append),
            Act::MakeKey { name, comment } => self.make_key(&name, &comment),
            Act::DeleteKey(name) => self.delete_key(&name),
            Act::SetKeyComment(comment) => self.set_key_comment(&comment),
            Act::Forget(name) => self.forget_entry(&name),
            Act::Scan(input) => self.scan(&input),
            Act::AddScanned => self.add_scanned(),
            Act::Pin { alias, name } => self.pin_host_key(&alias, &name),
        }
    }
}

/// j/k and the arrow keys, as one notion.
fn list_step(key: &KeyEvent) -> Option<isize> {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => Some(-1),
        KeyCode::Down | KeyCode::Char('j') => Some(1),
        _ => None,
    }
}

fn step_index(current: usize, step: isize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    current
        .saturating_add_signed(step)
        .min(len.saturating_sub(1))
}

/// For the default comment in a new key: who made it where.
fn machine_name() -> String {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this-machine".to_string())
}

/// The same gate as the GUI and the CLI: the rewrite must be proven, and an
/// unproved answer is not a pass.
fn save_blocked(outcome: &Option<proof::SaveJudgement>) -> Option<&'static str> {
    match outcome {
        None => None,
        Some(o) => match (&o.rewrite, &o.edits) {
            (proof::Verdict::Changed(_), _) => Some("The rewrite itself would change behaviour."),
            (proof::Verdict::Unknown(_), _) => {
                Some("ssh could not be asked, so nothing was proved.")
            }
            (_, Some(proof::Verdict::Unknown(_))) => {
                Some("What your edits change could not be proved.")
            }
            _ => None,
        },
    }
}

// ----------------------------------------------------------------------
// Rendering
// ----------------------------------------------------------------------

fn colour(level: Level) -> Color {
    match level {
        Level::Ok => Color::Green,
        Level::Warn => Color::Yellow,
        Level::Fail => Color::Red,
    }
}

fn dot(level: Option<Level>) -> Span<'static> {
    match level {
        Some(l) => Span::styled("●", Style::new().fg(colour(l))),
        None => Span::styled("○", Style::new().fg(Color::DarkGray)),
    }
}

fn dim(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::new().fg(Color::DarkGray))
}

fn warn_span(text: impl Into<String>) -> Span<'static> {
    Span::styled(text.into(), Style::new().fg(Color::Yellow))
}

fn header(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        text.to_string(),
        Style::new().add_modifier(Modifier::BOLD).fg(Color::Cyan),
    ))
}

fn ui(f: &mut Frame, app: &App) {
    let mut rows = vec![
        Constraint::Length(1), // title
        Constraint::Length(1), // tabs
    ];
    let unreadable_rows = if app.unreadable.is_some() { 2 } else { 0 };
    let losses_rows = if app.banner_losses() == 0 { 0 } else { 1 };
    rows.push(Constraint::Length(unreadable_rows));
    rows.push(Constraint::Length(losses_rows));
    rows.push(Constraint::Min(6)); // main
    rows.push(Constraint::Length(8)); // findings
    rows.push(Constraint::Length(1)); // toast
    rows.push(Constraint::Length(1)); // key bar
    let areas = Layout::vertical(rows).split(f.area());

    // Title line.
    let mut title = vec![Span::styled(
        "sshctl",
        Style::new().add_modifier(Modifier::BOLD),
    )];
    if app.checking {
        title.push(dim("  checking…"));
    }
    if app.dirty {
        title.push(Span::styled(
            "  ● not saved",
            Style::new().fg(Color::Yellow),
        ));
    }
    title.push(dim(format!("   {}", ssh_config_path().display())));
    f.render_widget(Paragraph::new(Line::from(title)), areas[0]);

    let titles: Vec<Line> = TABS
        .iter()
        .map(|t| Line::from(format!(" {} ", t.title())))
        .collect();
    let tab_index = TABS.iter().position(|t| *t == app.tab).unwrap_or(0);
    f.render_widget(
        Tabs::new(titles)
            .select(tab_index)
            .highlight_style(Style::new().add_modifier(Modifier::BOLD).bg(Color::Blue)),
        areas[1],
    );

    if let Some(why) = &app.unreadable {
        f.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    "Your config is there, but sshctl cannot read it. Saving is off.",
                    Style::new().fg(Color::Red),
                )),
                Line::from(dim(why.clone())),
            ]),
            areas[2],
        );
    }
    if app.banner_losses() > 0 {
        f.render_widget(
            Paragraph::new(Line::from(warn_span(format!(
                "{} line(s) will not survive a rewrite — press S to see them",
                app.banner_losses()
            )))),
            areas[3],
        );
    }

    let main = areas[4];
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Length(30), Constraint::Min(20)]).areas(main);
    render_list(f, app, list_area);
    render_detail(f, app, detail_area);

    render_findings(f, app, areas[5]);

    if let Some((msg, level)) = &app.toast {
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                msg.clone(),
                Style::new().fg(colour(*level)),
            ))),
            areas[6],
        );
    }
    f.render_widget(Paragraph::new(Line::from(dim(key_bar(app)))), areas[7]);

    render_modal(f, app);
}

fn key_bar(app: &App) -> String {
    if !matches!(app.modal, Modal::None) {
        return match &app.modal {
            Modal::Save { outcome, .. } => match save_blocked(outcome) {
                _ if outcome.is_none() => "esc cancel".to_string(),
                None => "w write · esc cancel".to_string(),
                Some(_) => "f arm override · w write anyway · esc cancel".to_string(),
            },
            Modal::ScanHost { .. } => "enter fetch · a add to known_hosts · esc close".to_string(),
            Modal::PickHop { .. } => "enter pick · ctrl-a toggle append · esc close".to_string(),
            Modal::AddHost { .. } => {
                "tab next field · space toggle key · enter add · esc cancel".to_string()
            }
            _ => "enter confirm · esc cancel".to_string(),
        };
    }
    let common = "1-4 tabs · C check · S save · R reload · ? help · q quit";
    match app.tab {
        Tab::Overview => format!("j/k host · {common}"),
        Tab::Config => {
            if app.config_fields_focused {
                format!(
                    "j/k row · enter edit · o option · p hop · x drop option · D remove host · h back · {common}"
                )
            } else {
                format!("j/k host · l fields · a add host · {common}")
            }
        }
        Tab::Keys => format!("j/k key · n new · c comment · H make host · d delete · {common}"),
        Tab::Known => format!("j/k entry · f fetch host · p pin · d remove · {common}"),
    }
}

fn render_list(f: &mut Frame, app: &App, area: Rect) {
    let inner_height = area.height.saturating_sub(2) as usize;
    let (title, lines): (&str, Vec<Line>) = match app.tab {
        Tab::Overview | Tab::Config => {
            let sel = app.selected;
            let lines = windowed(app.source.hosts.len(), sel, inner_height)
                .map(|i| {
                    let h = &app.source.hosts[i];
                    let mut spans = vec![dot(app.level_for(&h.alias)), Span::raw(" ")];
                    let style = if i == sel {
                        Style::new().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::new()
                    };
                    spans.push(Span::styled(h.alias.clone(), style));
                    Line::from(spans)
                })
                .collect();
            ("HOSTS", lines)
        }
        Tab::Keys => {
            let lines = windowed(app.keys.len(), app.key_sel, inner_height)
                .map(|i| {
                    let k = &app.keys[i];
                    let level = if k.is_orphan() {
                        Level::Warn
                    } else {
                        Level::Ok
                    };
                    let style = if i == app.key_sel {
                        Style::new().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::new()
                    };
                    Line::from(vec![
                        dot(Some(level)),
                        Span::raw(" "),
                        Span::styled(k.name.clone(), style),
                    ])
                })
                .collect();
            ("PRIVATE KEYS", lines)
        }
        Tab::Known => {
            let groups = app.ledger.per_name();
            let claimed: Vec<String> = app
                .tree
                .iter()
                .filter(|t| t.host.is_some())
                .flat_map(|t| t.entries.clone())
                .collect();
            let mut lines: Vec<Line> = windowed(groups.len(), app.entry_sel, inner_height)
                .map(|i| {
                    let (name, _) = &groups[i];
                    let level = if claimed.contains(name) {
                        Level::Ok
                    } else {
                        Level::Warn
                    };
                    let style = if i == app.entry_sel {
                        Style::new().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::new()
                    };
                    Line::from(vec![
                        dot(Some(level)),
                        Span::raw(" "),
                        Span::styled(name.clone(), style),
                    ])
                })
                .collect();
            if app.ledger_loading {
                lines.insert(0, Line::from(dim("reading ledger…")));
            }
            ("ENTRIES", lines)
        }
    };
    f.render_widget(
        Paragraph::new(Text::from(lines)).block(Block::bordered().title(title)),
        area,
    );
}

fn render_detail(f: &mut Frame, app: &App, area: Rect) {
    let lines = match app.tab {
        Tab::Overview => overview_lines(app),
        Tab::Config => config_lines(app),
        Tab::Keys => key_lines(app),
        Tab::Known => known_lines(app),
    };
    f.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .block(Block::bordered()),
        area,
    );
}

fn row(label: &str, value: &str, origin: Option<&Origin>) -> Line<'static> {
    let mut spans = vec![
        dim(format!("  {label:<14}")),
        Span::raw(if value.is_empty() {
            "—".to_string()
        } else {
            value.to_string()
        }),
    ];
    if let Some(o) = origin {
        let text = format!("   {}", o.describe());
        if o.is_invisible() {
            spans.push(warn_span(text));
        } else {
            spans.push(dim(text));
        }
    }
    Line::from(spans)
}

fn overview_lines(app: &App) -> Vec<Line<'static>> {
    let Some(host) = app.source.hosts.get(app.selected) else {
        return vec![Line::from(dim("No hosts. Press 2, then a, to add one."))];
    };
    let mut out = vec![
        Line::from(Span::styled(
            host.alias.clone(),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        header("1  WHICH RULES APPLY"),
    ];
    match &app.effective {
        Some(e) if !e.matching_blocks.is_empty() => {
            for b in &e.matching_blocks {
                let mut spans = vec![Span::raw(format!("  Host {}", b.patterns.join(" ")))];
                if b.source_file.starts_with("/etc/") {
                    spans.push(warn_span(format!(
                        "   {} — not in your own file",
                        b.source_file
                    )));
                } else {
                    spans.push(dim(format!("   {}", b.source_file)));
                }
                out.push(Line::from(spans));
            }
        }
        _ => out.push(Line::from(dim(app
            .effective_error
            .clone()
            .unwrap_or_else(|| "(not worked out yet)".to_string())))),
    }
    let value = |kw: &str| {
        app.effective
            .as_ref()
            .and_then(|e| e.get(kw))
            .map(|s| s.value.clone())
            .unwrap_or_default()
    };
    let origin = |kw: &str| {
        app.effective
            .as_ref()
            .and_then(|e| e.get(kw))
            .map(|s| s.origin.clone())
    };
    out.push(Line::default());
    out.push(header("2  WHERE TO"));
    out.push(row(
        "Hostname",
        &value("hostname"),
        origin("hostname").as_ref(),
    ));
    out.push(row("Port", &value("port"), origin("port").as_ref()));
    let jump = value("proxyjump");
    let chain = proxy::parse_chain(&jump);
    if chain.is_empty() {
        out.push(row("Which way", "direct", None));
    } else {
        let mut way = String::from("you");
        for hop in &chain {
            way.push_str(" -> ");
            way.push_str(&hop.label());
        }
        way.push_str(" -> ");
        way.push_str(&host.alias);
        out.push(row("Which way", &way, None));
    }
    out.push(Line::default());
    out.push(header("3  WHO AM I"));
    out.push(row("User", &value("user"), origin("user").as_ref()));
    let key_name = host.key.clone().unwrap_or_default();
    out.push(row("Key", &key_name, origin("identityfile").as_ref()));
    if let Some(k) = app.keys.iter().find(|k| k.name == key_name) {
        if !k.has_public {
            out.push(Line::from(warn_span(
                "  The public half is missing; you cannot authorise it anywhere.",
            )));
        }
    } else if !key_name.is_empty() {
        out.push(Line::from(Span::styled(
            "  That key is not in ~/.ssh.",
            Style::new().fg(Color::Red),
        )));
    } else {
        out.push(Line::from(warn_span(
            "  Without a key ssh offers everything in your agent.",
        )));
    }
    out.push(Line::default());
    out.push(header("4  WHO IS THE DESTINATION"));
    if app.known_types.is_empty() {
        out.push(Line::from(warn_span(
            "  Not in known_hosts — the first connection will ask for trust.",
        )));
    } else {
        out.push(Line::from(vec![
            Span::raw("  "),
            dot(Some(Level::Ok)),
            Span::raw(format!(
                " recognised before: {}",
                app.known_types.join(", ")
            )),
        ]));
    }
    out.push(row("Looked up as", &known::lookup_name_for(host), None));
    out.push(row(
        "Strictness",
        &value("stricthostkeychecking"),
        origin("stricthostkeychecking").as_ref(),
    ));
    if let Some(e) = &app.effective {
        let invisible = e.invisible();
        if !invisible.is_empty() {
            out.push(Line::default());
            out.push(Line::from(warn_span(
                "APPLIES WITHOUT BEING IN YOUR OWN FILE",
            )));
            for s in invisible {
                out.push(Line::from(vec![
                    Span::raw(format!("  {} {}", s.keyword, s.value)),
                    dim(format!("   {}", s.origin.describe())),
                ]));
            }
        }
    }
    out
}

fn config_lines(app: &App) -> Vec<Line<'static>> {
    let Some(host) = app.source.hosts.get(app.selected) else {
        return vec![Line::from(dim("No hosts. Press a to add one."))];
    };
    let mut out = vec![
        Line::from(Span::styled(
            host.alias.clone(),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        Line::default(),
    ];
    for (i, field) in HOST_FIELDS.iter().enumerate() {
        let selected = app.config_fields_focused && app.config_row == i;
        let value = field.current(host);
        let style = if selected {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
        };
        out.push(Line::from(vec![
            dim(format!("  {:<16}", field.label())),
            Span::styled(
                if value.is_empty() {
                    "—".to_string()
                } else {
                    value
                },
                style,
            ),
        ]));
    }
    out.push(Line::default());
    out.push(header("EXTRA SSH OPTIONS"));
    if host.options.is_empty() {
        out.push(Line::from(dim("  none")));
    }
    for (i, o) in host.options.iter().enumerate() {
        let selected = app.config_fields_focused && app.config_row == HOST_FIELDS.len() + i;
        let style = if selected {
            Style::new().add_modifier(Modifier::REVERSED)
        } else {
            Style::new()
        };
        out.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(o.clone(), style),
        ]));
    }
    out.push(Line::default());
    out.push(Line::from(dim(
        "What of this ends up applying, you can see on the overview tab.",
    )));
    out
}

fn key_lines(app: &App) -> Vec<Line<'static>> {
    if app.keys.is_empty() {
        return vec![Line::from(dim(
            "No private keys in ~/.ssh. Press n to make one.",
        ))];
    }
    let Some(d) = &app.key_detail else {
        return vec![Line::from(Span::styled(
            "Could not read this key.",
            Style::new().fg(Color::Red),
        ))];
    };
    let mut out = vec![
        Line::from(Span::styled(
            d.name.clone(),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        Line::from(dim(format!(
            "~/.ssh/{} — the contents are never shown",
            d.name
        ))),
        Line::default(),
        row("Type", &format!("{} ({} bits)", d.key_type, d.bits), None),
        row("Fingerprint", &d.fingerprint, None),
        row("Passphrase", if d.encrypted { "yes" } else { "no" }, None),
    ];
    if d.mode & 0o077 != 0 {
        out.push(Line::from(vec![
            dim("  Permissions   "),
            Span::styled(
                format!("{:o} — ssh refuses anything wider than 600", d.mode),
                Style::new().fg(Color::Red),
            ),
        ]));
    } else {
        out.push(row("Permissions", &format!("{:o}", d.mode), None));
    }
    if d.used_by.is_empty() {
        out.push(Line::from(vec![
            dim("  Used by       "),
            warn_span("no host in this config"),
        ]));
    } else {
        out.push(row("Used by", &d.used_by.join(", "), None));
    }
    out.push(row("Comment", &d.comment, None));
    out.push(Line::default());
    out.push(header("PUBLIC HALF"));
    match &d.public_line {
        Some(line) => {
            if d.public_derived {
                out.push(Line::from(warn_span(
                    "  No .pub file; this line was derived from the private half.",
                )));
            }
            out.push(Line::from(Span::raw(format!("  {line}"))));
        }
        None => out.push(Line::from(Span::styled(
            "  No public half, and it cannot be derived: the key is encrypted.",
            Style::new().fg(Color::Red),
        ))),
    }
    out
}

fn known_lines(app: &App) -> Vec<Line<'static>> {
    let groups = app.ledger.per_name();
    let Some((name, entries)) = groups.get(app.entry_sel) else {
        return vec![Line::from(dim(if app.ledger_loading {
            "Reading the ledger…"
        } else {
            "No entries. Press f to fetch a host key."
        }))];
    };
    let mut out = vec![
        Line::from(Span::styled(
            name.clone(),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        header("STORED KEYS"),
    ];
    for e in entries {
        out.push(Line::from(vec![
            dim(format!("  {:<10}", e.key_type)),
            Span::raw(e.fingerprint.clone()),
        ]));
    }
    if entries.iter().all(|e| e.hashed) {
        out.push(Line::from(warn_span(
            "  The name is stored hashed: it can be tested, not read out.",
        )));
    }
    out.push(Line::default());
    let belongs_to: Vec<String> = app
        .tree
        .iter()
        .filter(|t| t.host.is_some() && t.entries.iter().any(|v| v == name))
        .filter_map(|t| t.host.clone())
        .collect();
    if belongs_to.is_empty() {
        out.push(Line::from(vec![
            dim("  Belongs to    "),
            warn_span("no host in your config"),
        ]));
        out.push(Line::from(dim(
            "  Press p to pin it to a host via HostKeyAlias.",
        )));
    } else {
        out.push(row("Belongs to", &belongs_to.join(", "), None));
    }
    out.push(Line::from(dim(
        "  Lookup happens on the HostName, not on your alias.",
    )));
    out
}

fn render_findings(f: &mut Frame, app: &App, area: Rect) {
    let inner = area.height.saturating_sub(2) as usize;
    let shown: Vec<&Finding> = app
        .findings
        .iter()
        .filter(|x| x.subject != "orphan")
        .collect();
    let end = shown.len().saturating_sub(app.findings_scroll);
    let start = end.saturating_sub(inner);
    let lines: Vec<Line> = shown[start..end]
        .iter()
        .map(|x| {
            Line::from(vec![
                Span::styled(
                    format!("{:<5}", x.level.label().trim()),
                    Style::new().fg(colour(x.level)),
                ),
                Span::styled(
                    format!("{:<14}", x.subject),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
                Span::raw(x.message.clone()),
            ])
        })
        .collect();
    let title = format!(
        "FINDINGS ({}){}",
        shown.len(),
        if app.checking { " · checking…" } else { "" }
    );
    f.render_widget(
        Paragraph::new(Text::from(lines)).block(Block::bordered().title(title)),
        area,
    );
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn modal_box(f: &mut Frame, title: &str, lines: Vec<Line<'static>>, width: u16) {
    let height = (lines.len() as u16 + 2).min(f.area().height);
    let area = centered(f.area(), width, height);
    f.render_widget(Clear, area);
    f.render_widget(
        Paragraph::new(Text::from(lines))
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(title.to_string())),
        area,
    );
}

fn render_modal(f: &mut Frame, app: &App) {
    match &app.modal {
        Modal::None => {}
        Modal::Help => {
            let lines = vec![
                Line::from("The first tab is for looking, the other three change things."),
                Line::default(),
                Line::from("1-4 or tab   switch tab"),
                Line::from("j/k, arrows  move through lists"),
                Line::from("C            check everything again"),
                Line::from("S            save — shows what changes, proves it with ssh -G"),
                Line::from("R            reload from disk (asks first when unsaved)"),
                Line::from("pgup/pgdn    scroll the findings"),
                Line::from("q            quit"),
                Line::default(),
                Line::from(dim("Copy with your terminal's own selection; nothing here")),
                Line::from(dim("touches the clipboard.")),
            ];
            modal_box(f, "help", lines, 68);
        }
        Modal::ConfirmQuit => {
            modal_box(
                f,
                "quit?",
                vec![
                    Line::from("Your unsaved changes disappear."),
                    Line::from(dim("y quit · esc stay")),
                ],
                44,
            );
        }
        Modal::ConfirmReload => {
            modal_box(
                f,
                "throw changes away?",
                vec![
                    Line::from("Unsaved changes disappear and ~/.ssh/config is read again."),
                    Line::from(dim("y reload · esc keep")),
                ],
                60,
            );
        }
        Modal::ConfirmDeleteKey(name) => {
            let users: Vec<String> = app
                .source
                .hosts
                .iter()
                .filter(|h| h.key.as_deref() == Some(name.as_str()))
                .map(|h| h.alias.clone())
                .collect();
            let mut lines = vec![Line::from(format!("Key: {name}"))];
            if users.is_empty() {
                lines.push(Line::from(dim("No host in this config uses it.")));
            } else {
                lines.push(Line::from(Span::styled(
                    format!(
                        "Used by: {}. That host can then no longer log in.",
                        users.join(", ")
                    ),
                    Style::new().fg(Color::Red),
                )));
            }
            lines.push(Line::from(warn_span(
                "sshctl only sees this config; the key may be in use elsewhere.",
            )));
            lines.push(Line::from(dim(
                "It is not erased but moved to ~/.ssh/deleted/.",
            )));
            lines.push(Line::from(dim("y move · esc cancel")));
            modal_box(f, "delete key?", lines, 66);
        }
        Modal::ConfirmForget(name) => {
            let count = app
                .ledger
                .entries
                .iter()
                .filter(|e| &e.label() == name)
                .count();
            let belongs_to: Vec<String> = app
                .tree
                .iter()
                .filter(|t| t.host.is_some() && t.entries.contains(name))
                .filter_map(|t| t.host.clone())
                .collect();
            let mut lines = vec![Line::from(format!("{name} — {count} line(s) will go."))];
            if belongs_to.is_empty() {
                lines.push(Line::from(dim("No host in your config points at this.")));
            } else {
                lines.push(Line::from(warn_span(format!(
                    "Careful: {} relies on this trust.",
                    belongs_to.join(", ")
                ))));
            }
            lines.push(Line::from(dim(
                "A backup lands alongside as known_hosts.before-sshctl.",
            )));
            lines.push(Line::from(dim("y remove · esc cancel")));
            modal_box(f, "remove entry from known_hosts?", lines, 64);
        }
        Modal::Save {
            removed,
            added,
            disk_changed,
            outcome,
            lost_comments,
            losses,
            armed,
            ..
        } => {
            let mut lines = Vec::new();
            if *disk_changed {
                lines.push(Line::from(Span::styled(
                    "Careful: ~/.ssh/config changed since you opened it. Saving overwrites that.",
                    Style::new().fg(Color::Red),
                )));
            }
            match outcome {
                None => lines.push(Line::from(dim("Asking ssh whether anything changes…"))),
                Some(o) => {
                    match &o.rewrite {
                        proof::Verdict::Same { probed: 0 } => lines.push(Line::from(Span::styled(
                            "The file on disk is already in tidied form.",
                            Style::new().fg(Color::Green),
                        ))),
                        proof::Verdict::Same { probed } => lines.push(Line::from(Span::styled(
                            format!(
                                "Checked with ssh: the rewrite itself changes nothing, for all {probed} names asked."
                            ),
                            Style::new().fg(Color::Green),
                        ))),
                        proof::Verdict::Changed(diffs) => {
                            lines.push(Line::from(Span::styled(
                                "The rewrite itself would change behaviour — beyond what your edits ask:",
                                Style::new().fg(Color::Red),
                            )));
                            for d in diffs.iter().take(6) {
                                lines.push(Line::from(Span::raw(format!("  {}", d.describe()))));
                            }
                        }
                        proof::Verdict::Unknown(why) => {
                            lines.push(Line::from(warn_span(format!(
                                "Could not check this with ssh: {why}"
                            ))));
                            for loss in losses.iter().take(4) {
                                lines.push(Line::from(Span::raw(format!("  {}", loss.line))));
                            }
                        }
                    }
                    match &o.edits {
                        None => {}
                        Some(proof::Verdict::Same { .. }) => lines.push(Line::from(dim(
                            "Your edits change nothing about any connection.",
                        ))),
                        Some(proof::Verdict::Changed(diffs)) => {
                            lines.push(Line::from(Span::styled(
                                "Your edits change:",
                                Style::new().add_modifier(Modifier::BOLD),
                            )));
                            for d in diffs.iter().take(8) {
                                lines.push(Line::from(Span::raw(format!("  {}", d.describe()))));
                            }
                            if diffs.len() > 8 {
                                lines.push(Line::from(dim(format!(
                                    "  and {} more",
                                    diffs.len() - 8
                                ))));
                            }
                        }
                        Some(proof::Verdict::Unknown(why)) => lines.push(Line::from(warn_span(
                            format!("What your edits change could not be proved: {why}"),
                        ))),
                    }
                }
            }
            for comment in lost_comments {
                lines.push(Line::from(dim(format!(
                    "The comment \"{comment}\" disappears."
                ))));
            }
            lines.push(Line::from(dim(format!(
                "{} lines added · {} lines removed · a backup lands alongside",
                added.len(),
                removed.len()
            ))));
            for line in removed.iter().take(6) {
                lines.push(Line::from(Span::styled(
                    format!("- {line}"),
                    Style::new().fg(Color::Red),
                )));
            }
            for line in added.iter().take(6) {
                lines.push(Line::from(Span::styled(
                    format!("+ {line}"),
                    Style::new().fg(Color::Green),
                )));
            }
            if removed.len() > 6 || added.len() > 6 {
                lines.push(Line::from(dim("  (long diff shortened)")));
            }
            if save_blocked(outcome).is_some() {
                lines.push(Line::from(warn_span(if *armed {
                    "[x] I know — write anyway (press w)"
                } else {
                    "[ ] I know — write anyway (press f to arm)"
                })));
            }
            modal_box(f, "save to ~/.ssh/config", lines, 76);
        }
        Modal::EditField { field, input } => {
            let lines = vec![
                input.line(field.label(), true),
                Line::from(dim("enter apply · esc cancel")),
            ];
            modal_box(f, "edit", lines, 60);
        }
        Modal::PickKey { sel } => {
            let mut lines = Vec::new();
            let style = |on: bool| {
                if on {
                    Style::new().add_modifier(Modifier::REVERSED)
                } else {
                    Style::new()
                }
            };
            lines.push(Line::from(Span::styled("(none)", style(*sel == 0))));
            for (i, k) in app.keys.iter().enumerate() {
                lines.push(Line::from(Span::styled(
                    k.name.clone(),
                    style(*sel == i + 1),
                )));
            }
            lines.push(Line::from(dim("enter pick · esc cancel")));
            modal_box(f, "key", lines, 46);
        }
        Modal::AddHost {
            focus,
            alias,
            hostname,
            user,
            generate,
            existing_key,
        } => {
            let mut lines = vec![
                alias.line("Alias", *focus == 0),
                hostname.line("Hostname", *focus == 1),
                user.line("User", *focus == 2),
            ];
            match existing_key {
                Some(name) => lines.push(Line::from(vec![
                    dim("Key        "),
                    Span::raw(name.clone()),
                    dim("  (this existing key gets attached)"),
                ])),
                None => lines.push(Line::from(Span::styled(
                    format!(
                        "[{}] create key id_ed25519_{} right away",
                        if *generate { "x" } else { " " },
                        alias.text.trim()
                    ),
                    if *focus == 3 {
                        Style::new().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::new()
                    },
                ))),
            }
            lines.push(Line::from(dim(
                "tab field · space toggle · enter add · esc cancel",
            )));
            modal_box(f, "add host", lines, 64);
        }
        Modal::PickOption { search, sel, stage } => match stage {
            OptStage::Search => {
                let hits = sshctl::catalog::search(&search.text);
                let mut lines = vec![
                    search.line("Search", true),
                    Line::from(dim("by name, or by what you want to achieve")),
                    Line::default(),
                ];
                for (i, o) in hits.iter().take(12).enumerate() {
                    let style = if i == *sel {
                        Style::new().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::new()
                    };
                    lines.push(Line::from(vec![
                        Span::styled(format!("{:<26}", o.keyword), style),
                        dim(o.explanation),
                    ]));
                }
                if hits.is_empty() {
                    lines.push(Line::from(dim(
                        "Nothing found. Anything else can go in the file by hand; it is kept.",
                    )));
                }
                lines.push(Line::from(dim("up/down pick · enter choose · esc close")));
                modal_box(f, "add option", lines, 78);
            }
            OptStage::Value {
                spec,
                value,
                choice,
            } => {
                let mut lines = vec![
                    Line::from(Span::styled(
                        spec.keyword,
                        Style::new().add_modifier(Modifier::BOLD),
                    )),
                    Line::from(dim(spec.explanation)),
                    Line::default(),
                ];
                if spec.choices.is_empty() {
                    lines.push(value.line("Value", true));
                } else {
                    for (i, c) in spec.choices.iter().enumerate() {
                        let style = if i == *choice {
                            Style::new().add_modifier(Modifier::REVERSED)
                        } else {
                            Style::new()
                        };
                        lines.push(Line::from(Span::styled(*c, style)));
                    }
                }
                lines.push(Line::from(dim("enter add · esc back")));
                modal_box(f, "value", lines, 64);
            }
        },
        Modal::PickHop { sel, free, append } => {
            let own: Vec<String> = app
                .source
                .hosts
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != app.selected)
                .map(|(_, h)| h.alias.clone())
                .collect();
            let mut lines = vec![Line::from(dim(
                "An alias gets its own user and key; the destination's do not apply here.",
            ))];
            for (i, alias) in own.iter().enumerate() {
                let style = if i == *sel {
                    Style::new().add_modifier(Modifier::REVERSED)
                } else {
                    Style::new()
                };
                lines.push(Line::from(Span::styled(alias.clone(), style)));
            }
            lines.push(free.line("Type it", *sel == own.len()));
            lines.push(Line::from(dim(format!(
                "[{}] append to the existing chain (ctrl-a)",
                if *append { "x" } else { " " }
            ))));
            lines.push(Line::from(dim("enter pick · esc close")));
            modal_box(f, "pick a hop", lines, 60);
        }
        Modal::NewKey {
            focus,
            name,
            comment,
        } => {
            let becomes = keys::filename_for(&name.text);
            let mut lines = vec![
                name.line("Name", *focus == 0),
                comment.line("Comment", *focus == 1),
            ];
            match becomes {
                Ok(n) => lines.push(Line::from(dim(format!("becomes: ~/.ssh/{n}")))),
                Err(e) => lines.push(Line::from(Span::styled(e, Style::new().fg(Color::Red)))),
            }
            lines.push(Line::from(dim(
                "ed25519, without a passphrase — add one later with ssh-keygen -p",
            )));
            lines.push(Line::from(dim("tab field · enter create · esc cancel")));
            modal_box(f, "new key", lines, 64);
        }
        Modal::KeyMade { name, detail } => {
            let mut lines = vec![Line::from(vec![
                dot(Some(Level::Ok)),
                Span::raw(format!(" ~/.ssh/{name}")),
            ])];
            if let Some(d) = detail {
                lines.push(Line::from(dim(d.fingerprint.clone())));
                if let Some(public) = &d.public_line {
                    lines.push(Line::default());
                    lines.push(header("PUBLIC HALF"));
                    lines.push(Line::from(Span::raw(public.clone())));
                }
            }
            lines.push(Line::default());
            lines.push(Line::from(dim(
                "1. Put the public half in authorized_keys on the target machine.",
            )));
            lines.push(Line::from(dim("2. Attach it to a host on the config tab.")));
            lines.push(Line::from(dim("enter close")));
            modal_box(f, "key created", lines, 76);
        }
        Modal::EditKeyComment { input } => {
            let lines = vec![
                input.line("Comment", true),
                Line::from(dim(
                    "Changes only this file; copies in authorized_keys keep theirs.",
                )),
                Line::from(dim("enter apply · esc cancel")),
            ];
            modal_box(f, "key comment", lines, 66);
        }
        Modal::ScanHost { input } => {
            let mut lines = vec![
                input.line("Host", true),
                Line::from(warn_span(
                    "This is not a check: you get the key of whoever answers.",
                )),
            ];
            if !app.scan_result.is_empty() {
                lines.push(Line::default());
                lines.push(header("FOUND"));
                for s in &app.scan_result {
                    lines.push(Line::from(vec![
                        Span::raw(format!("{}  {}", s.name, s.kind)),
                        dim(format!("  {}", s.fingerprint)),
                    ]));
                }
                if let Some(target) = &app.scan_target {
                    lines.push(Line::from(dim(format!(
                        "will be added to {}",
                        target.display()
                    ))));
                }
            }
            lines.push(Line::from(dim("enter fetch · a add · esc close")));
            modal_box(f, "fetch host key (host or host:2222)", lines, 76);
        }
        Modal::PinEntry { name, sel } => {
            let mut lines = vec![Line::from(dim(format!(
                "Sets HostKeyAlias, so the host looks up under '{name}'."
            )))];
            for (i, h) in app.source.hosts.iter().enumerate() {
                let style = if i == *sel {
                    Style::new().add_modifier(Modifier::REVERSED)
                } else {
                    Style::new()
                };
                lines.push(Line::from(Span::styled(h.alias.clone(), style)));
            }
            lines.push(Line::from(dim("enter pin · esc cancel")));
            modal_box(f, "pin to a host", lines, 56);
        }
    }
}

/// A window of indices around the selection that fits the given height.
fn windowed(len: usize, selected: usize, height: usize) -> std::ops::Range<usize> {
    if height == 0 || len == 0 {
        return 0..0;
    }
    let start = selected
        .saturating_sub(height / 2)
        .min(len.saturating_sub(height));
    start..(start + height).min(len)
}
