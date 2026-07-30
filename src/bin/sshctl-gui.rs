//! Graphical shell on the same core as the CLI.
//!
//! Four things determine the shape:
//!   * `~/.ssh/config` is the single source of truth. It gets read on opening
//!     and written back on saving. There is no second file.
//!   * The round-trip check runs the moment the file is opened: what a rewrite
//!     would not survive is something you know before you start editing.
//!   * Checks take seconds per dead host, so they run in a separate thread and
//!     trickle in. The window never freezes.
//!   * The working copy on disk is a snapshot to look at. It gets wiped both
//!     on startup and on exit, so the question of which of the two is the
//!     right one never arises.

use eframe::egui;
use sshctl::catalog;
use sshctl::doctor::{self, Finding, Level};
use sshctl::effective::{self, Effective, Origin};
use sshctl::fidelity::{self, Loss};
use sshctl::generate;
use sshctl::keys::{self, KeyEntry};
use sshctl::known;
use sshctl::model::{self, Host, Source, ssh_config_path};
use sshctl::proof;
use sshctl::proxy;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

fn main() -> eframe::Result<()> {
    // Never start with leftovers from a previous session.
    model::wipe_work_files();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 780.0])
            .with_min_inner_size([840.0, 520.0])
            .with_title("sshctl"),
        ..Default::default()
    };
    eframe::run_native("sshctl", options, Box::new(|_cc| Ok(Box::new(App::new()))))
}

/// The four tabs. One to look at, three to change things in — that separation
/// makes sure the same information is never edited in two places.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Overview,
    Config,
    Keys,
    KnownHosts,
}

impl Tab {
    fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Config => "config",
            Tab::Keys => "keys",
            Tab::KnownHosts => "known_hosts",
        }
    }
}

/// What comes out of the checking thread.
enum Msg {
    Found(Finding),
    Done,
}

enum Modal {
    None,
    /// Preview of what would go into ~/.ssh/config.
    Save {
        rendered: String,
        removed: Vec<String>,
        added: Vec<String>,
        /// Someone has changed the file since we opened it.
        disk_changed: bool,
        /// What ssh itself says about the rewrite. This, and not the line
        /// count, decides whether saving is allowed.
        verdict: proof::Verdict,
        /// Comments that go away. Nothing breaks, but you should know.
        lost_comments: Vec<String>,
    },
    AddHost,
    /// Sure you want to throw your changes away?
    ConfirmReload,
    /// Sure this entry may leave known_hosts?
    ConfirmForget(String),
    /// Create a new key.
    NewKey,
    /// Sure this key may go?
    ConfirmDeleteKey(String),
    /// A freshly made key: show the public half so it can be authorised.
    KeyMade(String),
    /// Fetch a host key to add to known_hosts.
    ScanHost,
    /// Pick an extra ssh option from the catalog.
    PickOption,
    /// Pick a hop for ProxyJump.
    PickHop,
}

struct App {
    /// The text as it stood on disk when we opened it. Needed to see whether
    /// anything changed behind our back.
    original: String,
    source: Source,
    /// What a rewrite would not survive.
    losses: Vec<Loss>,
    /// What really applies to the selected host, according to ssh itself.
    /// Recomputed on a different selection and after saving — not every frame,
    /// because it starts a process.
    effective: Option<Effective>,
    effective_for: Option<String>,
    effective_error: Option<String>,
    /// What the ledger knows about this host: which key types you have ever
    /// recognised. Empty means: never connected.
    known_types: Vec<String>,
    /// The ledger as it currently stands on disk, plus which entries are
    /// claimed by a host from your config.
    ledger: known::Ledger,
    /// The tree: every host with the evidence below it, and at the end
    /// whatever belongs nowhere.
    tree: Vec<known::Branch>,
    /// All keys in ~/.ssh, with who uses them. Kept around instead of re-read
    /// every frame: this touches the disk.
    keys: Vec<KeyEntry>,

    dirty: bool,
    selected: Option<usize>,

    findings: Vec<Finding>,
    checking: bool,
    rx: Option<Receiver<Msg>>,
    timeout_secs: u64,

    modal: Modal,
    toast: Option<(String, Level)>,
    started: bool,
    tab: Tab,
    /// Which key and which ledger entry are selected in their own tab.
    selected_key: Option<String>,
    selected_entry: Option<String>,
    /// Editable comment field of the selected key.
    key_comment: String,

    // Fields of the "add host" screen.
    new_alias: String,
    new_hostname: String,
    new_user: String,
    new_generate_key: bool,
    /// An existing key we attach to the new host. If this is None, a new key
    /// is to be created.
    new_existing_key: Option<String>,
    /// Fields of the "new key" screen.
    keyname: String,
    keycomment: String,
    /// Result of an ssh-keyscan, waiting for confirmation.
    scan_result: Vec<(String, String, String)>,
    /// Which host a loose entry gets pinned to.
    pin_alias: Option<String>,
    /// Fields of the option picker.
    option_search: String,
    option_selected: Option<&'static catalog::OptionSpec>,
    option_value: String,
    /// Free-form input and pick behaviour of the hop picker.
    hop_freeform: String,
    hop_append: bool,
    /// Explicit confirmation to write even though lines would be lost.
    force_write: bool,
    /// Set when ~/.ssh/config is there but unreadable. Then the window would
    /// otherwise show an empty config, and saving would replace a file nobody
    /// has seen.
    unreadable: Option<String>,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            original: String::new(),
            source: Source::default(),
            losses: Vec::new(),
            keys: Vec::new(),
            effective: None,
            effective_for: None,
            effective_error: None,
            known_types: Vec::new(),
            ledger: known::Ledger::default(),
            tree: Vec::new(),
            dirty: false,
            selected: None,
            findings: Vec::new(),
            checking: false,
            rx: None,
            timeout_secs: 5,
            modal: Modal::None,
            toast: None,
            started: false,
            tab: Tab::Overview,
            selected_key: None,
            selected_entry: None,
            key_comment: String::new(),
            new_alias: String::new(),
            new_hostname: String::new(),
            new_user: String::new(),
            new_generate_key: true,
            new_existing_key: None,
            keyname: String::new(),
            keycomment: String::new(),
            scan_result: Vec::new(),
            pin_alias: None,
            option_search: String::new(),
            option_selected: None,
            option_value: String::new(),
            hop_freeform: String::new(),
            hop_append: false,
            force_write: false,
            unreadable: None,
        };
        app.reload();
        app
    }

    /// Reads ~/.ssh/config in again. Throws away unsaved work, so only call it
    /// on opening or on an explicit request.
    fn reload(&mut self) {
        let opened = sshctl::open();
        let (original, source) = (opened.original, opened.source);
        self.unreadable = opened.unreadable;
        self.losses = fidelity::check(&original, &source);
        self.original = original;
        self.source = source;
        self.dirty = false;
        // Show the first host straight away: opening on an empty panel is a
        // wasted screen, and the stage-by-stage view is exactly what you want
        // to see.
        self.selected = (!self.source.hosts.is_empty()).then_some(0);
        self.keys = keys::inventory(&self.source);
        self.refresh_ledger();
        self.source.write_work_copy();
    }

    /// Reads the ledger in. Which files those are, it asks ssh: next to
    /// known_hosts there is often a known_hosts.old with revoked keys, and
    /// that must never slip in.
    fn refresh_ledger(&mut self) {
        // Every host, not just the first: UserKnownHostsFile can be set per
        // host, and judging one host by another's ledger makes it look like a
        // machine you have visited a hundred times is suddenly unknown.
        let files = known::files_for_all(&self.source);
        if files.is_empty() {
            self.ledger = known::Ledger::default();
            self.tree.clear();
            return;
        }
        self.ledger = known::Ledger::load(&files);
        let per_host = known::lookup_per_host(&self.source, &files);
        self.tree = known::tree(&per_host, &self.ledger);
    }

    /// Asks ssh what applies to the selected host. Costs ~7 ms, so this is
    /// fine inside the draw loop as long as it does not happen every frame.
    fn refresh_effective(&mut self) {
        let Some(alias) = self
            .selected
            .and_then(|i| self.source.hosts.get(i))
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
                // Which files apply? Out of ssh itself, so that a
                // known_hosts.old with revoked keys cannot slip in.
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

    fn say(&mut self, message: impl Into<String>, level: Level) {
        self.toast = Some((message.into(), level));
    }

    /// Marks an edit and refreshes the snapshot on disk.
    fn touched(&mut self) {
        self.dirty = true;
        self.keys = keys::inventory(&self.source);
        // Deliberately NOT re-reading the ledger: an edit does not change it,
        // and it starts two processes.
        self.source.write_work_copy();
    }

    /// Sets `HostKeyAlias` on a host, so that ssh looks the trust up under
    /// *that* name instead of under the address.
    ///
    /// This is the only safe way to tie a host and an entry together. Changing
    /// the hostname would change the destination, and rewriting known_hosts
    /// would claim that a key belongs to a name without anything confirming
    /// it.
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
    }

    /// Prepares a new host around an unused key.
    ///
    /// Deliberately does *not* create a host straight away: we do not know the
    /// hostname, and inventing one produced nonsense like `Host server` with
    /// `HostName server` — an address pointing nowhere. So we ask for it.
    fn adopt_key(&mut self, key: &KeyEntry) {
        self.new_alias = key.suggested_alias();
        self.new_hostname.clear();
        self.new_user.clear();
        self.new_existing_key = Some(key.name.clone());
        self.new_generate_key = false;
        self.modal = Modal::AddHost;
    }

    /// Starts the checks in a separate thread. The model is copied so the user
    /// can simply keep editing in the meantime.
    fn start_check(&mut self, ctx: &egui::Context) {
        let copy = self.source.clone();
        let original = self.original.clone();
        let opts = doctor::Options {
            offline: false,
            connect_timeout: Duration::from_secs(self.timeout_secs),
            only: None,
        };

        let (tx, rx): (Sender<Msg>, Receiver<Msg>) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            doctor::run_streaming(&copy, &original, &opts, &mut |f| {
                // Sending fails if the window has closed in the meantime; then
                // carrying on is pointless, but so is panicking.
                let _ = tx.send(Msg::Found(f));
                ctx.request_repaint();
            });
            let _ = tx.send(Msg::Done);
            ctx.request_repaint();
        });

        self.findings.clear();
        self.checking = true;
        self.rx = Some(rx);
    }

    fn drain(&mut self) {
        let Some(rx) = &self.rx else { return };
        let mut done = false;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                Msg::Found(f) => self.findings.push(f),
                Msg::Done => done = true,
            }
        }
        if done {
            self.checking = false;
            self.rx = None;
        }
    }

    fn open_save_preview(&mut self) {
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

        // The gate: not "does every line survive" but "does ssh still do the
        // same thing". Costs a handful of `ssh -G` calls and is the only
        // answer worth anything.
        let verdict = proof::compare(&on_disk, &rendered, &self.source);
        let lost_comments = proof::lost_comments(&on_disk, &rendered);

        self.modal = Modal::Save {
            rendered,
            removed,
            added,
            disk_changed,
            verdict,
            lost_comments,
        };
    }

    fn apply_save(&mut self, rendered: &str) {
        self.force_write = false;
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
                self.effective_for = None; // forces a recomputation
                self.refresh_ledger();
                self.say("~/.ssh/config updated (backup alongside)", Level::Ok);
            }
            Err(e) => self.say(format!("writing failed: {e}"), Level::Fail),
        }
        self.modal = Modal::None;
    }

    fn add_host(&mut self) {
        let alias = self.new_alias.trim().to_string();
        if alias.is_empty() {
            self.say("alias must not be empty", Level::Fail);
            return;
        }
        // Without a hostname the block yields an address that goes nowhere.
        if self.new_hostname.trim().is_empty() {
            self.say("hostname must not be empty", Level::Fail);
            return;
        }
        if self.source.hosts.iter().any(|h| h.alias == alias) {
            self.say(format!("alias '{alias}' already exists"), Level::Fail);
            return;
        }

        // Attach an existing key, or make a new one following the same naming
        // rule as in the CLI.
        let key_name = self
            .new_existing_key
            .clone()
            .unwrap_or_else(|| format!("id_ed25519_{alias}"));
        let key_path = model::ssh_dir().join(&key_name);
        if self.new_generate_key {
            if key_path.exists() {
                self.say(
                    format!("{} already exists", key_path.display()),
                    Level::Fail,
                );
                return;
            }
            let status = std::process::Command::new("ssh-keygen")
                .args(["-t", "ed25519", "-N", "", "-C", &format!("sshctl-{alias}")])
                .arg("-f")
                .arg(&key_path)
                .status();
            match status {
                Ok(s) if s.success() => {}
                _ => {
                    self.say("ssh-keygen failed", Level::Fail);
                    return;
                }
            }
        }

        self.source.hosts.push(Host {
            alias: alias.clone(),
            hostname: self.new_hostname.trim().to_string(),
            // The user typed it in, so it belongs in the file.
            hostname_explicit: true,
            user: self.new_user.trim().to_string(),
            key: key_path.exists().then_some(key_name),
            ..Default::default()
        });
        self.selected = Some(self.source.hosts.len() - 1);
        self.modal = Modal::None;
        self.new_alias.clear();
        self.new_hostname.clear();
        self.new_user.clear();
        self.new_existing_key = None;
        self.touched();
        self.say(format!("'{alias}' added — not saved yet"), Level::Ok);
    }

    /// The worst verdict per host, so a dot can be coloured.
    fn level_for(&self, alias: &str) -> Option<Level> {
        self.findings
            .iter()
            .filter(|f| f.subject == alias)
            .map(|f| f.level)
            .max()
    }
}

/// Draws the status dot. Deliberately painted rather than set as a character:
/// ● and ○ are missing from the default font and turn into empty boxes.
fn status_dot(ui: &mut egui::Ui, level: Option<Level>) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
    let centre = rect.center();
    match level {
        Some(l) => {
            ui.painter().circle_filled(centre, 4.5, colour(l));
        }
        None => {
            ui.painter().circle_stroke(
                centre,
                4.0,
                egui::Stroke::new(1.0, ui.visuals().weak_text_color()),
            );
        }
    }
}

/// For the default comment in a new key: who made it where.
fn machine_name() -> String {
    std::process::Command::new("hostname")
        .arg("-s")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this-mac".to_string())
}

fn colour(level: Level) -> egui::Color32 {
    match level {
        Level::Ok => egui::Color32::from_rgb(0x4c, 0xaf, 0x50),
        Level::Warn => egui::Color32::from_rgb(0xe0, 0xa0, 0x30),
        Level::Fail => egui::Color32::from_rgb(0xe0, 0x5a, 0x4a),
    }
}

impl eframe::App for App {
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Leave nothing behind between sessions.
        model::wipe_work_files();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain();
        let ctx = ui.ctx().clone();
        let ctx = &ctx;

        if !self.started {
            self.started = true;
            self.start_check(ctx);
        }

        // Only recompute if the selection really changed; `ssh -G` starts a
        // process and does not belong in every frame.
        let selected = self
            .selected
            .and_then(|i| self.source.hosts.get(i))
            .map(|h| h.alias.clone());
        if selected != self.effective_for {
            self.refresh_effective();
        }

        egui::Panel::top("bar").show(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("sshctl");
                ui.separator();

                if ui
                    .add_enabled(!self.checking, egui::Button::new("Check everything"))
                    .clicked()
                {
                    self.start_check(ctx);
                }
                if self.checking {
                    ui.spinner();
                    ui.label("working…");
                }

                let may_save = self.unreadable.is_none();
                if ui
                    .add_enabled(may_save, egui::Button::new("Save…"))
                    .on_disabled_hover_text(
                        "sshctl cannot read your config, so it will not \
                         overwrite it either",
                    )
                    .clicked()
                {
                    self.open_save_preview();
                }
                if ui.button("Add host").clicked() {
                    self.new_existing_key = None;
                    self.new_generate_key = true;
                    self.modal = Modal::AddHost;
                }
                if ui
                    .button("Reload")
                    .on_hover_text("Reads ~/.ssh/config again; unsaved work is lost")
                    .clicked()
                {
                    // Without changes there is nothing to lose, so no question
                    // then. With changes this is precisely the way out to undo
                    // something, so it must never be disabled.
                    if self.dirty {
                        self.modal = Modal::ConfirmReload;
                    } else {
                        self.reload();
                        self.say("~/.ssh/config read in again", Level::Ok);
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::DragValue::new(&mut self.timeout_secs)
                            .range(1..=30)
                            .suffix(" s"),
                    );
                    ui.label("timeout");
                    if self.dirty {
                        ui.colored_label(colour(Level::Warn), "not saved");
                        status_dot(ui, Some(Level::Warn));
                    }
                });
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                for t in [Tab::Overview, Tab::Config, Tab::Keys, Tab::KnownHosts] {
                    if ui.selectable_label(self.tab == t, t.title()).clicked() {
                        self.tab = t;
                    }
                }
            });
            ui.add_space(4.0);
        });

        egui::Panel::bottom("below").show(ui, |ui| {
            ui.add_space(4.0);
            match &self.toast {
                Some((msg, level)) => {
                    ui.colored_label(colour(*level), msg);
                }
                None => {
                    ui.label(ssh_config_path().display().to_string());
                }
            }
            ui.add_space(4.0);
        });

        // Nothing beats this: an unreadable file looks exactly like an empty
        // one, and that is the only way sshctl could delete everything.
        if let Some(why) = self.unreadable.clone() {
            egui::Panel::top("unreadable").show(ui, |ui| {
                ui.add_space(6.0);
                ui.colored_label(
                    colour(Level::Fail),
                    "Your config is there, but sshctl cannot read it. \
                     Everything below is empty for that reason — not because \
                     the file is. Saving is switched off.",
                );
                ui.weak(why);
                ui.weak(
                    "A file saved as UTF-16 (PowerShell's `>` does this) reads \
                     as unusable here; save it as UTF-8.",
                );
                ui.add_space(6.0);
            });
        }

        // The round-trip warning sits at the top and not among the findings:
        // it decides whether saving is safe at all.
        if !self.losses.is_empty() {
            egui::Panel::top("roundtrip").show(ui, |ui| {
                ui.add_space(6.0);
                ui.colored_label(
                    colour(Level::Warn),
                    format!(
                        "{} line(s) will not survive the rewrite — saving would delete them:",
                        self.losses.len()
                    ),
                );
                for loss in &self.losses {
                    ui.horizontal_wrapped(|ui| {
                        ui.monospace(&loss.line);
                        ui.weak(loss.reason.describe());
                    });
                }
                ui.add_space(6.0);
            });
        }

        // Four tabs: one to look at, three to change things in. That
        // separation is deliberate — so far every mistake in this window came
        // from the same information living in two places and growing apart.
        egui::Panel::bottom("findings")
            .resizable(true)
            .default_size(140.0)
            .min_size(50.0)
            .show(ui, |ui| {
                ui.add_space(4.0);
                let shown = self
                    .findings
                    .iter()
                    .filter(|f| f.subject != "orphan")
                    .count();
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("FINDINGS").small().weak());
                    if shown > 0 {
                        ui.weak(format!("({shown})"));
                    }
                    if self.checking {
                        ui.spinner();
                    }
                });
                ui.add_space(2.0);
                egui::ScrollArea::vertical()
                    .id_salt("findings")
                    .show(ui, |ui| {
                        if self.findings.is_empty() && !self.checking {
                            ui.weak("Nothing checked yet.");
                        }
                        for f in self.findings.iter().filter(|f| f.subject != "orphan") {
                            ui.horizontal_wrapped(|ui| {
                                ui.colored_label(colour(f.level), f.level.label().trim());
                                ui.strong(&f.subject);
                                ui.add_space(4.0);
                                ui.label(&f.message);
                            });
                        }
                    });
            });

        egui::CentralPanel::default().show(ui, |ui| match self.tab {
            Tab::Overview => self.tab_overview(ui),
            Tab::Config => self.tab_config(ui),
            Tab::Keys => self.tab_keys(ui),
            Tab::KnownHosts => self.tab_known(ui),
        });

        self.show_modal(ctx);
    }
}

impl App {
    fn show_modal(&mut self, ctx: &egui::Context) {
        let mut close = false;
        let mut save: Option<String> = None;
        let mut add = false;
        let mut reload = false;
        let mut forget: Option<String> = None;
        let mut make_key = false;
        let mut delete_key: Option<String> = None;
        let mut scan = false;
        let mut add_scanned = false;
        let mut pick_option: Option<&'static catalog::OptionSpec> = None;
        let mut new_value: Option<String> = None;
        let mut add_option: Option<String> = None;
        let mut pick_hop: Option<String> = None;
        let current_alias = self
            .selected
            .and_then(|i| self.source.hosts.get(i))
            .map(|h| h.alias.clone());

        match &self.modal {
            Modal::None => {}
            Modal::Save {
                rendered,
                removed,
                added,
                disk_changed,
                verdict,
                lost_comments,
            } => {
                egui::Window::new("Save to ~/.ssh/config")
                    .collapsible(false)
                    .resizable(true)
                    .default_size([760.0, 540.0])
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        if *disk_changed {
                            ui.colored_label(
                                colour(Level::Fail),
                                "Careful: ~/.ssh/config has changed since you opened it. \
                                 Saving overwrites that change.",
                            );
                            ui.add_space(6.0);
                        }
                        // What ssh itself says, above the line count — because
                        // this is the part that actually decides.
                        match verdict {
                            proof::Verdict::Same { probed } => {
                                ui.colored_label(
                                    colour(Level::Ok),
                                    format!(
                                        "Checked with ssh: for all {probed} names it gives \
                                         exactly the same answer afterwards.",
                                    ),
                                );
                            }
                            proof::Verdict::Changed(diffs) => {
                                ui.colored_label(
                                    colour(Level::Fail),
                                    "ssh would behave differently afterwards:",
                                );
                                for d in diffs.iter().take(8) {
                                    ui.monospace(d.describe());
                                }
                                if diffs.len() > 8 {
                                    ui.weak(format!("and {} more", diffs.len() - 8));
                                }
                            }
                            proof::Verdict::Unknown(why) => {
                                ui.colored_label(
                                    colour(Level::Warn),
                                    format!("Could not check this with ssh: {why}"),
                                );
                                if !self.losses.is_empty() {
                                    ui.label(format!(
                                        "{} line(s) from your original will not survive this \
                                         — see the top of the window.",
                                        self.losses.len()
                                    ));
                                }
                            }
                        }
                        ui.add_space(6.0);
                        for comment in lost_comments {
                            ui.weak(format!("The comment \"{comment}\" disappears."));
                        }
                        if !lost_comments.is_empty() {
                            ui.add_space(6.0);
                        }
                        ui.horizontal(|ui| {
                            ui.label(format!("{} lines added", added.len()));
                            ui.separator();
                            ui.label(format!("{} lines removed", removed.len()));
                            ui.separator();
                            ui.weak("a backup lands alongside as config.before-sshctl");
                        });
                        ui.add_space(6.0);
                        egui::ScrollArea::vertical()
                            .max_height(380.0)
                            .show(ui, |ui| {
                                for line in removed {
                                    ui.colored_label(colour(Level::Fail), format!("- {line}"));
                                }
                                for line in added {
                                    ui.colored_label(colour(Level::Ok), format!("+ {line}"));
                                }
                                if removed.is_empty() && added.is_empty() {
                                    ui.weak("No difference — there is nothing to write.");
                                }
                            });
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            // The same gate as `sshctl write` on the command
                            // line: writing something that changes behaviour
                            // takes a deliberate act, not a click on a button
                            // that looks like every other one.
                            let blocked = match verdict {
                                proof::Verdict::Same { .. } => None,
                                proof::Verdict::Changed(_) => {
                                    Some("ssh would behave differently afterwards.")
                                }
                                proof::Verdict::Unknown(_) if self.losses.is_empty() => None,
                                proof::Verdict::Unknown(_) => {
                                    Some("Lines would be lost and ssh could not be asked about it.")
                                }
                            };
                            if blocked.is_none() {
                                if ui.button("Write").clicked() {
                                    save = Some(rendered.clone());
                                }
                            } else {
                                ui.add_enabled(false, egui::Button::new("Write"))
                                    .on_disabled_hover_text(format!(
                                        "{} Tick the box if you want it anyway.",
                                        blocked.unwrap_or_default()
                                    ));
                                ui.checkbox(&mut self.force_write, "I know — write anyway");
                                if self.force_write && ui.button("Write anyway").clicked() {
                                    save = Some(rendered.clone());
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            Modal::NewKey => {
                egui::Window::new("New key")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(520.0)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        egui::Grid::new("newkey").num_columns(2).show(ui, |ui| {
                            ui.label("Name");
                            ui.text_edit_singleline(&mut self.keyname);
                            ui.end_row();
                            ui.label("Comment");
                            ui.text_edit_singleline(&mut self.keycomment);
                            ui.end_row();
                        });
                        ui.add_space(6.0);
                        match keys::filename_for(&self.keyname) {
                            Ok(name) => {
                                ui.horizontal(|ui| {
                                    ui.weak("becomes:");
                                    ui.monospace(format!("~/.ssh/{name}"));
                                });
                            }
                            Err(e) => {
                                ui.colored_label(colour(Level::Fail), e);
                            }
                        }
                        ui.add_space(10.0);
                        ui.label(
                            egui::RichText::new("Type: ed25519, without a passphrase")
                                .small()
                                .weak(),
                        );
                        ui.weak(
                            "We deliberately do not set a passphrase from this window: it \
                             would have to travel over the command line and through this \
                             app's memory. If you want one on the key, do that afterwards \
                             with 'ssh-keygen -p -f ~/.ssh/<name>' — there you type it \
                             behind a hidden prompt.",
                        );
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Create").clicked() {
                                make_key = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            Modal::ConfirmDeleteKey(name) => {
                let users: Vec<String> = self
                    .source
                    .hosts
                    .iter()
                    .filter(|h| h.key.as_deref() == Some(name.as_str()))
                    .map(|h| h.alias.clone())
                    .collect();
                egui::Window::new("Delete key?")
                    .collapsible(false)
                    .resizable(false)
                    .default_width(520.0)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Key");
                            ui.monospace(name);
                        });
                        ui.add_space(8.0);
                        if users.is_empty() {
                            ui.weak("No host in this config uses it.");
                        } else {
                            ui.colored_label(
                                colour(Level::Fail),
                                format!(
                                    "Used by: {}. That host will no longer be able to log in.",
                                    users.join(", ")
                                ),
                            );
                        }
                        ui.add_space(6.0);
                        ui.colored_label(
                            colour(Level::Warn),
                            "Careful: sshctl only sees this config. The key may be in use \
                             elsewhere — by Xcode, a script or another machine.",
                        );
                        ui.add_space(8.0);
                        ui.weak(
                            "It is not erased but moved to ~/.ssh/deleted/, so you can get \
                             it back.",
                        );
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Move").clicked() {
                                delete_key = Some(name.clone());
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            Modal::KeyMade(name) => {
                let detail = keys::detail(name, &self.source);
                egui::Window::new("Key created")
                    .collapsible(false)
                    .resizable(true)
                    .default_size([640.0, 340.0])
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            status_dot(ui, Some(Level::Ok));
                            ui.monospace(format!("~/.ssh/{name}"));
                        });
                        if let Some(d) = &detail {
                            ui.weak(&d.fingerprint);
                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("PUBLIC HALF").small().weak());
                            if let Some(line) = &d.public_line {
                                ui.add(
                                    egui::TextEdit::multiline(&mut line.as_str())
                                        .font(egui::TextStyle::Monospace)
                                        .desired_rows(3)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.add_space(6.0);
                                if ui.button("Copy").clicked() {
                                    ctx.copy_text(line.clone());
                                }
                            }
                        }
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("NEXT").small().weak());
                        ui.weak("1. Put the public half in authorized_keys on the target machine.");
                        ui.weak("2. Attach it to a host through the 'Key' dropdown.");
                        ui.weak(format!(
                            "3. Want a passphrase on it: ssh-keygen -p -f ~/.ssh/{name}"
                        ));
                        ui.add_space(10.0);
                        if ui.button("Close").clicked() {
                            close = true;
                        }
                    });
            }
            Modal::ScanHost => {
                egui::Window::new("Fetch host key")
                    .collapsible(false)
                    .resizable(true)
                    .default_size([620.0, 360.0])
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Hostname");
                            ui.add_sized(
                                [260.0, 20.0],
                                egui::TextEdit::singleline(&mut self.keyname),
                            );
                            if ui.button("Fetch").clicked() {
                                scan = true;
                            }
                        });
                        ui.add_space(8.0);
                        ui.colored_label(
                            colour(Level::Warn),
                            "This is not a check. You get the key of whoever answers, \
                             whoever that may be. Confirm the fingerprint by some other \
                             route before you trust it.",
                        );
                        if !self.scan_result.is_empty() {
                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("FOUND").small().weak());
                            for (name, kind, line) in &self.scan_result {
                                let fp = std::process::Command::new("ssh-keygen")
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
                                    .unwrap_or_default();
                                ui.horizontal(|ui| {
                                    ui.monospace(format!("{name}  {kind}"));
                                    ui.weak(fp);
                                });
                            }
                            ui.add_space(10.0);
                            if ui.button("Add to known_hosts").clicked() {
                                add_scanned = true;
                            }
                        }
                        ui.add_space(10.0);
                        if ui.button("Close").clicked() {
                            close = true;
                        }
                    });
            }

            Modal::ConfirmForget(name) => {
                let lines: Vec<&sshctl::known::Entry> = self
                    .ledger
                    .entries
                    .iter()
                    .filter(|e| &e.label() == name)
                    .collect();
                let belongs_to: Vec<String> = self
                    .tree
                    .iter()
                    .filter(|t| t.host.is_some() && t.entries.contains(name))
                    .filter_map(|t| t.host.clone())
                    .collect();

                egui::Window::new("Remove entry from known_hosts?")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Name");
                            ui.monospace(name);
                        });
                        ui.add_space(6.0);
                        ui.label(format!("{} line(s) will go:", lines.len()));
                        for e in &lines {
                            ui.monospace(format!("  {}  {}", e.key_type, e.fingerprint));
                        }
                        ui.add_space(8.0);
                        if belongs_to.is_empty() {
                            ui.weak("No host in your config points at this.");
                        } else {
                            ui.colored_label(
                                colour(Level::Warn),
                                format!(
                                    "Careful: {} relies on this trust. The next connection \
                                     will ask for the fingerprint again.",
                                    belongs_to.join(", ")
                                ),
                            );
                        }
                        ui.add_space(6.0);
                        ui.weak("A backup lands alongside as known_hosts.before-sshctl.");
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Remove").clicked() {
                                forget = Some(name.clone());
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            Modal::PickOption => {
                egui::Window::new("Add option")
                    .collapsible(false)
                    .resizable(true)
                    .default_size([640.0, 460.0])
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Search");
                            ui.add_sized(
                                [340.0, 20.0],
                                egui::TextEdit::singleline(&mut self.option_search)
                                    .hint_text("by name, or by what you want to achieve"),
                            );
                        });
                        ui.weak(
                            "Searching by intent is fine: 'instant', 'agent off', 'slow line'.",
                        );
                        ui.add_space(8.0);

                        let hits = catalog::search(&self.option_search);
                        egui::ScrollArea::vertical()
                            .max_height(230.0)
                            .show(ui, |ui| {
                                let mut previous = "";
                                for o in &hits {
                                    if o.group != previous {
                                        ui.add_space(6.0);
                                        ui.label(egui::RichText::new(o.group).small().weak());
                                        previous = o.group;
                                    }
                                    let selected = self
                                        .option_selected
                                        .map(|g| g.keyword == o.keyword)
                                        .unwrap_or(false);
                                    if ui
                                        .selectable_label(selected, o.keyword)
                                        .on_hover_text(o.explanation)
                                        .clicked()
                                    {
                                        pick_option = Some(*o);
                                    }
                                }
                                if hits.is_empty() {
                                    ui.weak(
                                        "Nothing found. Any other option you can put in the \
                                             file by hand; that one gets kept.",
                                    );
                                }
                            });

                        if let Some(o) = self.option_selected {
                            ui.add_space(10.0);
                            ui.separator();
                            ui.add_space(6.0);
                            ui.strong(o.keyword);
                            ui.weak(o.explanation);
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                ui.label("Value");
                                if o.choices.is_empty() {
                                    ui.add_sized(
                                        [300.0, 20.0],
                                        egui::TextEdit::singleline(&mut self.option_value),
                                    );
                                } else {
                                    egui::ComboBox::from_id_salt("optionvalue")
                                        .selected_text(if self.option_value.is_empty() {
                                            "(pick)".to_string()
                                        } else {
                                            self.option_value.clone()
                                        })
                                        .show_ui(ui, |ui| {
                                            for k in o.choices {
                                                if ui
                                                    .selectable_label(self.option_value == *k, *k)
                                                    .clicked()
                                                {
                                                    new_value = Some((*k).to_string());
                                                }
                                            }
                                        });
                                }
                            });
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                if !self.option_value.trim().is_empty()
                                    && ui.button("Add").clicked()
                                {
                                    add_option =
                                        Some(format!("{} {}", o.keyword, self.option_value.trim()));
                                }
                                if ui.button("Cancel").clicked() {
                                    close = true;
                                }
                            });
                        } else {
                            ui.add_space(10.0);
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        }
                    });
            }
            Modal::PickHop => {
                let own: Vec<(String, String)> = self
                    .source
                    .hosts
                    .iter()
                    .filter(|h| Some(h.alias.as_str()) != current_alias.as_deref())
                    .map(|h| (h.alias.clone(), h.hostname.clone()))
                    .collect();
                let from_ledger: Vec<String> = self
                    .ledger
                    .per_name()
                    .into_iter()
                    .map(|(n, _)| n)
                    .filter(|n| !n.starts_with('('))
                    .filter(|n| !own.iter().any(|(_, hn)| hn == n))
                    .collect();

                egui::Window::new("Pick a hop")
                    .collapsible(false)
                    .resizable(true)
                    .default_size([560.0, 460.0])
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(egui::RichText::new("FROM YOUR CONFIG").small().weak());
                        ui.weak(
                            "Recommended: an alias gets its own user and key, because the \
                             settings of the final destination do not apply here.",
                        );
                        ui.add_space(4.0);
                        egui::ScrollArea::vertical()
                            .id_salt("hop_own")
                            .max_height(150.0)
                            .show(ui, |ui| {
                                if own.is_empty() {
                                    ui.weak("no other hosts");
                                }
                                for (alias, hostname) in &own {
                                    ui.horizontal(|ui| {
                                        if ui.button(alias).clicked() {
                                            pick_hop = Some(alias.clone());
                                        }
                                        ui.weak(hostname);
                                    });
                                }
                            });

                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("FROM KNOWN_HOSTS").small().weak());
                        ui.colored_label(
                            colour(Level::Warn),
                            "You have connected to this before, but there is no block for \
                             it. ssh will then use your local username and whatever the \
                             agent offers.",
                        );
                        ui.add_space(4.0);
                        egui::ScrollArea::vertical()
                            .id_salt("hop_ledger")
                            .max_height(120.0)
                            .show(ui, |ui| {
                                if from_ledger.is_empty() {
                                    ui.weak("nothing that does not have a block yet");
                                }
                                for name in &from_ledger {
                                    if ui.button(name).clicked() {
                                        pick_hop = Some(name.clone());
                                    }
                                }
                            });

                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("TYPE IT YOURSELF").small().weak());
                        ui.weak("Form: [user@]host[:port]");
                        ui.horizontal(|ui| {
                            ui.add_sized(
                                [300.0, 20.0],
                                egui::TextEdit::singleline(&mut self.hop_freeform),
                            );
                            if !self.hop_freeform.trim().is_empty() && ui.button("Use").clicked() {
                                pick_hop = Some(self.hop_freeform.trim().to_string());
                            }
                        });

                        ui.add_space(12.0);
                        ui.checkbox(
                            &mut self.hop_append,
                            "append to the existing chain instead of replacing it",
                        );
                        ui.add_space(8.0);
                        if ui.button("Cancel").clicked() {
                            close = true;
                        }
                    });
            }
            Modal::ConfirmReload => {
                egui::Window::new("Throw changes away?")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        ui.label(
                            "Your unsaved changes disappear and ~/.ssh/config gets read in \
                             again.",
                        );
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Throw away").clicked() {
                                reload = true;
                            }
                            if ui.button("Keep").clicked() {
                                close = true;
                            }
                        });
                    });
            }
            Modal::AddHost => {
                egui::Window::new("Add host")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        egui::Grid::new("new").num_columns(2).show(ui, |ui| {
                            ui.label("Alias");
                            ui.text_edit_singleline(&mut self.new_alias);
                            ui.end_row();
                            ui.label("Hostname");
                            ui.text_edit_singleline(&mut self.new_hostname);
                            ui.end_row();
                            ui.label("User");
                            ui.text_edit_singleline(&mut self.new_user);
                            ui.end_row();
                        });
                        ui.add_space(6.0);
                        match &self.new_existing_key {
                            Some(name) => {
                                ui.horizontal(|ui| {
                                    ui.label("Key");
                                    ui.monospace(name);
                                });
                                ui.weak(
                                    "This existing key gets attached to the host. Fill in the \
                                     hostname it should go to.",
                                );
                            }
                            None => {
                                ui.checkbox(&mut self.new_generate_key, "Create a key right away");
                                if self.new_generate_key && !self.new_alias.trim().is_empty() {
                                    ui.weak(format!(
                                        "becomes: id_ed25519_{}",
                                        self.new_alias.trim()
                                    ));
                                }
                            }
                        }
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if ui.button("Add").clicked() {
                                add = true;
                            }
                            if ui.button("Cancel").clicked() {
                                close = true;
                            }
                        });
                    });
            }
        }

        if let Some(rendered) = save {
            self.apply_save(&rendered);
        }
        if add {
            self.add_host();
        }
        if let Some(name) = forget {
            // The label is not always the raw first field: on a hashed line it
            // is "(hashed name)". Look up the real value.
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
        if make_key {
            match keys::generate(&self.keyname.clone(), &self.keycomment.clone()) {
                Ok(name) => {
                    self.keys = keys::inventory(&self.source);
                    self.modal = Modal::KeyMade(name.clone());
                    self.say(format!("{name} created"), Level::Ok);
                }
                Err(e) => self.say(e, Level::Fail),
            }
        }
        if let Some(name) = delete_key {
            match keys::delete(&name) {
                Ok(target) => {
                    self.keys = keys::inventory(&self.source);
                    self.modal = Modal::None;
                    self.say(format!("moved to {}", target.display()), Level::Warn);
                }
                Err(e) => self.say(e, Level::Fail),
            }
        }
        if scan {
            let name = self.keyname.trim().to_string();
            match known::scan(&name, 22) {
                Ok(r) => {
                    self.scan_result = r;
                    self.say(
                        format!("{} key(s) fetched", self.scan_result.len()),
                        Level::Ok,
                    );
                }
                Err(e) => {
                    self.scan_result.clear();
                    self.say(e, Level::Fail);
                }
            }
        }
        if add_scanned {
            let lines: Vec<String> = self.scan_result.iter().map(|(_, _, r)| r.clone()).collect();
            match known::append(&self.ledger.files.clone(), &lines) {
                Ok(n) => {
                    self.refresh_ledger();
                    self.modal = Modal::None;
                    self.say(format!("{n} line(s) added (backup alongside)"), Level::Ok);
                }
                Err(e) => self.say(e, Level::Fail),
            }
        }
        if let Some(hop) = pick_hop {
            if let Some(i) = self.selected
                && let Some(h) = self.source.hosts.get_mut(i)
            {
                let updated = match (&h.proxy_jump, self.hop_append) {
                    (Some(existing), true) if !existing.trim().is_empty() => {
                        format!("{existing},{hop}")
                    }
                    _ => hop.clone(),
                };
                h.proxy_jump = Some(updated);
                self.touched();
                self.say(format!("hop '{hop}' set"), Level::Ok);
            }
            self.hop_freeform.clear();
            self.modal = Modal::None;
        }
        if let Some(o) = pick_option {
            self.option_selected = Some(o);
            self.option_value.clear();
        }
        if let Some(v) = new_value {
            self.option_value = v;
        }
        if let Some(line) = add_option {
            if let Some(i) = self.selected
                && let Some(h) = self.source.hosts.get_mut(i)
            {
                // Setting the same option twice is usually pointless: ssh
                // takes the first and ignores the rest without saying
                // anything. But some keywords gather instead of overwrite —
                // two LocalForwards really are two forwards — and for those
                // the old line has to stay.
                let keyword = line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if !catalog::is_repeatable(&keyword) {
                    h.options
                        .retain(|o| !o.to_ascii_lowercase().starts_with(&format!("{keyword} ")));
                }
                h.options.push(line.clone());
                self.touched();
                self.say(format!("'{line}' added — not saved yet"), Level::Ok);
            }
            self.modal = Modal::None;
        }
        if reload {
            self.reload();
            self.modal = Modal::None;
            self.say("changes thrown away; read in again", Level::Ok);
        }
        if close {
            self.modal = Modal::None;
            self.new_existing_key = None;
        }
    }
}

/// Size of an input field. `desired_width` on a `TextEdit` is ignored inside a
/// `Grid` — the column width wins — so we force it.
const FIELD: [f32; 2] = [230.0, 22.0];

/// The narrow picker list on the left of a tab.
///
/// Deliberately a separate call from the content next to it: if both closures
/// were arguments of the same function, their borrows of `self` would live at
/// the same time and the second one could no longer change anything.
fn list_panel(
    ui: &mut egui::Ui,
    id: &'static str,
    width: f32,
    content: impl FnOnce(&mut egui::Ui),
) {
    egui::Panel::left(id)
        .resizable(true)
        .default_size(width)
        .min_size(160.0)
        .max_size(400.0)
        .show(ui, |ui| {
            ui.add_space(6.0);
            egui::ScrollArea::vertical().id_salt(id).show(ui, content);
        });
}

/// The content area next to it, on the right.
fn content_panel(ui: &mut egui::Ui, id: &'static str, content: impl FnOnce(&mut egui::Ui)) {
    egui::CentralPanel::default().show(ui, |ui| {
        egui::ScrollArea::vertical().id_salt(id).show(ui, content);
    });
}

/// A "name: value" line with its origin behind it, read-only.
fn row(ui: &mut egui::Ui, name: &str, value: &str, origin: Option<&Origin>) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [110.0, 18.0],
            egui::Label::new(name).halign(egui::Align::LEFT),
        );
        if value.is_empty() {
            ui.weak("—");
        } else {
            ui.monospace(value);
        }
        if let Some(o) = origin {
            ui.add_space(6.0);
            if o.is_invisible() {
                ui.colored_label(colour(Level::Warn), o.describe());
            } else if *o == Origin::SshDefault {
                ui.weak("ssh's own default");
            } else {
                ui.weak(o.describe());
            }
        }
    });
}

impl App {
    /// Tab 1 — looking only. Everything there is to know about one host,
    /// brought together from config, your keys and the ledger.
    fn tab_overview(&mut self, ui: &mut egui::Ui) {
        let aliases: Vec<String> = self.source.hosts.iter().map(|h| h.alias.clone()).collect();
        let eff = self.effective.take();
        let keys = self.keys.clone();
        let known_types = self.known_types.clone();
        let losses = self.losses.len();
        let selected = self.selected;
        let mut pick = None;

        list_panel(ui, "overview_list", 220.0, |ui| {
            ui.label(egui::RichText::new("HOSTS").small().weak());
            ui.add_space(4.0);
            for (i, alias) in aliases.iter().enumerate() {
                ui.horizontal(|ui| {
                    status_dot(ui, self.level_for(alias));
                    if ui.selectable_label(selected == Some(i), alias).clicked() {
                        pick = Some(i);
                    }
                });
            }
        });
        content_panel(ui, "overview_content", |ui| {
            let Some(host) = selected.and_then(|i| self.source.hosts.get(i)) else {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| ui.weak("Pick a host on the left."));
                return;
            };
            ui.add_space(6.0);
            ui.heading(&host.alias);
            if losses > 0 {
                ui.colored_label(
                    colour(Level::Warn),
                    format!("{losses} line(s) in your config will not survive a rewrite"),
                );
            }
            ui.add_space(12.0);

            let origin = |kw: &str| eff.as_ref().and_then(|e| e.get(kw)).map(|s| &s.origin);
            let value = |kw: &str| {
                eff.as_ref()
                    .and_then(|e| e.get(kw))
                    .map(|s| s.value.clone())
                    .unwrap_or_default()
            };

            ui.label(egui::RichText::new("1  WHICH RULES APPLY").small().strong());
            ui.add_space(4.0);
            match &eff {
                Some(e) if !e.matching_blocks.is_empty() => {
                    for b in &e.matching_blocks {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("Host {}", b.patterns.join(" ")));
                            if b.source_file.starts_with("/etc/") {
                                ui.colored_label(
                                    colour(Level::Warn),
                                    format!("{} — not in your own file", b.source_file),
                                );
                            } else {
                                ui.weak(&b.source_file);
                            }
                        });
                    }
                }
                _ => {
                    ui.weak("(not worked out yet)");
                }
            }

            ui.add_space(14.0);
            ui.label(egui::RichText::new("2  WHERE TO").small().strong());
            ui.add_space(4.0);
            row(ui, "Hostname", &value("hostname"), origin("hostname"));
            row(ui, "Port", &value("port"), origin("port"));
            let jump = value("proxyjump");
            let chain = proxy::parse_chain(&jump);
            if chain.is_empty() {
                row(ui, "Which way", "direct", None);
            } else {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [110.0, 18.0],
                        egui::Label::new("Which way").halign(egui::Align::LEFT),
                    );
                    ui.monospace("you");
                    for hop in &chain {
                        ui.weak("->");
                        ui.monospace(hop.label());
                    }
                    ui.weak("->");
                    ui.monospace(&host.alias);
                });
                ui.weak("Every hop is tested separately; the findings say which one gives out.");
            }

            ui.add_space(14.0);
            ui.label(egui::RichText::new("3  WHO AM I").small().strong());
            ui.add_space(4.0);
            row(ui, "User", &value("user"), origin("user"));
            let key_name = host.key.clone().unwrap_or_default();
            row(ui, "Key", &key_name, origin("identityfile"));
            if let Some(k) = keys.iter().find(|k| k.name == key_name) {
                if !k.has_public {
                    ui.colored_label(
                        colour(Level::Warn),
                        "The public half is missing; you cannot authorise it anywhere.",
                    );
                }
            } else if !key_name.is_empty() {
                ui.colored_label(colour(Level::Fail), "That key is not in ~/.ssh.");
            } else {
                ui.colored_label(
                    colour(Level::Warn),
                    "Without a key ssh offers everything in your agent.",
                );
            }

            ui.add_space(14.0);
            ui.label(
                egui::RichText::new("4  WHO IS THE DESTINATION")
                    .small()
                    .strong(),
            );
            ui.add_space(4.0);
            if known_types.is_empty() {
                ui.colored_label(
                    colour(Level::Warn),
                    "Not in known_hosts — the first connection will ask for trust.",
                );
            } else {
                ui.horizontal(|ui| {
                    status_dot(ui, Some(Level::Ok));
                    ui.label(format!("recognised before: {}", known_types.join(", ")));
                });
            }
            row(
                ui,
                "Looked up as",
                &sshctl::known::lookup_name_for(host),
                None,
            );
            row(
                ui,
                "Strictness",
                &value("stricthostkeychecking"),
                origin("stricthostkeychecking"),
            );

            if let Some(e) = &eff {
                let invisible = e.invisible();
                if !invisible.is_empty() {
                    ui.add_space(14.0);
                    ui.colored_label(
                        colour(Level::Warn),
                        "APPLIES WITHOUT BEING IN YOUR OWN FILE",
                    );
                    for s in invisible {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{} {}", s.keyword, s.value));
                            ui.weak(s.origin.describe());
                        });
                    }
                }
            }
            ui.add_space(20.0);
        });

        self.effective = eff;
        if let Some(i) = pick {
            self.selected = Some(i);
        }
    }
}

impl App {
    /// Tab 2 — the only tab that changes ~/.ssh/config.
    fn tab_config(&mut self, ui: &mut egui::Ui) {
        let aliases: Vec<String> = self.source.hosts.iter().map(|h| h.alias.clone()).collect();
        let available: Vec<String> = self.keys.iter().map(|k| k.name.clone()).collect();
        let eff = self.effective.take();
        let selected = self.selected;
        let mut pick = None;
        let mut changed = false;
        let mut remove = None;
        let mut add = false;
        let mut choose_option = false;
        let mut choose_hop = false;

        list_panel(ui, "config_list", 220.0, |ui| {
            ui.label(egui::RichText::new("HOSTS").small().weak());
            ui.add_space(4.0);
            for (i, alias) in aliases.iter().enumerate() {
                ui.horizontal(|ui| {
                    status_dot(ui, self.level_for(alias));
                    if ui.selectable_label(selected == Some(i), alias).clicked() {
                        pick = Some(i);
                    }
                });
            }
            ui.add_space(10.0);
            if ui.small_button("+ add host").clicked() {
                add = true;
            }
        });
        content_panel(ui, "config_content", |ui| {
            let Some(index) = selected else {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| ui.weak("Pick a host on the left."));
                return;
            };
            let Some(host) = self.source.hosts.get_mut(index) else {
                return;
            };
            ui.add_space(6.0);
            ui.heading(&host.alias);
            ui.add_space(12.0);

            egui::Grid::new("configfields")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label("Alias");
                    changed |= ui
                        .add_sized(FIELD, egui::TextEdit::singleline(&mut host.alias))
                        .changed();
                    ui.end_row();

                    ui.label("Hostname");
                    changed |= ui
                        .add_sized(FIELD, egui::TextEdit::singleline(&mut host.hostname))
                        .changed();
                    ui.end_row();

                    ui.label("User");
                    changed |= ui
                        .add_sized(FIELD, egui::TextEdit::singleline(&mut host.user))
                        .changed();
                    ui.end_row();

                    ui.label("Port");
                    let mut port = host.port.map(|p| p.to_string()).unwrap_or_default();
                    if ui
                        .add_sized(FIELD, egui::TextEdit::singleline(&mut port))
                        .changed()
                    {
                        host.port = port.trim().parse().ok();
                        changed = true;
                    }
                    ui.end_row();

                    ui.label("Key");
                    let current = host.key.clone().unwrap_or_default();
                    egui::ComboBox::from_id_salt("keypick")
                        .selected_text(if current.is_empty() {
                            "(none)".to_string()
                        } else {
                            current.clone()
                        })
                        .width(FIELD[0])
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(current.is_empty(), "(none)").clicked() {
                                host.key = None;
                                changed = true;
                            }
                            for k in &available {
                                if ui.selectable_label(&current == k, k).clicked() {
                                    host.key = Some(k.clone());
                                    changed = true;
                                }
                            }
                        });
                    ui.end_row();

                    ui.label("Via (ProxyJump)");
                    let mut via = host.proxy_jump.clone().unwrap_or_default();
                    if ui
                        .add_sized(
                            [FIELD[0] - 30.0, FIELD[1]],
                            egui::TextEdit::singleline(&mut via),
                        )
                        .on_hover_text(
                            "Jump via another machine. May be an alias from this file; \
                             several hops comma-separated.",
                        )
                        .changed()
                    {
                        host.proxy_jump = (!via.trim().is_empty()).then_some(via);
                        changed = true;
                    }
                    if ui
                        .small_button("pick")
                        .on_hover_text("pick a hop from your hosts or from known_hosts")
                        .clicked()
                    {
                        choose_hop = true;
                    }
                    ui.end_row();

                    ui.label("Comment");
                    let mut comment = host.comment.clone().unwrap_or_default();
                    if ui
                        .add_sized(FIELD, egui::TextEdit::singleline(&mut comment))
                        .changed()
                    {
                        host.comment = (!comment.trim().is_empty()).then_some(comment);
                        changed = true;
                    }
                    ui.end_row();
                });

            ui.add_space(14.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("EXTRA SSH OPTIONS").small().weak());
                if ui.small_button("+ add option").clicked() {
                    choose_option = true;
                }
            });
            if host.options.is_empty() {
                ui.weak("none");
            }
            let mut drop: Option<usize> = None;
            for (i, o) in host.options.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.monospace(o);
                    if ui
                        .small_button("x")
                        .on_hover_text("remove this line")
                        .clicked()
                    {
                        drop = Some(i);
                    }
                });
            }
            if let Some(i) = drop {
                host.options.remove(i);
                changed = true;
            }

            // What really applies is in the overview; here only what this
            // block sets itself.
            if eff.is_some() {
                ui.add_space(10.0);
                ui.weak("What of this ends up applying, you can see on the Overview tab.");
            }

            ui.add_space(18.0);
            if ui.button("Remove this host").clicked() {
                remove = Some(host.alias.clone());
            }
            ui.add_space(20.0);
        });

        self.effective = eff;
        if let Some(i) = pick {
            self.selected = Some(i);
        }
        if add {
            self.new_existing_key = None;
            self.new_generate_key = true;
            self.modal = Modal::AddHost;
        }
        if choose_hop {
            self.modal = Modal::PickHop;
        }
        if choose_option {
            self.option_search.clear();
            self.option_value.clear();
            self.option_selected = None;
            self.modal = Modal::PickOption;
        }
        if let Some(alias) = remove {
            if let Some(i) = self.selected {
                self.source.hosts.remove(i);
            }
            self.selected = None;
            self.touched();
            self.say(format!("'{alias}' removed — not saved yet"), Level::Warn);
        } else if changed {
            self.touched();
        }
    }

    /// Tab 3 — your keys. Only the comment field can be changed; type,
    /// fingerprint and the key itself are fixed.
    fn tab_keys(&mut self, ui: &mut egui::Ui) {
        let keys = self.keys.clone();
        let selected = self.selected_key.clone();
        let mut pick = None;
        let mut new = false;
        let mut remove = None;
        let mut rename_comment = None;
        let mut make_host = false;

        list_panel(ui, "key_list", 260.0, |ui| {
            let orphans = keys.iter().filter(|k| k.is_orphan()).count();
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("PRIVATE KEYS").small().weak());
                if orphans > 0 {
                    ui.colored_label(
                        colour(Level::Warn),
                        egui::RichText::new(format!("{orphans} not in config")).small(),
                    );
                }
            });
            ui.add_space(4.0);
            for k in &keys {
                ui.horizontal(|ui| {
                    status_dot(
                        ui,
                        Some(if k.is_orphan() {
                            Level::Warn
                        } else {
                            Level::Ok
                        }),
                    );
                    let mut text = egui::RichText::new(&k.name);
                    if !k.has_public {
                        text = text.italics();
                    }
                    if ui
                        .selectable_label(selected.as_deref() == Some(&k.name), text)
                        .clicked()
                    {
                        pick = Some(k.name.clone());
                    }
                });
            }
            ui.add_space(10.0);
            if ui.small_button("+ new key").clicked() {
                new = true;
            }
        });
        content_panel(ui, "key_content", |ui| {
            let Some(name) = selected.as_deref() else {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| ui.weak("Pick a key on the left."));
                return;
            };
            let Some(d) = keys::detail(name, &self.source) else {
                ui.colored_label(colour(Level::Fail), "Could not read this key.");
                return;
            };
            ui.add_space(6.0);
            ui.heading(&d.name);
            ui.horizontal(|ui| {
                ui.monospace(format!("~/.ssh/{}", d.name));
                ui.weak("the contents are never shown");
            });
            ui.add_space(12.0);

            row(
                ui,
                "Type",
                &format!("{} ({} bits)", d.key_type, d.bits),
                None,
            );
            row(ui, "Fingerprint", &d.fingerprint, None);
            row(
                ui,
                "Passphrase",
                if d.encrypted { "yes" } else { "no" },
                None,
            );
            ui.horizontal(|ui| {
                ui.add_sized([110.0, 18.0], egui::Label::new("Permissions"));
                if d.mode & 0o077 != 0 {
                    ui.colored_label(
                        colour(Level::Fail),
                        format!("{:o} — ssh refuses anything wider than 600", d.mode),
                    );
                } else {
                    ui.monospace(format!("{:o}", d.mode));
                }
            });
            ui.horizontal(|ui| {
                ui.add_sized([110.0, 18.0], egui::Label::new("Used by"));
                if d.used_by.is_empty() {
                    ui.colored_label(colour(Level::Warn), "no host in this config");
                } else {
                    ui.label(d.used_by.join(", "));
                }
            });

            ui.add_space(14.0);
            ui.label(egui::RichText::new("COMMENT").small().weak());
            ui.weak("The only field that can be changed.");
            ui.horizontal(|ui| {
                ui.add_sized(
                    [300.0, 20.0],
                    egui::TextEdit::singleline(&mut self.key_comment),
                );
                if ui.button("Save").clicked() {
                    rename_comment = Some((d.name.clone(), self.key_comment.clone()));
                }
            });
            ui.weak(
                "Changes only this file; copies already sitting in authorized_keys \
                     keep their old comment.",
            );

            ui.add_space(14.0);
            ui.label(egui::RichText::new("PUBLIC HALF").small().weak());
            match &d.public_line {
                Some(r) => {
                    if d.public_derived {
                        ui.colored_label(
                            colour(Level::Warn),
                            "No .pub file; this line was derived from the private half.",
                        );
                    }
                    ui.add(
                        egui::TextEdit::multiline(&mut r.as_str())
                            .font(egui::TextStyle::Monospace)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY),
                    );
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(r.clone());
                    }
                }
                None => {
                    ui.colored_label(
                        colour(Level::Fail),
                        "No public half, and it cannot be derived because the key is \
                             encrypted.",
                    );
                }
            }

            ui.add_space(18.0);
            ui.horizontal(|ui| {
                if d.used_by.is_empty()
                    && ui
                        .button("Create a host with this key")
                        .on_hover_text("opens the form with this key already attached")
                        .clicked()
                {
                    make_host = true;
                }
                if ui.button("Delete this key").clicked() {
                    remove = Some(d.name.clone());
                }
            });
            ui.add_space(20.0);
        });

        if let Some(n) = pick {
            self.key_comment = keys::detail(&n, &self.source)
                .map(|d| d.comment)
                .unwrap_or_default();
            self.selected_key = Some(n);
        }
        if new {
            self.keyname.clear();
            self.keycomment = format!("new@{}", machine_name());
            self.modal = Modal::NewKey;
        }
        if let Some(n) = remove {
            self.modal = Modal::ConfirmDeleteKey(n);
        }
        if make_host && let Some(n) = self.selected_key.clone() {
            let entry = self.keys.iter().find(|k| k.name == n).cloned();
            if let Some(k) = entry {
                self.adopt_key(&k);
            }
        }
        if let Some((name, comment)) = rename_comment {
            match keys::set_comment(&name, &comment) {
                Ok(()) => {
                    self.keys = keys::inventory(&self.source);
                    self.say("comment updated", Level::Ok);
                }
                Err(e) => self.say(e, Level::Fail),
            }
        }
    }

    /// Tab 4 — the ledger. Showing, removing, and fetching a host.
    fn tab_known(&mut self, ui: &mut egui::Ui) {
        let groups = self.ledger.per_name();
        let claimed: Vec<String> = self
            .tree
            .iter()
            .filter(|t| t.host.is_some())
            .flat_map(|t| t.entries.clone())
            .collect();
        let duplicates = self.ledger.duplicate_names();
        let selected = self.selected_entry.clone();
        let mut pick = None;
        let mut remove = None;
        let mut fetch = false;
        let mut pin: Option<(String, String)> = None;
        let mut new_pin_alias: Option<String> = None;
        let pin_alias = self.pin_alias.clone();

        list_panel(ui, "known_list", 260.0, |ui| {
            let loose = groups.iter().filter(|(n, _)| !claimed.contains(n)).count();
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("ENTRIES").small().weak());
                if loose > 0 {
                    ui.colored_label(
                        colour(Level::Warn),
                        egui::RichText::new(format!("{loose} without a host")).small(),
                    );
                }
            });
            ui.add_space(4.0);
            for (name, _) in &groups {
                ui.horizontal(|ui| {
                    status_dot(
                        ui,
                        Some(if claimed.contains(name) {
                            Level::Ok
                        } else {
                            Level::Warn
                        }),
                    );
                    if ui
                        .selectable_label(selected.as_deref() == Some(name.as_str()), name)
                        .clicked()
                    {
                        pick = Some(name.clone());
                    }
                    if duplicates.contains(name) {
                        ui.weak(egui::RichText::new("duplicate").small());
                    }
                });
            }
            ui.add_space(10.0);
            if ui
                .small_button("+ fetch host")
                .on_hover_text("fetches the host key with ssh-keyscan")
                .clicked()
            {
                fetch = true;
            }
        });
        content_panel(ui, "known_content", |ui| {
            let Some(name) = selected.as_deref() else {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| ui.weak("Pick an entry on the left."));
                return;
            };
            let lines: Vec<&sshctl::known::Entry> = self
                .ledger
                .entries
                .iter()
                .filter(|e| e.label() == name)
                .collect();
            ui.add_space(6.0);
            ui.heading(name);
            if lines.iter().all(|e| e.hashed) {
                ui.colored_label(
                    colour(Level::Warn),
                    "The name is stored hashed: you can test whether a name belongs to \
                         it, but not read out which one.",
                );
            }
            ui.add_space(12.0);

            ui.label(egui::RichText::new("STORED KEYS").small().weak());
            ui.add_space(4.0);
            for e in &lines {
                ui.horizontal(|ui| {
                    ui.add_sized([110.0, 18.0], egui::Label::new(&e.key_type));
                    ui.monospace(&e.fingerprint);
                });
            }

            ui.add_space(14.0);
            let belongs_to: Vec<String> = self
                .tree
                .iter()
                .filter(|t| t.host.is_some() && t.entries.iter().any(|v| v == name))
                .filter_map(|t| t.host.clone())
                .collect();
            ui.horizontal(|ui| {
                ui.add_sized([110.0, 18.0], egui::Label::new("Belongs to"));
                if belongs_to.is_empty() {
                    ui.colored_label(colour(Level::Warn), "no host in your config");
                } else {
                    ui.label(belongs_to.join(", "));
                }
            });
            ui.weak(
                "Lookup happens on the HostName, not on your alias. Change that and the \
                     machine is suddenly unknown.",
            );

            if belongs_to.is_empty() && !self.source.hosts.is_empty() {
                ui.add_space(14.0);
                ui.label(egui::RichText::new("PIN TO A HOST").small().weak());
                ui.weak(
                    "Sets HostKeyAlias, so that host looks up under this name. That is the \
                     only safe way to tie a host and an entry together: changing the \
                     hostname would change the destination.",
                );
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("pin_host")
                        .selected_text(pin_alias.clone().unwrap_or_else(|| "(pick host)".into()))
                        .show_ui(ui, |ui| {
                            for h in &self.source.hosts {
                                if ui
                                    .selectable_label(
                                        pin_alias.as_deref() == Some(h.alias.as_str()),
                                        &h.alias,
                                    )
                                    .clicked()
                                {
                                    new_pin_alias = Some(h.alias.clone());
                                }
                            }
                        });
                    if pin_alias.is_some() && ui.button("Pin").clicked() {
                        pin = pin_alias.clone().map(|a| (a, name.to_string()));
                    }
                });
            }

            ui.add_space(18.0);
            if ui.button("Remove this entry").clicked() {
                remove = Some(name.to_string());
            }
            ui.add_space(20.0);
        });

        if let Some(n) = pick {
            self.selected_entry = Some(n);
        }
        if let Some(n) = remove {
            self.modal = Modal::ConfirmForget(n);
        }
        if fetch {
            self.keyname.clear();
            self.scan_result.clear();
            self.modal = Modal::ScanHost;
        }
        if let Some(a) = new_pin_alias {
            self.pin_alias = Some(a);
        }
        if let Some((alias, name)) = pin {
            self.pin_host_key(&alias, &name);
        }
    }
}
