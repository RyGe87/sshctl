# Changelog

## Unreleased

- Zero dependencies, everywhere: the terminal UI draws itself (raw mode
  from `stty`, keys from a thread reading `/dev/tty`, cells over plain
  ANSI), the CLI parses its own arguments, and the snapshot writes its own
  TOML. A tip of the hat to the [ratatui](https://ratatui.rs) project,
  whose API shape the new terminal layer deliberately mirrors and whose
  crate served sshctl 0.2 and 0.3 well.
- The panes scroll: shift-j/k moves through the detail, shift-d/f through
  the findings — the left hand mirroring the right. Both know where to
  stop and say how much sits beyond the fold, and long findings wrap under
  their own message column. Remove host moved from D to X, next to the
  small x that drops an option.
- Help grew two pages — the tabs, then the keys — and opens by itself on a
  config with no hosts. The bottom key bar retired in favour of `?` in the
  corner, enter in overview jumps to config for the selected host, and
  shift-tab cycles the tabs backwards.
- The GUI retired at v0.3.0, in favour of the terminal UI; the native
  Windows build retired there too — WSL runs the Linux build. Releases now
  ship macOS and Linux, sign and notarize the bare binaries, and publish
  with the gh CLI: no third-party actions left in the pipeline.
- Release binaries roughly halved: the profile chooses size over speed,
  because this tool waits on ssh, not on itself.

## 0.3.0 — 2026-07-31

- The terminal UI is the default shell: `cargo install sshctl` now builds
  `sshctl-tui` alone — it is the shell that works everywhere, and the
  cheapest to build. The CLI and the GUI are one feature flag away
  (`--features cli`, `--features gui`, `--all-features` for everything);
  the release archives still hold all three.

## 0.2.0 — 2026-07-31

- A third shell: `sshctl-tui`, the same four tabs in plain characters, for
  over ssh, tmux and machines without a screen. Same core, same save screen
  with its two separate questions, same proof.
- Each shell sits behind its own cargo feature, so nobody compiles or
  installs more than the shell they want:
  `cargo install sshctl --no-default-features --features tui`.
- The save judgement (does the rewrite change anything? what do your edits
  change?) moved into the library, shared by both interactive shells.
- The "will not survive a rewrite" banner no longer counts lines your own
  edits add — the save screen judges those with ssh.

## 0.1.0 — 2026-07-30

The first public release: show, check and safely rewrite `~/.ssh/config`,
with a CLI and a GUI on one core.

- `list`, `show`, `write`, `doctor`, `explain` and `add` on the command
  line; the same core behind a four-tab window (overview, config, keys,
  known_hosts).
- A rewrite is only written once `ssh -G` proves it changes nothing about
  any connection; `--force` overrides, never silently. The GUI asks two
  separate questions: whether the rewrite itself changes anything, and what
  your own edits change.
- The doctor checks the file, the network and the real login in three
  layers, understands ProxyJump chains and ProxyCommand, tries every
  resolved address, and refuses to guess: an unrecognised ssh error is
  reported as "could not tell", not as success.
- known_hosts is read through the files ssh itself names, compared per name
  rather than per key, and rewritten atomically with a backup.
- Quoted `Host "my server"` patterns, group headings, trailing comments,
  `=` notation, and `Match`/`Include` passed through in place.

Built in collaboration with Claude (Anthropic): the first version together
with Claude Opus 5; the in-depth review, the fixes and the optimisations
with Claude Fable 5.
