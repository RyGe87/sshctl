# Changelog

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
