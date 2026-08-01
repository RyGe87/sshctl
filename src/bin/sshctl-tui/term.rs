//! A terminal layer of its own: raw mode, keys, cells — and nothing else.
//!
//! This replaces ratatui for exactly the surface the shell above uses, with
//! the same names, so the shell did not have to change. It leans on the
//! platform the way the whole tool does: `stty` puts the terminal in raw
//! mode and reports its size, ANSI sequences do the drawing, and a thread
//! reading `/dev/tty` turns bytes into keys. Unix only, like the rest.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- style ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    Red,
    Green,
    Yellow,
    Blue,
    Cyan,
    DarkGray,
}

impl Color {
    /// Palette slot, sent as `38;5;N` — the same bytes crossterm sent.
    /// The classic `31`-style codes name the same slots on paper, but
    /// Terminal.app and friends colour the two forms from different tables,
    /// and the eye notices. Byte-for-byte equal is the only equal.
    fn slot(self) -> &'static str {
        match self {
            Color::Red => "1",
            Color::Green => "2",
            Color::Yellow => "3",
            Color::Blue => "4",
            Color::Cyan => "6",
            Color::DarkGray => "8",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modifier(u8);

impl Modifier {
    pub const BOLD: Modifier = Modifier(1);
    pub const REVERSED: Modifier = Modifier(2);

    fn contains(self, other: Modifier) -> bool {
        self.0 & other.0 == other.0
    }
}

impl std::ops::BitOr for Modifier {
    type Output = Modifier;
    fn bitor(self, rhs: Modifier) -> Modifier {
        Modifier(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Style {
    pub fg: Option<Color>,
    pub bg: Option<Color>,
    modifiers: Modifier,
}

impl Style {
    pub fn new() -> Style {
        Style::default()
    }

    pub fn fg(mut self, color: Color) -> Style {
        self.fg = Some(color);
        self
    }

    pub fn bg(mut self, color: Color) -> Style {
        self.bg = Some(color);
        self
    }

    pub fn add_modifier(mut self, m: Modifier) -> Style {
        self.modifiers = self.modifiers | m;
        self
    }

    /// The other style wins wherever it says something.
    fn patched_with(self, over: Style) -> Style {
        Style {
            fg: over.fg.or(self.fg),
            bg: over.bg.or(self.bg),
            modifiers: self.modifiers | over.modifiers,
        }
    }

    fn sgr(self) -> String {
        let mut codes: Vec<String> = vec!["0".to_string()];
        if self.modifiers.contains(Modifier::BOLD) {
            codes.push("1".to_string());
        }
        if self.modifiers.contains(Modifier::REVERSED) {
            codes.push("7".to_string());
        }
        if let Some(fg) = self.fg {
            codes.push(format!("38;5;{}", fg.slot()));
        }
        if let Some(bg) = self.bg {
            codes.push(format!("48;5;{}", bg.slot()));
        }
        format!("\x1b[{}m", codes.join(";"))
    }
}

// ----------------------------------------------------------------- text ----

use std::borrow::Cow;

#[derive(Debug, Clone, Default)]
pub struct Span<'a> {
    pub content: Cow<'a, str>,
    pub style: Style,
}

impl<'a> Span<'a> {
    pub fn raw(content: impl Into<Cow<'a, str>>) -> Span<'a> {
        Span {
            content: content.into(),
            style: Style::default(),
        }
    }

    pub fn styled(content: impl Into<Cow<'a, str>>, style: Style) -> Span<'a> {
        Span {
            content: content.into(),
            style,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Line<'a> {
    pub spans: Vec<Span<'a>>,
}

impl<'a> From<Vec<Span<'a>>> for Line<'a> {
    fn from(spans: Vec<Span<'a>>) -> Line<'a> {
        Line { spans }
    }
}

impl<'a> From<Span<'a>> for Line<'a> {
    fn from(span: Span<'a>) -> Line<'a> {
        Line { spans: vec![span] }
    }
}

impl<'a> From<&'a str> for Line<'a> {
    fn from(text: &'a str) -> Line<'a> {
        Line::from(Span::raw(text))
    }
}

impl<'a> From<String> for Line<'a> {
    fn from(text: String) -> Line<'a> {
        Line::from(Span::raw(text))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Text<'a> {
    pub lines: Vec<Line<'a>>,
}

impl<'a> From<Vec<Line<'a>>> for Text<'a> {
    fn from(lines: Vec<Line<'a>>) -> Text<'a> {
        Text { lines }
    }
}

impl<'a> From<Line<'a>> for Text<'a> {
    fn from(line: Line<'a>) -> Text<'a> {
        Text { lines: vec![line] }
    }
}

// --------------------------------------------------------------- layout ----

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u16,
    pub y: u16,
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, Clone, Copy)]
pub enum Constraint {
    Length(u16),
    Min(u16),
}

pub struct Layout {
    constraints: Vec<Constraint>,
    vertical: bool,
}

impl Layout {
    pub fn vertical(constraints: impl IntoIterator<Item = Constraint>) -> Layout {
        Layout {
            constraints: constraints.into_iter().collect(),
            vertical: true,
        }
    }

    pub fn horizontal(constraints: impl IntoIterator<Item = Constraint>) -> Layout {
        Layout {
            constraints: constraints.into_iter().collect(),
            vertical: false,
        }
    }

    /// Fixed lengths first; whatever remains is shared by the `Min`s, each
    /// getting at least its minimum and an equal slice of the surplus.
    pub fn split(self, area: Rect) -> Vec<Rect> {
        let total = if self.vertical {
            area.height
        } else {
            area.width
        };
        let fixed: u32 = self
            .constraints
            .iter()
            .map(|c| match c {
                Constraint::Length(n) => u32::from(*n),
                Constraint::Min(n) => u32::from(*n),
            })
            .sum();
        let mins = self
            .constraints
            .iter()
            .filter(|c| matches!(c, Constraint::Min(_)))
            .count() as u32;
        let surplus = u32::from(total).saturating_sub(fixed);
        let (each, mut leftover) = if mins == 0 {
            (0, 0)
        } else {
            (surplus / mins, surplus % mins)
        };

        let mut out = Vec::with_capacity(self.constraints.len());
        let mut at = if self.vertical { area.y } else { area.x };
        let end = at.saturating_add(total);
        for c in &self.constraints {
            let want = match c {
                Constraint::Length(n) => u32::from(*n),
                Constraint::Min(n) => {
                    let extra = if leftover > 0 {
                        leftover -= 1;
                        1
                    } else {
                        0
                    };
                    u32::from(*n) + each + extra
                }
            };
            let size = want.min(u32::from(end.saturating_sub(at))) as u16;
            out.push(if self.vertical {
                Rect {
                    x: area.x,
                    y: at,
                    width: area.width,
                    height: size,
                }
            } else {
                Rect {
                    x: at,
                    y: area.y,
                    width: size,
                    height: area.height,
                }
            });
            at = at.saturating_add(size);
        }
        out
    }

    pub fn areas<const N: usize>(self, area: Rect) -> [Rect; N] {
        self.split(area)
            .try_into()
            .expect("areas() asked for a different count than the constraints given")
    }
}

// -------------------------------------------------------------- widgets ----

pub trait Widget {
    fn render(self, area: Rect, frame: &mut Frame);
}

#[derive(Debug, Clone, Default)]
pub struct Block {
    title: Option<String>,
}

impl Block {
    pub fn bordered() -> Block {
        Block::default()
    }

    pub fn title(mut self, title: impl Into<String>) -> Block {
        self.title = Some(title.into());
        self
    }

    /// Draws the border and gives back the space inside it.
    fn render_frame(&self, area: Rect, frame: &mut Frame) -> Rect {
        if area.width < 2 || area.height < 2 {
            return Rect::default();
        }
        let style = Style::default();
        let (left, right) = (area.x, area.x + area.width - 1);
        let (top, bottom) = (area.y, area.y + area.height - 1);
        for x in left..=right {
            frame.set(x, top, '─', style);
            frame.set(x, bottom, '─', style);
        }
        for y in top..=bottom {
            frame.set(left, y, '│', style);
            frame.set(right, y, '│', style);
        }
        frame.set(left, top, '┌', style);
        frame.set(right, top, '┐', style);
        frame.set(left, bottom, '└', style);
        frame.set(right, bottom, '┘', style);
        if let Some(title) = &self.title {
            let mut x = left + 1;
            for ch in title.chars() {
                if x >= right {
                    break;
                }
                frame.set(x, top, ch, style);
                x += 1;
            }
        }
        Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width - 2,
            height: area.height - 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Wrap {
    pub trim: bool,
}

pub struct Paragraph<'a> {
    text: Text<'a>,
    block: Option<Block>,
    wrap: Option<Wrap>,
}

impl<'a> Paragraph<'a> {
    pub fn new(text: impl Into<Text<'a>>) -> Paragraph<'a> {
        Paragraph {
            text: text.into(),
            block: None,
            wrap: None,
        }
    }

    pub fn block(mut self, block: Block) -> Paragraph<'a> {
        self.block = Some(block);
        self
    }

    pub fn wrap(mut self, wrap: Wrap) -> Paragraph<'a> {
        self.wrap = Some(wrap);
        self
    }
}

/// One line flattened to characters, so wrapping and drawing need no more
/// span bookkeeping.
fn flatten(line: &Line) -> Vec<(char, Style)> {
    line.spans
        .iter()
        .flat_map(|s| s.content.chars().map(|c| (c, s.style)))
        .collect()
}

/// Breaks a flattened line into rows of at most `width`, preferring to break
/// after the last space that still fits.
fn wrap_chars(chars: &[(char, Style)], width: usize) -> Vec<Vec<(char, Style)>> {
    if width == 0 {
        return vec![Vec::new()];
    }
    if chars.is_empty() {
        return vec![Vec::new()];
    }
    let mut rows = Vec::new();
    let mut rest = chars;
    while rest.len() > width {
        let cut = rest[..=width - 1]
            .iter()
            .rposition(|(c, _)| *c == ' ')
            .map(|i| i + 1)
            .unwrap_or(width);
        rows.push(rest[..cut].to_vec());
        rest = &rest[cut..];
    }
    rows.push(rest.to_vec());
    rows
}

impl Widget for Paragraph<'_> {
    fn render(self, area: Rect, frame: &mut Frame) {
        let inner = match &self.block {
            Some(block) => block.render_frame(area, frame),
            None => area,
        };
        if inner.width == 0 || inner.height == 0 {
            return;
        }
        let width = inner.width as usize;
        let mut rows: Vec<Vec<(char, Style)>> = Vec::new();
        for line in &self.text.lines {
            let chars = flatten(line);
            match self.wrap {
                Some(wrap) => {
                    let mut wrapped = wrap_chars(&chars, width);
                    if wrap.trim {
                        for row in &mut wrapped {
                            let spaces = row.iter().take_while(|(c, _)| *c == ' ').count();
                            row.drain(..spaces);
                        }
                    }
                    rows.extend(wrapped);
                }
                None => rows.push(chars.into_iter().take(width).collect()),
            }
        }
        for (dy, row) in rows.iter().take(inner.height as usize).enumerate() {
            for (dx, (ch, style)) in row.iter().take(width).enumerate() {
                frame.set(inner.x + dx as u16, inner.y + dy as u16, *ch, *style);
            }
        }
    }
}

pub struct Tabs<'a> {
    titles: Vec<Line<'a>>,
    selected: usize,
    highlight: Style,
}

impl<'a> Tabs<'a> {
    pub fn new(titles: Vec<Line<'a>>) -> Tabs<'a> {
        Tabs {
            titles,
            selected: 0,
            highlight: Style::default(),
        }
    }

    pub fn select(mut self, index: usize) -> Tabs<'a> {
        self.selected = index;
        self
    }

    pub fn highlight_style(mut self, style: Style) -> Tabs<'a> {
        self.highlight = style;
        self
    }
}

impl Widget for Tabs<'_> {
    fn render(self, area: Rect, frame: &mut Frame) {
        if area.height == 0 {
            return;
        }
        let mut x = area.x;
        let end = area.x.saturating_add(area.width);
        for (i, title) in self.titles.iter().enumerate() {
            if i > 0 {
                if x >= end {
                    break;
                }
                frame.set(x, area.y, '│', Style::default());
                x += 1;
            }
            for (ch, style) in flatten(title) {
                if x >= end {
                    break;
                }
                let style = if i == self.selected {
                    style.patched_with(self.highlight)
                } else {
                    style
                };
                frame.set(x, area.y, ch, style);
                x += 1;
            }
        }
    }
}

/// Blanks an area, so a modal never shows the screen underneath through its
/// gaps.
pub struct Clear;

impl Widget for Clear {
    fn render(self, area: Rect, frame: &mut Frame) {
        for y in area.y..area.y.saturating_add(area.height) {
            for x in area.x..area.x.saturating_add(area.width) {
                frame.set(x, y, ' ', Style::default());
            }
        }
    }
}

// ---------------------------------------------------------------- frame ----

#[derive(Debug, Clone, Copy, PartialEq)]
struct Cell {
    ch: char,
    style: Style,
}

const BLANK: Cell = Cell {
    ch: ' ',
    style: Style {
        fg: None,
        bg: None,
        modifiers: Modifier(0),
    },
};

pub struct Frame {
    width: u16,
    height: u16,
    cells: Vec<Cell>,
}

impl Frame {
    pub fn area(&self) -> Rect {
        Rect {
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
        }
    }

    pub fn render_widget(&mut self, widget: impl Widget, area: Rect) {
        widget.render(area, self);
    }

    fn set(&mut self, x: u16, y: u16, ch: char, style: Style) {
        if x >= self.width || y >= self.height {
            return;
        }
        self.cells[usize::from(y) * usize::from(self.width) + usize::from(x)] = Cell { ch, style };
    }
}

// ------------------------------------------------------------- terminal ----

static SAVED_STTY: OnceLock<String> = OnceLock::new();

/// Runs stty against the controlling terminal, not stdin: stdout may be
/// captured, the tty is still the tty.
fn stty(args: &[&str]) -> Option<String> {
    let tty = std::fs::File::open("/dev/tty").ok()?;
    let out = std::process::Command::new("stty")
        .args(args)
        .stdin(tty)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn term_size() -> (u16, u16) {
    // "rows cols" — anything unreadable, including the "0 0" of a fresh
    // pseudo-terminal, falls back to a classic 80x24.
    let report = stty(&["size"]).unwrap_or_default();
    let mut parts = report.split_whitespace();
    let mut dimension = |fallback: u16| {
        parts
            .next()
            .and_then(|p| p.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(fallback)
    };
    let rows = dimension(24);
    let cols = dimension(80);
    (cols, rows)
}

pub struct DefaultTerminal {
    width: u16,
    height: u16,
    sized_at: Instant,
    previous: Vec<Cell>,
}

pub fn init() -> DefaultTerminal {
    if let Some(saved) = stty(&["-g"]) {
        let _ = SAVED_STTY.set(saved);
    }
    // Raw, no echo; reads return after a tenth of a second even when no key
    // came, which is what lets the reader thread notice a lone Esc.
    stty(&["raw", "-echo", "min", "0", "time", "1"]);
    print!("\x1b[?1049h\x1b[?25l\x1b[2J");
    let _ = std::io::stdout().flush();

    // A panic must never leave the terminal raw: restore first, then report.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        previous_hook(info);
    }));

    spawn_reader();
    let (width, height) = term_size();
    DefaultTerminal {
        width,
        height,
        sized_at: Instant::now(),
        previous: Vec::new(),
    }
}

pub fn restore() {
    print!("\x1b[0m\x1b[?1049l\x1b[?25h");
    let _ = std::io::stdout().flush();
    if let Some(saved) = SAVED_STTY.get() {
        stty(&[saved.as_str()]);
    }
}

impl DefaultTerminal {
    pub fn draw(&mut self, render: impl FnOnce(&mut Frame)) -> std::io::Result<()> {
        // The terminal may have been resized; asking costs a process, so ask
        // at most once a second. The next draw is never far away.
        if self.sized_at.elapsed() >= Duration::from_secs(1) {
            let (w, h) = term_size();
            self.sized_at = Instant::now();
            if (w, h) != (self.width, self.height) {
                self.width = w;
                self.height = h;
                self.previous.clear();
                print!("\x1b[2J");
            }
        }

        let mut frame = Frame {
            width: self.width,
            height: self.height,
            cells: vec![BLANK; usize::from(self.width) * usize::from(self.height)],
        };
        render(&mut frame);

        // Only rows that changed travel over the wire: this shell is at its
        // best over ssh, where every byte is round-trip time.
        let mut out = String::from("\x1b[?2026h");
        let width = usize::from(self.width);
        for y in 0..usize::from(self.height) {
            let row = &frame.cells[y * width..(y + 1) * width];
            let unchanged = self
                .previous
                .get(y * width..(y + 1) * width)
                .is_some_and(|prev| prev == row);
            if unchanged {
                continue;
            }
            out.push_str(&format!("\x1b[{};1H", y + 1));
            let mut current: Option<Style> = None;
            for cell in row {
                if current != Some(cell.style) {
                    out.push_str(&cell.style.sgr());
                    current = Some(cell.style);
                }
                out.push(cell.ch);
            }
            out.push_str("\x1b[0m");
        }
        out.push_str("\x1b[?2026l");
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(out.as_bytes())?;
        stdout.flush()?;
        self.previous = frame.cells;
        Ok(())
    }
}

// ----------------------------------------------------------------- keys ----

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    Char(char),
    Enter,
    Esc,
    Tab,
    BackTab,
    Backspace,
    Delete,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyModifiers(u8);

impl KeyModifiers {
    pub const NONE: KeyModifiers = KeyModifiers(0);
    pub const CONTROL: KeyModifiers = KeyModifiers(1);

    pub fn contains(self, other: KeyModifiers) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEventKind {
    Press,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
    pub kind: KeyEventKind,
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::NONE,
        kind: KeyEventKind::Press,
    }
}

fn ctrl(c: char) -> KeyEvent {
    KeyEvent {
        code: KeyCode::Char(c),
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
    }
}

/// What the bytes at the front of the buffer amount to: a key, a complete
/// sequence this decoder does not speak (consumed, no key), or the prefix of
/// something longer that needs more bytes.
enum Parsed {
    Key(KeyEvent, usize),
    Skip(usize),
    Prefix,
}

fn parse_key(buf: &[u8]) -> Parsed {
    let Some(first) = buf.first() else {
        return Parsed::Prefix;
    };
    match first {
        0x1b => parse_escape(buf),
        b'\r' | b'\n' => Parsed::Key(key(KeyCode::Enter), 1),
        0x7f | 0x08 => Parsed::Key(key(KeyCode::Backspace), 1),
        b'\t' => Parsed::Key(key(KeyCode::Tab), 1),
        b @ 0x01..=0x1a => Parsed::Key(ctrl((b'a' + *b - 1) as char), 1),
        b if *b < 0x20 => Parsed::Skip(1),
        _ => parse_utf8(buf),
    }
}

fn parse_escape(buf: &[u8]) -> Parsed {
    match buf.get(1) {
        None => Parsed::Prefix, // a lone Esc so far; the timeout decides
        Some(b'[') => {
            // CSI: parameters, then one final byte in @..~.
            let mut i = 2;
            while let Some(b) = buf.get(i) {
                if (0x40..=0x7e).contains(b) {
                    return match csi_key(*b, &buf[2..i]) {
                        Some(event) => Parsed::Key(event, i + 1),
                        None => Parsed::Skip(i + 1),
                    };
                }
                i += 1;
            }
            Parsed::Prefix
        }
        Some(b'O') => {
            let Some(third) = buf.get(2) else {
                return Parsed::Prefix;
            };
            let code = match third {
                b'A' => KeyCode::Up,
                b'B' => KeyCode::Down,
                b'C' => KeyCode::Right,
                b'D' => KeyCode::Left,
                b'H' => KeyCode::Home,
                b'F' => KeyCode::End,
                _ => return Parsed::Skip(3),
            };
            Parsed::Key(key(code), 3)
        }
        // Esc followed by an ordinary byte: treat the Esc as itself and let
        // the next round have the byte.
        Some(_) => Parsed::Key(key(KeyCode::Esc), 1),
    }
}

fn csi_key(final_byte: u8, params: &[u8]) -> Option<KeyEvent> {
    let code = match final_byte {
        b'A' => KeyCode::Up,
        b'B' => KeyCode::Down,
        b'C' => KeyCode::Right,
        b'D' => KeyCode::Left,
        b'H' => KeyCode::Home,
        b'F' => KeyCode::End,
        b'Z' => KeyCode::BackTab,
        b'~' => {
            let number: u16 = params
                .split(|b| *b == b';')
                .next()
                .and_then(|p| std::str::from_utf8(p).ok())
                .and_then(|p| p.parse().ok())?;
            match number {
                1 | 7 => KeyCode::Home,
                3 => KeyCode::Delete,
                4 | 8 => KeyCode::End,
                5 => KeyCode::PageUp,
                6 => KeyCode::PageDown,
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(key(code))
}

fn parse_utf8(buf: &[u8]) -> Parsed {
    let len = match buf[0] {
        b if b < 0x80 => 1,
        b if b & 0b1110_0000 == 0b1100_0000 => 2,
        b if b & 0b1111_0000 == 0b1110_0000 => 3,
        b if b & 0b1111_1000 == 0b1111_0000 => 4,
        _ => return Parsed::Skip(1),
    };
    if buf.len() < len {
        return Parsed::Prefix;
    }
    match std::str::from_utf8(&buf[..len]) {
        Ok(s) => match s.chars().next() {
            Some(c) => Parsed::Key(key(KeyCode::Char(c)), len),
            None => Parsed::Skip(len),
        },
        Err(_) => Parsed::Skip(1),
    }
}

/// Turns buffered bytes into keys. `timed_out` says the tty had nothing
/// more, which is what makes a lone Esc a keypress instead of a prefix.
fn drain_keys(buf: &mut Vec<u8>, timed_out: bool) -> Vec<KeyEvent> {
    let mut events = Vec::new();
    loop {
        match parse_key(buf) {
            Parsed::Key(event, used) => {
                events.push(event);
                buf.drain(..used);
            }
            Parsed::Skip(used) => {
                buf.drain(..used);
            }
            Parsed::Prefix => {
                if timed_out && !buf.is_empty() {
                    if buf == &[0x1b] {
                        events.push(key(KeyCode::Esc));
                    }
                    // Either a lone Esc, now delivered, or a truncated
                    // sequence nobody will ever finish; both are done with.
                    buf.clear();
                }
                return events;
            }
        }
    }
}

struct EventQueue {
    receiver: Receiver<Event>,
    pending: VecDeque<Event>,
}

static EVENTS: OnceLock<Mutex<EventQueue>> = OnceLock::new();

fn spawn_reader() {
    let (sender, receiver): (Sender<Event>, Receiver<Event>) = channel();
    let _ = EVENTS.set(Mutex::new(EventQueue {
        receiver,
        pending: VecDeque::new(),
    }));
    std::thread::spawn(move || {
        let Ok(mut tty) = std::fs::File::open("/dev/tty") else {
            return;
        };
        let mut pending: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 64];
        loop {
            let n = tty.read(&mut chunk).unwrap_or(0);
            pending.extend_from_slice(&chunk[..n]);
            for event in drain_keys(&mut pending, n == 0) {
                if sender.send(Event::Key(event)).is_err() {
                    return;
                }
            }
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    Key(KeyEvent),
}

pub mod event {
    use super::{EVENTS, RecvTimeoutError};
    pub use super::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
    use std::time::Duration;

    /// True when `read` will return without waiting.
    pub fn poll(timeout: Duration) -> std::io::Result<bool> {
        let Some(queue) = EVENTS.get() else {
            std::thread::sleep(timeout);
            return Ok(false);
        };
        let mut queue = queue.lock().expect("event queue poisoned");
        if !queue.pending.is_empty() {
            return Ok(true);
        }
        match queue.receiver.recv_timeout(timeout) {
            Ok(event) => {
                queue.pending.push_back(event);
                Ok(true)
            }
            Err(RecvTimeoutError::Timeout) => Ok(false),
            // The reader thread only dies when the tty is gone; quietly
            // reporting "nothing" would spin the caller at full speed.
            Err(RecvTimeoutError::Disconnected) => {
                std::thread::sleep(timeout);
                Ok(false)
            }
        }
    }

    pub fn read() -> std::io::Result<Event> {
        let queue = EVENTS
            .get()
            .ok_or_else(|| std::io::Error::other("terminal was never initialised"))?;
        let mut queue = queue.lock().expect("event queue poisoned");
        if let Some(event) = queue.pending.pop_front() {
            return Ok(event);
        }
        queue.receiver.recv().map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(bytes: &[u8], timed_out: bool) -> Vec<KeyEvent> {
        let mut buf = bytes.to_vec();
        drain_keys(&mut buf, timed_out)
    }

    #[test]
    fn plain_characters_and_uppercase() {
        assert_eq!(
            keys(b"aS", true),
            vec![key(KeyCode::Char('a')), key(KeyCode::Char('S'))]
        );
    }

    #[test]
    fn utf8_characters_survive() {
        assert_eq!(keys("é".as_bytes(), true), vec![key(KeyCode::Char('é'))]);
    }

    #[test]
    fn a_half_utf8_character_waits_for_the_rest() {
        assert_eq!(keys(&"é".as_bytes()[..1], false), vec![]);
    }

    #[test]
    fn control_a_is_a_modifier_not_a_character() {
        assert_eq!(keys(&[0x01], true), vec![ctrl('a')]);
    }

    #[test]
    fn enter_backspace_tab() {
        assert_eq!(
            keys(&[b'\r', 0x7f, b'\t'], true),
            vec![
                key(KeyCode::Enter),
                key(KeyCode::Backspace),
                key(KeyCode::Tab)
            ]
        );
    }

    #[test]
    fn arrows_in_both_dialects() {
        assert_eq!(
            keys(b"\x1b[A\x1bOB", true),
            vec![key(KeyCode::Up), key(KeyCode::Down)]
        );
    }

    #[test]
    fn paging_home_end_delete_backtab() {
        assert_eq!(
            keys(b"\x1b[5~\x1b[6~\x1b[H\x1b[F\x1b[3~\x1b[Z", true),
            vec![
                key(KeyCode::PageUp),
                key(KeyCode::PageDown),
                key(KeyCode::Home),
                key(KeyCode::End),
                key(KeyCode::Delete),
                key(KeyCode::BackTab),
            ]
        );
    }

    #[test]
    fn a_lone_esc_needs_the_timeout_to_speak() {
        assert_eq!(keys(&[0x1b], false), vec![]);
        assert_eq!(keys(&[0x1b], true), vec![key(KeyCode::Esc)]);
    }

    #[test]
    fn esc_before_a_plain_byte_is_esc_then_the_byte() {
        assert_eq!(
            keys(b"\x1bq", true),
            vec![key(KeyCode::Esc), key(KeyCode::Char('q'))]
        );
    }

    #[test]
    fn an_unknown_sequence_is_swallowed_whole() {
        assert_eq!(keys(b"\x1b[99~", false), vec![]);
    }

    #[test]
    fn an_unknown_sequence_does_not_eat_the_key_after_it() {
        assert_eq!(keys(b"\x1b[99~q", false), vec![key(KeyCode::Char('q'))]);
    }

    #[test]
    fn modified_arrows_still_move() {
        assert_eq!(keys(b"\x1b[1;5A", true), vec![key(KeyCode::Up)]);
    }

    #[test]
    fn colours_travel_as_palette_slots_like_crossterm_sent_them() {
        let style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
        assert_eq!(style.sgr(), "\x1b[0;1;38;5;6m");
        let dim = Style::new().fg(Color::DarkGray);
        assert_eq!(dim.sgr(), "\x1b[0;38;5;8m");
        let tab = Style::new().add_modifier(Modifier::BOLD).bg(Color::Blue);
        assert_eq!(tab.sgr(), "\x1b[0;1;48;5;4m");
    }

    #[test]
    fn wrapping_prefers_the_last_space() {
        let line = Line::from("one two three");
        let rows = wrap_chars(&flatten(&line), 8);
        let texts: Vec<String> = rows
            .iter()
            .map(|r| r.iter().map(|(c, _)| c).collect())
            .collect();
        assert_eq!(texts, vec!["one two ", "three"]);
    }

    #[test]
    fn wrapping_hard_breaks_a_word_wider_than_the_area() {
        let line = Line::from("abcdefghij");
        let rows = wrap_chars(&flatten(&line), 4);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn layout_gives_fixed_rows_their_length_and_min_the_rest() {
        let areas = Layout::vertical(vec![
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(2),
        ])
        .split(Rect {
            x: 0,
            y: 0,
            width: 80,
            height: 24,
        });
        assert_eq!(areas[0].height, 1);
        assert_eq!(areas[1].height, 21);
        assert_eq!(areas[2].height, 2);
        assert_eq!(areas[2].y, 22);
    }

    #[test]
    fn layout_never_leaves_the_area() {
        let areas =
            Layout::vertical(vec![Constraint::Length(30), Constraint::Length(30)]).split(Rect {
                x: 0,
                y: 0,
                width: 10,
                height: 20,
            });
        assert_eq!(areas[0].height, 20);
        assert_eq!(areas[1].height, 0);
    }

    #[test]
    fn a_bordered_paragraph_draws_its_frame_and_title() {
        let mut frame = Frame {
            width: 12,
            height: 4,
            cells: vec![BLANK; 48],
        };
        let text = Paragraph::new(Line::from("hi")).block(Block::bordered().title("T"));
        frame.render_widget(text, frame.area());
        let row: String = frame.cells[..12].iter().map(|c| c.ch).collect();
        assert_eq!(row, "┌T─────────┐");
        assert_eq!(frame.cells[13].ch, 'h');
        assert_eq!(frame.cells[14].ch, 'i');
    }
}
