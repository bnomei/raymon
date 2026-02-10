//! Ratatui interface for Raymon.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use memchr::{memchr, memchr2};
use rapidfuzz::fuzz;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, Wrap,
};
use ratatui::Frame;
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tempfile::{NamedTempFile, TempPath};
use thiserror::Error;
use tiktoken_rs::o200k_base_singleton;

use crate::colors::{canonical_color_name, OFFICIAL_COLORS};

/// Key handling modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    Command,
    Goto,
    Space,
    Picker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusPane {
    Logs,
    Detail,
    Archives,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpMode {
    Space,
    Keymap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerKind {
    Screens,
    Colors,
    Types,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerItemId {
    Screen(String),
    Color(String),
    EntryType(String),
    ClearColors,
    ClearTypes,
    ClearScreens,
}

#[derive(Debug, Clone)]
pub struct PickerItem {
    pub label: String,
    pub meta: Option<String>,
    pub id: PickerItemId,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub struct PickerState {
    pub kind: PickerKind,
    pub query: InputState,
    pub items: Vec<PickerItem>,
    pub filtered: Vec<usize>,
    pub selected: usize,
    pub multi_select: bool,
}

impl PickerState {
    pub fn new(kind: PickerKind, items: Vec<PickerItem>, multi_select: bool) -> Self {
        let mut picker = Self {
            kind,
            query: InputState::default(),
            items,
            filtered: Vec::new(),
            selected: 0,
            multi_select,
        };
        picker.recompute();
        picker
    }

    fn recompute(&mut self) {
        let query = self.query.buffer.trim();
        if query.is_empty() {
            self.filtered = (0..self.items.len()).collect();
        } else {
            self.filtered = fuzzy_rank_items(&self.items, query);
        }
        if self.filtered.is_empty() {
            self.selected = 0;
        } else if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len() - 1;
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.filtered.len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        let mut next = self.selected as i32 + delta;
        if next < 0 {
            next = 0;
        } else if next >= len as i32 {
            next = len as i32 - 1;
        }
        self.selected = next as usize;
    }

    fn selected_item(&self) -> Option<&PickerItem> {
        let idx = *self.filtered.get(self.selected)?;
        self.items.get(idx)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FilterState {
    pub types: BTreeSet<String>,
    pub colors: BTreeSet<String>,
}

/// A single log entry displayed in the list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: u64,
    pub uuid: String,
    pub message: String,
    pub detail: String,
    pub origin: Option<String>,
    pub origin_file: Option<String>,
    pub origin_line: Option<u32>,
    pub timestamp: Option<u64>,
    pub entry_type: Option<String>,
    pub color: Option<String>,
    pub screen: Option<String>,
}

/// File-backed archive entry.
#[derive(Debug, Clone)]
pub struct ArchiveFile {
    pub name: String,
    pub count: usize,
    pub path: PathBuf,
    pub live: bool,
}

/// Input buffer with a cursor.
#[derive(Debug, Clone, Default)]
pub struct InputState {
    pub buffer: String,
    pub cursor: usize,
}

impl InputState {
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    pub fn insert_str(&mut self, value: &str) {
        if self.cursor >= self.buffer.len() {
            self.buffer.push_str(value);
            self.cursor = self.buffer.len();
            return;
        }
        self.buffer.insert_str(self.cursor, value);
        self.cursor += value.len();
    }

    pub fn backspace(&mut self) {
        if self.cursor == 0 || self.buffer.is_empty() {
            return;
        }
        self.cursor -= 1;
        self.buffer.remove(self.cursor);
    }
}

#[derive(Debug, Clone)]
pub struct RenameArchiveState {
    pub path: PathBuf,
    pub input: InputState,
    pub overwrite: bool,
}

#[derive(Debug, Clone)]
pub struct TuiPalette {
    pub fg: Color,
    pub bg: Color,
    pub ansi: [Color; 16],
}

impl TuiPalette {
    pub const CSV_LEN: usize = 18;

    pub fn parse_csv(value: &str) -> Result<Self, String> {
        let parts: Vec<&str> = value.split(',').map(|part| part.trim()).collect();
        if parts.len() != Self::CSV_LEN {
            return Err(format!(
                "expected {} comma-separated colors (fg,bg,black,red,green,yellow,blue,magenta,cyan,white,bright_black,bright_red,bright_green,bright_yellow,bright_blue,bright_magenta,bright_cyan,bright_white), got {}",
                Self::CSV_LEN,
                parts.len()
            ));
        }

        let fg = parse_palette_color(parts[0])?;
        let bg = parse_palette_color(parts[1])?;

        let mut ansi = [Color::Reset; 16];
        for (idx, part) in parts.iter().skip(2).enumerate() {
            ansi[idx] = parse_palette_color(part)?;
        }

        Ok(Self { fg, bg, ansi })
    }

    pub fn ansi_color(&self, idx: usize) -> Color {
        self.ansi[idx]
    }
}

fn parse_palette_color(value: &str) -> Result<Color, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("empty color".to_string());
    }

    let lower = trimmed.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("rgb:") {
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() != 3 {
            return Err(format!("invalid rgb: value: {trimmed}"));
        }
        let r = parse_hex_channel(parts[0])?;
        let g = parse_hex_channel(parts[1])?;
        let b = parse_hex_channel(parts[2])?;
        return Ok(Color::Rgb(r, g, b));
    }

    let hex = trimmed
        .strip_prefix('#')
        .or_else(|| trimmed.strip_prefix("0x"))
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);

    if hex.len() != 6 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("invalid hex color: {trimmed} (expected #RRGGBB)"));
    }
    let rgb = u32::from_str_radix(hex, 16).map_err(|_| format!("invalid hex color: {trimmed}"))?;
    let r = ((rgb >> 16) & 0xFF) as u8;
    let g = ((rgb >> 8) & 0xFF) as u8;
    let b = (rgb & 0xFF) as u8;
    Ok(Color::Rgb(r, g, b))
}

fn parse_hex_channel(value: &str) -> Result<u8, String> {
    let value = value.trim();
    if value.len() == 2 {
        let parsed =
            u8::from_str_radix(value, 16).map_err(|_| format!("invalid rgb: component {value}"))?;
        return Ok(parsed);
    }
    if value.len() == 4 {
        let parsed = u16::from_str_radix(value, 16)
            .map_err(|_| format!("invalid rgb: component {value}"))?;
        return Ok((parsed >> 8) as u8);
    }
    Err(format!("invalid rgb: component {value} (expected 2 or 4 hex digits)"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ansi16 {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightBlack,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite,
}

impl Ansi16 {
    const fn idx(self) -> usize {
        match self {
            Self::Black => 0,
            Self::Red => 1,
            Self::Green => 2,
            Self::Yellow => 3,
            Self::Blue => 4,
            Self::Magenta => 5,
            Self::Cyan => 6,
            Self::White => 7,
            Self::BrightBlack => 8,
            Self::BrightRed => 9,
            Self::BrightGreen => 10,
            Self::BrightYellow => 11,
            Self::BrightBlue => 12,
            Self::BrightMagenta => 13,
            Self::BrightCyan => 14,
            Self::BrightWhite => 15,
        }
    }
}

impl From<Ansi16> for Color {
    fn from(value: Ansi16) -> Self {
        match value {
            Ansi16::Black => Color::Black,
            Ansi16::Red => Color::Red,
            Ansi16::Green => Color::Green,
            Ansi16::Yellow => Color::Yellow,
            Ansi16::Blue => Color::Blue,
            Ansi16::Magenta => Color::Magenta,
            Ansi16::Cyan => Color::Cyan,
            Ansi16::White => Color::Gray,
            Ansi16::BrightBlack => Color::DarkGray,
            Ansi16::BrightRed => Color::LightRed,
            Ansi16::BrightGreen => Color::LightGreen,
            Ansi16::BrightYellow => Color::LightYellow,
            Ansi16::BrightBlue => Color::LightBlue,
            Ansi16::BrightMagenta => Color::LightMagenta,
            Ansi16::BrightCyan => Color::LightCyan,
            Ansi16::BrightWhite => Color::White,
        }
    }
}

/// Configuration for editor/IDE integrations.
#[derive(Debug, Clone)]
pub struct TuiConfig {
    pub editor_command: Option<String>,
    pub ide_command: Option<String>,
    pub jq_command: Option<String>,
    pub palette: Option<TuiPalette>,
    pub show_archives_by_default: bool,
    pub archive_dir: Option<PathBuf>,
    pub max_query_len: usize,
    pub jq_timeout_ms: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            editor_command: env::var("VISUAL").ok().or_else(|| env::var("EDITOR").ok()),
            ide_command: env::var("RAYMON_IDE").ok(),
            jq_command: env::var("RAYMON_JQ").ok(),
            palette: None,
            show_archives_by_default: false,
            archive_dir: None,
            max_query_len: 265,
            jq_timeout_ms: 10_000,
        }
    }
}

/// TUI state used for rendering and event handling.
#[derive(Debug, Clone)]
pub struct TuiState {
    pub mode: Mode,
    pub focus: FocusPane,
    pub paused: bool,
    pub logs: Vec<LogEntry>,
    pub queued: Vec<LogEntry>,
    pub filtered: Vec<usize>,
    pub selected: usize,
    pub search: InputState,
    pub search_error: Option<String>,
    pub detail_notice: Option<String>,
    pub filters: FilterState,
    pub screens: Vec<String>,
    pub active_screen: Option<String>,
    pub command: InputState,
    pub show_archives: bool,
    pub archives: Vec<ArchiveFile>,
    pub archive_selected: usize,
    pub json_expanded: bool,
    pub json_raw: bool,
    pub show_decorators: bool,
    pub show_timestamp: bool,
    pub show_filename: bool,
    pub show_color_indicator: bool,
    pub show_labels: bool,
    pub show_message: bool,
    pub show_uuid: bool,
    pub show_help: bool,
    pub help_mode: HelpMode,
    pub help_scroll: u16,
    pub help_viewport_height: u16,
    pub picker: Option<PickerState>,
    pub last_detail_search: Option<DetailSearchResult>,
    pub last_yank: Option<String>,
    pub goto: InputState,
    pub goto_overwrite: bool,
    pub detail_scroll: u16,
    pub detail_viewport_height: u16,
    pub delete_archive_confirm: Option<PathBuf>,
    pub rename_archive: Option<RenameArchiveState>,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            mode: Mode::Normal,
            focus: FocusPane::Logs,
            paused: false,
            logs: Vec::new(),
            queued: Vec::new(),
            filtered: Vec::new(),
            selected: 0,
            search: InputState::default(),
            search_error: None,
            detail_notice: None,
            filters: FilterState::default(),
            screens: Vec::new(),
            active_screen: None,
            command: InputState::default(),
            show_archives: false,
            archives: Vec::new(),
            archive_selected: 0,
            json_expanded: true,
            json_raw: false,
            show_decorators: false,
            show_timestamp: false,
            show_filename: false,
            show_color_indicator: true,
            show_labels: false,
            show_message: true,
            show_uuid: false,
            show_help: false,
            help_mode: HelpMode::Space,
            help_scroll: 0,
            help_viewport_height: 0,
            picker: None,
            last_detail_search: None,
            last_yank: None,
            goto: InputState::default(),
            goto_overwrite: false,
            detail_scroll: 0,
            detail_viewport_height: 0,
            delete_archive_confirm: None,
            rename_archive: None,
        }
    }
}

/// Clipboard abstraction for yank/paste support.
pub trait Clipboard: Send {
    fn get(&mut self) -> Result<String, TuiError>;
    fn set(&mut self, contents: &str) -> Result<(), TuiError>;
}

/// System clipboard using arboard.
#[derive(Default)]
pub struct SystemClipboard {
    inner: Option<arboard::Clipboard>,
}

impl SystemClipboard {
    pub fn new() -> Self {
        Self { inner: None }
    }

    fn ensure(&mut self) -> Result<&mut arboard::Clipboard, TuiError> {
        if self.inner.is_none() {
            self.inner = Some(arboard::Clipboard::new().map_err(TuiError::Clipboard)?);
        }
        Ok(self.inner.as_mut().expect("clipboard just initialized"))
    }
}

impl Clipboard for SystemClipboard {
    fn get(&mut self) -> Result<String, TuiError> {
        let clipboard = self.ensure()?;
        clipboard.get_text().map_err(TuiError::Clipboard)
    }

    fn set(&mut self, contents: &str) -> Result<(), TuiError> {
        let clipboard = self.ensure()?;
        clipboard.set_text(contents.to_string()).map_err(TuiError::Clipboard)
    }
}

/// Possible actions requiring external side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    None,
    ClearLogs,
    OpenEditor,
    OpenOrigin,
    Quit,
}

/// Outcome after executing an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    OpenedEditor(PathBuf),
    OpenedOrigin,
    Quit,
}

/// Results for detail search operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailSearchResult {
    Text,
    JsonPath(String),
    Jq(String),
    NotFound,
}

/// Errors raised by the TUI.
#[derive(Debug, Error)]
pub enum TuiError {
    #[error("clipboard error: {0}")]
    Clipboard(#[from] arboard::Error),
    #[error("missing editor command")]
    MissingEditor,
    #[error("missing IDE command")]
    MissingIde,
    #[error("no selected entry")]
    NoSelection,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid command line: {0}")]
    InvalidCommandLine(String),
    #[error("jq not available")]
    JqMissing,
    #[error("jq invocation failed: {0}")]
    JqFailed(String),
    #[error("jq timed out")]
    JqTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct JqFingerprint {
    len: usize,
    prefix: [u8; 8],
    suffix: [u8; 8],
}

impl JqFingerprint {
    fn new(value: &str) -> Self {
        let bytes = value.as_bytes();
        let len = bytes.len();
        let mut prefix = [0u8; 8];
        let mut suffix = [0u8; 8];

        for (idx, byte) in bytes.iter().take(8).enumerate() {
            prefix[idx] = *byte;
        }

        let start = len.saturating_sub(8);
        for (idx, byte) in bytes.iter().skip(start).take(8).enumerate() {
            suffix[idx] = *byte;
        }

        Self { len, prefix, suffix }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetailCacheKey {
    entry_id: Option<u64>,
    entry_timestamp: Option<u64>,
    json_expanded: bool,
    json_raw: bool,
    show_decorators: bool,
    jq_fingerprint: Option<JqFingerprint>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DetailStats {
    lines: usize,
    bytes: usize,
    tokens: usize,
}

#[derive(Debug, Clone)]
struct DetailCache {
    key: DetailCacheKey,
    timestamp_iso: Option<String>,
    render: Text<'static>,
    display_stats: DetailStats,
    blob_stats: DetailStats,
}

#[derive(Default)]
struct LiveBuffer {
    logs: Vec<LogEntry>,
    queued: Vec<LogEntry>,
}

const LIVE_ARCHIVE_FLUSH_EVERY_ENTRIES: usize = 64;
const LIVE_ARCHIVE_FLUSH_EVERY_MS: u64 = 1_000;

struct LiveArchive {
    path: PathBuf,
    writer: BufWriter<std::fs::File>,
    writes_since_flush: usize,
    last_flush_at: Instant,
}

/// Main TUI container.
pub struct Tui {
    pub config: TuiConfig,
    pub state: TuiState,
    clipboard: Box<dyn Clipboard>,
    open_temp: Option<TempPath>,
    detail_cache: Option<DetailCache>,
    live_buffer: Option<LiveBuffer>,
    viewing_archive: Option<PathBuf>,
    live_archive: Option<LiveArchive>,
    follow_tail: bool,
    filter_dirty: bool,
    events_per_min: u32,
    events_bucket_start: Instant,
    events_bucket_idx: usize,
    events_bucket_counts: [u32; 6],
}

impl Default for Tui {
    fn default() -> Self {
        Self::new(TuiConfig::default())
    }
}

impl Tui {
    fn stack_panes_vertically(&self, area: Rect) -> bool {
        let width = area.width;
        if self.state.show_archives {
            width < 110
        } else {
            width < 90
        }
    }

    fn main_areas(&self, area: Rect) -> (Rect, Rect, Option<Rect>) {
        let constraints = if self.state.show_archives {
            vec![Constraint::Percentage(34), Constraint::Percentage(33), Constraint::Percentage(33)]
        } else {
            vec![Constraint::Percentage(50), Constraint::Percentage(50)]
        };
        let direction = if self.stack_panes_vertically(area) {
            Direction::Vertical
        } else {
            Direction::Horizontal
        };
        let chunks = Layout::default().direction(direction).constraints(constraints).split(area);

        let logs = chunks[0];
        let detail = chunks[1];
        let archives = self.state.show_archives.then(|| chunks[2]);
        (logs, detail, archives)
    }

    pub fn new(config: TuiConfig) -> Self {
        let state =
            TuiState { show_archives: config.show_archives_by_default, ..Default::default() };
        let now = Instant::now();
        let mut tui = Self {
            config,
            state,
            clipboard: Box::new(SystemClipboard::new()),
            open_temp: None,
            detail_cache: None,
            live_buffer: None,
            viewing_archive: None,
            live_archive: None,
            follow_tail: false,
            filter_dirty: false,
            events_per_min: 0,
            events_bucket_start: now,
            events_bucket_idx: 0,
            events_bucket_counts: [0; 6],
        };
        tui.init_archives();
        tui
    }

    pub fn with_clipboard(config: TuiConfig, clipboard: Box<dyn Clipboard>) -> Self {
        let state =
            TuiState { show_archives: config.show_archives_by_default, ..Default::default() };
        let now = Instant::now();
        let mut tui = Self {
            config,
            state,
            clipboard,
            open_temp: None,
            detail_cache: None,
            live_buffer: None,
            viewing_archive: None,
            live_archive: None,
            follow_tail: false,
            filter_dirty: false,
            events_per_min: 0,
            events_bucket_start: now,
            events_bucket_idx: 0,
            events_bucket_counts: [0; 6],
        };
        tui.init_archives();
        tui
    }

    pub fn resync_live_logs(&mut self, logs: Vec<LogEntry>, notice: String) {
        if self.viewing_archive.is_some() {
            let live = self.live_buffer.get_or_insert_with(LiveBuffer::default);
            live.logs = logs;
            live.queued.clear();
            self.state.detail_notice = Some(notice);
            return;
        }

        self.state.logs = logs;
        self.state.queued.clear();
        self.rebuild_screens();
        self.detail_cache = None;
        self.state.last_detail_search = None;
        self.recompute_filter();
        self.state.detail_notice = Some(notice);
    }

    fn tick_events_per_min(&mut self, now: Instant) {
        const BUCKET_SECS: u64 = 10;
        const BUCKETS: usize = 6;

        let elapsed = now.duration_since(self.events_bucket_start);
        let steps = (elapsed.as_secs() / BUCKET_SECS) as usize;
        if steps == 0 {
            return;
        }

        if steps >= BUCKETS {
            self.events_bucket_counts = [0; BUCKETS];
            self.events_bucket_idx = 0;
            self.events_bucket_start = now;
            self.events_per_min = 0;
            return;
        }

        for _ in 0..steps {
            self.events_bucket_idx = (self.events_bucket_idx + 1) % BUCKETS;
            self.events_bucket_counts[self.events_bucket_idx] = 0;
        }

        self.events_bucket_start += Duration::from_secs((steps as u64) * BUCKET_SECS);
        self.events_per_min = self.events_bucket_counts.iter().copied().sum();
    }

    fn record_event(&mut self) {
        let now = Instant::now();
        self.tick_events_per_min(now);
        self.events_bucket_counts[self.events_bucket_idx] =
            self.events_bucket_counts[self.events_bucket_idx].saturating_add(1);
    }

    fn init_archives(&mut self) {
        let Some(dir) = self.config.archive_dir.clone() else {
            return;
        };
        if let Err(err) = fs::create_dir_all(&dir) {
            self.state.detail_notice = Some(format!("archive disabled: {err}"));
            return;
        }

        match self.create_live_archive(&dir) {
            Ok(live_archive) => {
                self.live_archive = Some(live_archive);
                self.refresh_archives();
            }
            Err(err) => {
                self.state.detail_notice = Some(format!("archive disabled: {err}"));
            }
        }
    }

    fn create_live_archive(&self, dir: &Path) -> Result<LiveArchive, std::io::Error> {
        let stamp = archive_stamp(Utc::now());
        let (path, file) = create_unique_jsonl_file(dir, &stamp)?;
        Ok(LiveArchive {
            path,
            writer: BufWriter::new(file),
            writes_since_flush: 0,
            last_flush_at: Instant::now(),
        })
    }

    fn refresh_archives(&mut self) {
        let Some(dir) = self.config.archive_dir.as_deref() else {
            return;
        };
        let live_path = self.live_archive.as_ref().map(|live| live.path.clone());
        let mut archives = match scan_archives(dir, live_path.as_deref()) {
            Ok(archives) => archives,
            Err(err) => {
                self.state.detail_notice = Some(format!("failed to scan archives: {err}"));
                Vec::new()
            }
        };

        // Keep the live archive pinned at the top, then sort newest-first by name.
        archives.sort_by(|a, b| match (a.live, b.live) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => b.name.cmp(&a.name),
        });
        self.state.archives = archives;

        // Prefer selecting the live archive if we have one.
        if let Some(live_path) = live_path.as_deref() {
            if let Some(idx) = self.state.archives.iter().position(|entry| entry.path == live_path)
            {
                self.state.archive_selected = idx;
            }
        }
        self.state.archive_selected =
            self.state.archive_selected.min(self.state.archives.len().saturating_sub(1));
    }

    pub fn push_log(&mut self, entry: LogEntry) {
        self.record_event();

        let follow_tail = self.viewing_archive.is_none() && !self.state.paused && self.follow_tail;

        if !self.state.paused {
            self.append_to_live_archive(&entry);
            self.bump_live_archive_count();
        }

        if self.viewing_archive.is_some() {
            let live = self.live_buffer.get_or_insert_with(LiveBuffer::default);
            if self.state.paused {
                live.queued.push(entry);
            } else {
                live.logs.push(entry);
            }
            return;
        }

        if let Some(screen) = entry.screen.as_deref() {
            if !self.state.screens.iter().any(|name| name == screen) {
                self.state.screens.push(screen.to_string());
            }
        }
        if self.state.paused {
            self.state.queued.push(entry);
        } else {
            self.state.logs.push(entry);
            if self.state.search.buffer.trim().is_empty() {
                let idx = self.state.logs.len().saturating_sub(1);
                if let Some(entry) = self.state.logs.get(idx) {
                    if self.entry_matches_filters(entry) {
                        self.state.filtered.push(idx);
                    }
                }
            } else {
                self.filter_dirty = true;
            }
            if follow_tail {
                self.state.selected = self.state.filtered.len().saturating_sub(1);
                self.state.last_detail_search = None;
                self.state.detail_notice = None;
                self.state.detail_scroll = 0;
            }
        }
    }

    fn append_to_live_archive(&mut self, entry: &LogEntry) {
        let Some(live) = self.live_archive.as_mut() else {
            return;
        };

        let now = Instant::now();
        let write_result = (|| {
            serde_json::to_writer(&mut live.writer, entry)?;
            live.writer.write_all(b"\n")?;
            live.writes_since_flush = live.writes_since_flush.saturating_add(1);

            let should_flush = live.writes_since_flush >= LIVE_ARCHIVE_FLUSH_EVERY_ENTRIES
                || now.duration_since(live.last_flush_at)
                    >= Duration::from_millis(LIVE_ARCHIVE_FLUSH_EVERY_MS);
            if should_flush {
                live.writer.flush()?;
                live.writes_since_flush = 0;
                live.last_flush_at = now;
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        })();

        if let Err(err) = write_result {
            self.state.detail_notice = Some(format!("live archive write failed: {err}"));
            self.live_archive = None;
        }
    }

    fn flush_live_archive(&mut self) {
        let flush_result = match self.live_archive.as_mut() {
            Some(live) => {
                if live.writes_since_flush == 0 {
                    return;
                }

                let result = live.writer.flush();
                if result.is_ok() {
                    live.writes_since_flush = 0;
                    live.last_flush_at = Instant::now();
                }
                result
            }
            None => return,
        };

        if let Err(err) = flush_result {
            self.state.detail_notice = Some(format!("live archive flush failed: {err}"));
            self.live_archive = None;
        }
    }

    fn quit(&mut self) -> Action {
        self.flush_live_archive();
        Action::Quit
    }

    fn bump_live_archive_count(&mut self) {
        let Some(live_path) = self.live_archive.as_ref().map(|live| live.path.clone()) else {
            return;
        };

        if let Some(entry) = self.state.archives.iter_mut().find(|entry| entry.path == live_path) {
            entry.count = entry.count.saturating_add(1);
            entry.live = true;
            return;
        }

        let name = archive_display_name(&live_path);
        self.state.archives.push(ArchiveFile { name, count: 1, path: live_path, live: true });
        self.state.archives.sort_by(|a, b| match (a.live, b.live) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => b.name.cmp(&a.name),
        });
    }

    pub fn archives_mut(&mut self) -> &mut Vec<ArchiveFile> {
        &mut self.state.archives
    }

    pub fn selected_entry(&self) -> Option<&LogEntry> {
        let idx = *self.state.filtered.get(self.state.selected)?;
        self.state.logs.get(idx)
    }

    fn clear_filters_and_queries(&mut self) {
        self.state.search.clear();
        self.state.search_error = None;
        self.state.command.clear();
        self.state.detail_notice = None;
        self.state.last_detail_search = None;
        self.state.goto.clear();
        self.state.goto_overwrite = false;
        self.state.detail_scroll = 0;
        self.state.filters.types.clear();
        self.state.filters.colors.clear();
        self.state.active_screen = None;
        self.state.mode = Mode::Normal;
        self.state.focus = FocusPane::Logs;
        self.state.show_help = false;
        self.state.picker = None;
        self.follow_tail = false;
        self.detail_cache = None;
        self.recompute_filter();
    }

    fn snap_filters_to_selected_entry(&mut self) {
        if self.state.focus != FocusPane::Logs {
            return;
        }
        let Some(log_index) = self.state.filtered.get(self.state.selected).copied() else {
            return;
        };
        let Some(entry) = self.state.logs.get(log_index) else {
            return;
        };

        let color = entry.color.as_deref().and_then(|value| {
            canonical_color_name(value).map(|value| value.to_string()).or_else(|| {
                let normalized = normalize_label(value);
                (!normalized.is_empty()).then_some(normalized)
            })
        });
        let entry_type =
            entry.entry_type.as_deref().map(normalize_label).filter(|value| !value.is_empty());

        self.state.filters.colors.clear();
        self.state.filters.types.clear();
        if let Some(color) = color {
            self.state.filters.colors.insert(color);
        }
        if let Some(entry_type) = entry_type {
            self.state.filters.types.insert(entry_type);
        }

        self.recompute_filter();
        if let Some(pos) = self.state.filtered.iter().position(|idx| *idx == log_index) {
            self.state.selected = pos;
        }
    }

    fn ensure_focus_visible(&mut self) {
        if !self.state.show_archives && self.state.focus == FocusPane::Archives {
            self.state.focus = FocusPane::Detail;
        }
    }

    fn focus_next(&mut self) {
        self.ensure_focus_visible();
        self.state.focus = match (self.state.focus, self.state.show_archives) {
            (FocusPane::Logs, _) => FocusPane::Detail,
            (FocusPane::Detail, true) => FocusPane::Archives,
            (FocusPane::Detail, false) => FocusPane::Logs,
            (FocusPane::Archives, _) => FocusPane::Logs,
        };
    }

    fn focus_prev(&mut self) {
        self.ensure_focus_visible();
        self.state.focus = match (self.state.focus, self.state.show_archives) {
            (FocusPane::Logs, true) => FocusPane::Archives,
            (FocusPane::Logs, false) => FocusPane::Detail,
            (FocusPane::Detail, _) => FocusPane::Logs,
            (FocusPane::Archives, _) => FocusPane::Detail,
        };
    }

    fn focus_right(&mut self) {
        self.ensure_focus_visible();
        self.state.focus = match (self.state.focus, self.state.show_archives) {
            (FocusPane::Logs, _) => FocusPane::Detail,
            (FocusPane::Detail, true) => FocusPane::Archives,
            (FocusPane::Detail, false) => FocusPane::Detail,
            (FocusPane::Archives, _) => FocusPane::Archives,
        };
    }

    fn focus_left(&mut self) {
        self.ensure_focus_visible();
        self.state.focus = match (self.state.focus, self.state.show_archives) {
            (FocusPane::Logs, _) => FocusPane::Logs,
            (FocusPane::Detail, _) => FocusPane::Logs,
            (FocusPane::Archives, _) => FocusPane::Detail,
        };
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c') | KeyCode::Char('C') => return self.quit(),
                _ => {}
            }
        }

        if self.state.rename_archive.is_some() {
            return self.handle_rename_archive(key);
        }

        if self.state.delete_archive_confirm.is_some() {
            return self.handle_delete_archive_confirm(key);
        }

        if self.state.show_help && self.state.picker.is_none() && self.state.mode == Mode::Normal {
            match key {
                KeyEvent { code: KeyCode::Esc, .. }
                | KeyEvent { code: KeyCode::Char('?'), modifiers: KeyModifiers::NONE, .. } => {
                    self.state.show_help = false;
                    return Action::None;
                }
                KeyEvent { code: KeyCode::Char('q' | 'Q'), modifiers, .. }
                    if !modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    return self.quit();
                }
                KeyEvent { code: KeyCode::Char('j'), modifiers: KeyModifiers::NONE, .. }
                | KeyEvent { code: KeyCode::Down, modifiers: KeyModifiers::NONE, .. } => {
                    self.help_scroll_by(1);
                    return Action::None;
                }
                KeyEvent { code: KeyCode::Char('k'), modifiers: KeyModifiers::NONE, .. }
                | KeyEvent { code: KeyCode::Up, modifiers: KeyModifiers::NONE, .. } => {
                    self.help_scroll_by(-1);
                    return Action::None;
                }
                KeyEvent { code: KeyCode::PageDown, modifiers: KeyModifiers::NONE, .. } => {
                    self.help_scroll_page(1);
                    return Action::None;
                }
                KeyEvent { code: KeyCode::PageUp, modifiers: KeyModifiers::NONE, .. } => {
                    self.help_scroll_page(-1);
                    return Action::None;
                }
                KeyEvent { code: KeyCode::Home, modifiers: KeyModifiers::NONE, .. } => {
                    self.state.help_scroll = 0;
                    return Action::None;
                }
                KeyEvent { code: KeyCode::End, modifiers: KeyModifiers::NONE, .. } => {
                    self.state.help_scroll = u16::MAX;
                    return Action::None;
                }
                _ => return Action::None,
            }
        }

        match self.state.mode {
            Mode::Normal => self.handle_normal(key),
            Mode::Search => self.handle_search(key),
            Mode::Command => self.handle_command(key),
            Mode::Goto => self.handle_goto(key),
            Mode::Space => self.handle_space(key),
            Mode::Picker => self.handle_picker(key),
        }
    }

    pub fn handle_mouse(&mut self, event: MouseEvent, size: Rect) -> Action {
        if self.state.picker.is_some()
            || self.state.delete_archive_confirm.is_some()
            || self.state.rename_archive.is_some()
        {
            return Action::None;
        }

        if self.state.show_help {
            let (w, h) = match self.state.help_mode {
                HelpMode::Space => (60, 45),
                HelpMode::Keymap => (72, 80),
            };
            let area = centered_rect(w, h, size);
            let in_rect = |rect: Rect| {
                event.column >= rect.x
                    && event.column < rect.x.saturating_add(rect.width)
                    && event.row >= rect.y
                    && event.row < rect.y.saturating_add(rect.height)
            };
            if in_rect(area) {
                match event.kind {
                    MouseEventKind::ScrollUp => self.help_scroll_by(-1),
                    MouseEventKind::ScrollDown => self.help_scroll_by(1),
                    _ => {}
                }
            }
            return Action::None;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(2)])
            .split(size);
        let Some(top_area) = chunks.first().copied() else {
            return Action::None;
        };
        let Some(main_area) = chunks.get(1).copied() else {
            return Action::None;
        };

        let (logs_area, detail_area, archives_area) = self.main_areas(main_area);
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(14), Constraint::Length(1), Constraint::Min(0)])
            .split(top_area);
        let run_area = top_chunks[0];
        let search_area = top_chunks[2];

        let in_rect = |rect: Rect| {
            event.column >= rect.x
                && event.column < rect.x.saturating_add(rect.width)
                && event.row >= rect.y
                && event.row < rect.y.saturating_add(rect.height)
        };

        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if in_rect(run_area) {
                    self.toggle_pause();
                    return Action::None;
                }

                if in_rect(search_area) {
                    match self.state.mode {
                        Mode::Command => {
                            self.state.command.cursor = self.state.command.buffer.len();
                        }
                        _ => {
                            self.state.mode = Mode::Search;
                            self.state.search.cursor = self.state.search.buffer.len();
                        }
                    }
                    return Action::None;
                }

                if in_rect(logs_area) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Logs;
                } else if in_rect(detail_area) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Detail;
                } else if archives_area.is_some_and(in_rect) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Archives;
                }

                if let Some(list_area) = self.logs_list_area(size) {
                    if in_rect(list_area) {
                        let total = self.state.filtered.len();
                        if total == 0 {
                            return Action::None;
                        }

                        let row = event.row.saturating_sub(list_area.y) as usize;
                        let offset =
                            logs_view_offset(self.state.selected, total, list_area.height as usize);
                        let next = offset.saturating_add(row);

                        if next < total {
                            self.state.selected = next;
                            self.follow_tail = self.state.selected.saturating_add(1) >= total;
                            self.state.last_detail_search = None;
                            self.state.detail_notice = None;
                            self.state.detail_scroll = 0;
                        }

                        return Action::None;
                    }
                }

                if let Some(list_area) = self.archives_list_area(size) {
                    if in_rect(list_area) {
                        let total = self.state.archives.len();
                        if total == 0 {
                            return Action::None;
                        }

                        let row = event.row.saturating_sub(list_area.y) as usize;
                        let offset = logs_view_offset(
                            self.state.archive_selected,
                            total,
                            list_area.height as usize,
                        );
                        let next = offset.saturating_add(row);

                        if next < total {
                            self.state.archive_selected = next;
                            self.state.detail_notice = None;
                        }
                    }
                }
            }
            MouseEventKind::ScrollUp => {
                if in_rect(logs_area) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Logs;
                    self.move_selection(-1);
                } else if in_rect(detail_area) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Detail;
                    self.scroll_detail_by(-1);
                } else if archives_area.is_some_and(in_rect) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Archives;
                    self.move_archive_selection(-1);
                }
            }
            MouseEventKind::ScrollDown => {
                if in_rect(logs_area) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Logs;
                    self.move_selection(1);
                } else if in_rect(detail_area) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Detail;
                    self.scroll_detail_by(1);
                } else if archives_area.is_some_and(in_rect) {
                    self.state.mode = Mode::Normal;
                    self.state.focus = FocusPane::Archives;
                    self.move_archive_selection(1);
                }
            }
            _ => {}
        }

        Action::None
    }

    pub fn perform_action(&mut self, action: Action) -> Result<ActionOutcome, TuiError> {
        match action {
            Action::None => Err(TuiError::InvalidCommandLine("no action".to_string())),
            Action::ClearLogs => Err(TuiError::InvalidCommandLine(
                "clear logs is handled by the runtime".to_string(),
            )),
            Action::OpenEditor => {
                let path = self.open_in_editor()?;
                Ok(ActionOutcome::OpenedEditor(path))
            }
            Action::OpenOrigin => {
                self.open_origin_in_ide()?;
                Ok(ActionOutcome::OpenedOrigin)
            }
            Action::Quit => Ok(ActionOutcome::Quit),
        }
    }

    pub fn render(&mut self, frame: &mut Frame<'_>) {
        if self.filter_dirty {
            self.recompute_filter();
        }
        self.tick_events_per_min(Instant::now());

        let size = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(2)])
            .split(size);

        self.render_top_bar(frame, chunks[0]);
        self.render_main(frame, chunks[1]);
        self.render_footer(frame, chunks[2]);

        if self.state.rename_archive.is_some() {
            self.render_rename_archive(frame);
        } else if self.state.delete_archive_confirm.is_some() {
            self.render_delete_archive_confirm(frame);
        } else if self.state.picker.is_some() {
            self.render_picker(frame);
        } else if self.state.show_help {
            self.render_help(frame);
        }
    }

    fn modal_open(&self) -> bool {
        self.state.picker.is_some()
            || self.state.show_help
            || self.state.delete_archive_confirm.is_some()
            || self.state.rename_archive.is_some()
    }

    fn base_style(&self) -> Style {
        if let Some(palette) = &self.config.palette {
            Style::default().fg(palette.fg).bg(palette.bg)
        } else {
            Style::default()
        }
    }

    fn ansi_color(&self, color: Ansi16) -> Color {
        if let Some(palette) = &self.config.palette {
            palette.ansi_color(color.idx())
        } else {
            color.into()
        }
    }

    fn color_from_name(&self, value: &str) -> Option<Color> {
        match value.trim().to_ascii_lowercase().as_str() {
            "red" => Some(self.ansi_color(Ansi16::Red)),
            "brightred" | "bright_red" | "lightred" | "light_red" => {
                Some(self.ansi_color(Ansi16::BrightRed))
            }
            "green" => Some(self.ansi_color(Ansi16::Green)),
            "brightgreen" | "bright_green" | "lightgreen" | "light_green" => {
                Some(self.ansi_color(Ansi16::BrightGreen))
            }
            "blue" => Some(self.ansi_color(Ansi16::Blue)),
            "yellow" => Some(self.ansi_color(Ansi16::Yellow)),
            "orange" => Some(self.ansi_color(Ansi16::Yellow)),
            "brightyellow" | "bright_yellow" | "lightyellow" | "light_yellow" => {
                Some(self.ansi_color(Ansi16::BrightYellow))
            }
            "purple" | "magenta" => Some(self.ansi_color(Ansi16::Magenta)),
            "brightmagenta" | "bright_magenta" | "lightmagenta" | "light_magenta" => {
                Some(self.ansi_color(Ansi16::BrightMagenta))
            }
            "cyan" => Some(self.ansi_color(Ansi16::Cyan)),
            "brightcyan" | "bright_cyan" | "lightcyan" | "light_cyan" => {
                Some(self.ansi_color(Ansi16::BrightCyan))
            }
            "white" => Some(self.ansi_color(Ansi16::BrightWhite)),
            "gray" | "grey" => Some(self.ansi_color(Ansi16::BrightBlack)),
            _ => None,
        }
    }

    fn panel_border_style(&self, focused: bool) -> Style {
        if self.modal_open() && !focused {
            self.base_style().fg(self.ansi_color(Ansi16::BrightBlack))
        } else if focused {
            self.base_style().fg(self.ansi_color(Ansi16::Green))
        } else {
            self.base_style()
        }
    }

    fn panel_title_style(&self, focused: bool) -> Style {
        if self.modal_open() && !focused {
            self.base_style().fg(self.ansi_color(Ansi16::BrightBlack))
        } else if focused {
            self.base_style().fg(self.ansi_color(Ansi16::Green)).add_modifier(Modifier::BOLD)
        } else {
            self.base_style().add_modifier(Modifier::BOLD)
        }
    }

    fn selection_style(&self) -> Style {
        // Prefer reverse-video over hard-coded fg/bg so the selection adapts to the user's terminal
        // theme (light/dark, base16, etc).
        self.base_style().add_modifier(Modifier::REVERSED | Modifier::BOLD)
    }

    fn help_key_style(&self) -> Style {
        self.base_style().fg(self.ansi_color(Ansi16::BrightBlue)).add_modifier(Modifier::BOLD)
    }

    fn help_header_style(&self) -> Style {
        self.base_style().fg(self.ansi_color(Ansi16::Green)).add_modifier(Modifier::BOLD)
    }

    fn dimmed_style(&self) -> Style {
        self.base_style().fg(self.ansi_color(Ansi16::BrightBlack))
    }

    fn json_syntax_highlight(&self, input: &str) -> Text<'static> {
        let key_style =
            self.base_style().fg(self.ansi_color(Ansi16::Cyan)).add_modifier(Modifier::BOLD);
        let string_style = self.base_style().fg(self.ansi_color(Ansi16::Green));
        let number_style = self.base_style().fg(self.ansi_color(Ansi16::Magenta));
        let bool_style = self.base_style().fg(self.ansi_color(Ansi16::Yellow));
        let null_style = self.base_style().fg(self.ansi_color(Ansi16::Yellow));
        let other_style = self.base_style();

        let mut lines: Vec<Vec<Span<'static>>> = vec![Vec::new()];

        for (kind, segment) in json_highlight_segments(input) {
            let style = match kind {
                JsonHighlightKind::Key => key_style,
                JsonHighlightKind::String => string_style,
                JsonHighlightKind::Number => number_style,
                JsonHighlightKind::Bool => bool_style,
                JsonHighlightKind::Null => null_style,
                JsonHighlightKind::Other => other_style,
            };

            for (idx, part) in segment.split('\n').enumerate() {
                if idx > 0 {
                    lines.push(Vec::new());
                }
                if part.is_empty() {
                    continue;
                }
                let span = Span::styled(part.to_string(), style);
                if let Some(line) = lines.last_mut() {
                    line.push(span);
                }
            }
        }

        let text_lines = lines.into_iter().map(Line::from).collect::<Vec<_>>();
        Text::from(text_lines)
    }

    pub fn enter_search(&mut self) {
        self.state.mode = Mode::Search;
        self.state.detail_notice = None;
    }

    fn run_jq(&self, detail: &str, query: &str) -> Result<Option<String>, TuiError> {
        let command = self.config.jq_command.clone().unwrap_or_else(|| "jq".to_string());
        run_jq_command(
            &command,
            detail,
            query,
            std::time::Duration::from_millis(self.config.jq_timeout_ms),
        )
    }

    pub fn enter_command(&mut self) {
        self.state.mode = Mode::Command;
        self.state.command.clear();
        self.state.detail_notice = None;
    }

    fn open_picker(&mut self, picker: PickerState) {
        self.state.picker = Some(picker);
        self.state.mode = Mode::Picker;
        self.state.show_help = false;
    }

    fn close_picker(&mut self) {
        self.state.picker = None;
        self.state.mode = Mode::Normal;
        self.state.show_help = false;
    }

    fn open_delete_archive_confirm(&mut self) {
        let Some(entry) = self.state.archives.get(self.state.archive_selected) else {
            return;
        };
        if entry.live {
            return;
        }
        self.state.rename_archive = None;
        self.state.delete_archive_confirm = Some(entry.path.clone());
    }

    fn open_rename_archive(&mut self) {
        let Some(entry) = self.state.archives.get(self.state.archive_selected) else {
            return;
        };
        if entry.live {
            return;
        }
        let mut input = InputState::default();
        input.insert_str(&entry.name);
        input.cursor = input.buffer.len();
        self.state.delete_archive_confirm = None;
        self.state.rename_archive =
            Some(RenameArchiveState { path: entry.path.clone(), input, overwrite: true });
    }

    fn open_screen_picker(&mut self) {
        let mut screens = self.state.screens.clone();
        screens.sort();
        let mut items = Vec::new();
        items.push(PickerItem {
            label: "All screens".to_string(),
            meta: None,
            id: PickerItemId::ClearScreens,
            active: self.state.active_screen.is_none(),
        });
        for screen in screens {
            let active = self.state.active_screen.as_deref() == Some(screen.as_str());
            items.push(PickerItem {
                label: screen.clone(),
                meta: None,
                id: PickerItemId::Screen(screen),
                active,
            });
        }
        self.open_picker(PickerState::new(PickerKind::Screens, items, false));
    }

    fn open_color_picker(&mut self) {
        let mut items = Vec::new();
        items.push(PickerItem {
            label: "All colors".to_string(),
            meta: None,
            id: PickerItemId::ClearColors,
            active: self.state.filters.colors.is_empty(),
        });
        for color in self.available_colors() {
            let active = self.state.filters.colors.contains(&color);
            items.push(PickerItem {
                label: color.clone(),
                meta: None,
                id: PickerItemId::Color(color),
                active,
            });
        }
        self.open_picker(PickerState::new(PickerKind::Colors, items, true));
    }

    fn open_type_picker(&mut self) {
        let mut items = Vec::new();
        items.push(PickerItem {
            label: "All types".to_string(),
            meta: None,
            id: PickerItemId::ClearTypes,
            active: self.state.filters.types.is_empty(),
        });
        for entry_type in self.available_types() {
            let active = self.state.filters.types.contains(&entry_type);
            items.push(PickerItem {
                label: entry_type.clone(),
                meta: None,
                id: PickerItemId::EntryType(entry_type),
                active,
            });
        }
        self.open_picker(PickerState::new(PickerKind::Types, items, true));
    }

    fn available_types(&self) -> Vec<String> {
        let mut types = BTreeSet::new();
        for entry in &self.state.logs {
            if let Some(value) = entry.entry_type.as_deref() {
                if self
                    .state
                    .active_screen
                    .as_deref()
                    .is_some_and(|screen| entry.screen.as_deref() != Some(screen))
                {
                    continue;
                }
                types.insert(normalize_label(value));
            }
        }
        types.into_iter().collect()
    }

    fn available_colors(&self) -> Vec<String> {
        OFFICIAL_COLORS.iter().map(|color| (*color).to_string()).collect()
    }

    fn sync_picker_active_states(&mut self) {
        let Some(picker) = self.state.picker.as_mut() else {
            return;
        };
        match picker.kind {
            PickerKind::Colors => {
                for item in &mut picker.items {
                    item.active = match &item.id {
                        PickerItemId::Color(name) => self.state.filters.colors.contains(name),
                        PickerItemId::ClearColors => self.state.filters.colors.is_empty(),
                        _ => item.active,
                    };
                }
            }
            PickerKind::Types => {
                for item in &mut picker.items {
                    item.active = match &item.id {
                        PickerItemId::EntryType(name) => self.state.filters.types.contains(name),
                        PickerItemId::ClearTypes => self.state.filters.types.is_empty(),
                        _ => item.active,
                    };
                }
            }
            PickerKind::Screens => {
                for item in &mut picker.items {
                    item.active = match &item.id {
                        PickerItemId::Screen(name) => {
                            self.state.active_screen.as_deref() == Some(name.as_str())
                        }
                        PickerItemId::ClearScreens => self.state.active_screen.is_none(),
                        _ => item.active,
                    };
                }
            }
        }
    }

    pub fn search_detail(&mut self, query: &str) -> DetailSearchResult {
        self.state.detail_notice = None;
        let detail = match self.selected_entry() {
            Some(entry) => &entry.detail,
            None => {
                self.state.last_detail_search = Some(DetailSearchResult::NotFound);
                return DetailSearchResult::NotFound;
            }
        };

        if detail.contains(query) {
            self.state.last_detail_search = Some(DetailSearchResult::Text);
            return DetailSearchResult::Text;
        }

        let parsed: Value = match serde_json::from_str(detail) {
            Ok(value) => value,
            Err(_) => {
                self.state.last_detail_search = Some(DetailSearchResult::NotFound);
                return DetailSearchResult::NotFound;
            }
        };

        if let Some(result) = json_path_match(&parsed, query) {
            let outcome = DetailSearchResult::JsonPath(result);
            self.state.last_detail_search = Some(outcome.clone());
            return outcome;
        }

        match self.run_jq(detail, query) {
            Ok(Some(result)) => {
                let outcome = DetailSearchResult::Jq(result);
                self.state.last_detail_search = Some(outcome.clone());
                return outcome;
            }
            Ok(None) => {}
            Err(TuiError::JqMissing) => {
                self.state.detail_notice = Some("jq not available".to_string());
            }
            Err(TuiError::JqFailed(message)) => {
                self.state.detail_notice = Some(format!("jq failed: {}", message));
            }
            Err(TuiError::JqTimeout) => {
                self.state.detail_notice = Some("jq timed out".to_string());
            }
            Err(_) => {
                self.state.detail_notice = Some("jq failed".to_string());
            }
        }

        self.state.last_detail_search = Some(DetailSearchResult::NotFound);
        DetailSearchResult::NotFound
    }

    fn handle_normal(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent { code: KeyCode::Char('l' | 'L'), modifiers, .. }
                if modifiers.contains(KeyModifiers::CONTROL) =>
            {
                Action::ClearLogs
            }
            KeyEvent { code: KeyCode::Char('j'), modifiers: KeyModifiers::NONE, .. } => {
                match self.state.focus {
                    FocusPane::Logs => self.move_selection(1),
                    FocusPane::Detail => self.scroll_detail_by(1),
                    FocusPane::Archives => self.move_archive_selection(1),
                }
                Action::None
            }
            KeyEvent { code: KeyCode::Char('J'), modifiers, .. }
                if !modifiers.contains(KeyModifiers::CONTROL)
                    && !modifiers.contains(KeyModifiers::ALT) =>
            {
                self.scroll_detail_by(1);
                Action::None
            }
            KeyEvent { code: KeyCode::Down, modifiers: KeyModifiers::NONE, .. } => {
                match self.state.focus {
                    FocusPane::Logs => self.move_selection(1),
                    FocusPane::Detail => self.scroll_detail_by(1),
                    FocusPane::Archives => self.move_archive_selection(1),
                }
                Action::None
            }
            KeyEvent { code: KeyCode::Up, modifiers: KeyModifiers::NONE, .. } => {
                match self.state.focus {
                    FocusPane::Logs => self.move_selection(-1),
                    FocusPane::Detail => self.scroll_detail_by(-1),
                    FocusPane::Archives => self.move_archive_selection(-1),
                }
                Action::None
            }
            KeyEvent { code: KeyCode::Char('k'), modifiers: KeyModifiers::NONE, .. } => {
                match self.state.focus {
                    FocusPane::Logs => self.move_selection(-1),
                    FocusPane::Detail => self.scroll_detail_by(-1),
                    FocusPane::Archives => self.move_archive_selection(-1),
                }
                Action::None
            }
            KeyEvent { code: KeyCode::Char('K'), modifiers, .. }
                if !modifiers.contains(KeyModifiers::CONTROL)
                    && !modifiers.contains(KeyModifiers::ALT) =>
            {
                self.scroll_detail_by(-1);
                Action::None
            }
            KeyEvent { code: KeyCode::PageDown, modifiers: KeyModifiers::NONE, .. } => {
                self.scroll_detail_page(1);
                Action::None
            }
            KeyEvent { code: KeyCode::PageUp, modifiers: KeyModifiers::NONE, .. } => {
                self.scroll_detail_page(-1);
                Action::None
            }
            KeyEvent { code: KeyCode::Char('g'), modifiers: KeyModifiers::NONE, .. }
                if self.state.focus == FocusPane::Logs =>
            {
                self.enter_goto();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('G'), modifiers, .. }
                if !modifiers.contains(KeyModifiers::CONTROL)
                    && !modifiers.contains(KeyModifiers::ALT)
                    && self.state.focus == FocusPane::Logs =>
            {
                self.select_last_log();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('s'), modifiers: KeyModifiers::NONE, .. }
                if self.state.focus == FocusPane::Logs =>
            {
                self.snap_filters_to_selected_entry();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('u'), modifiers: KeyModifiers::NONE, .. } => {
                self.clear_filters_and_queries();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('h'), modifiers: KeyModifiers::NONE, .. }
            | KeyEvent { code: KeyCode::Left, modifiers: KeyModifiers::NONE, .. } => {
                self.focus_left();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('l'), modifiers: KeyModifiers::NONE, .. }
            | KeyEvent { code: KeyCode::Right, modifiers: KeyModifiers::NONE, .. } => {
                self.focus_right();
                Action::None
            }
            KeyEvent { code: KeyCode::Tab, modifiers: KeyModifiers::NONE, .. } => {
                self.focus_next();
                Action::None
            }
            KeyEvent { code: KeyCode::BackTab, .. } => {
                self.focus_prev();
                Action::None
            }
            KeyEvent { code: KeyCode::Tab, modifiers, .. }
                if modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.focus_prev();
                Action::None
            }
            KeyEvent { code: KeyCode::Enter, modifiers: KeyModifiers::NONE, .. }
                if self.state.focus == FocusPane::Archives =>
            {
                self.load_selected_archive();
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('x') | KeyCode::Char('X'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                if self.state.focus != FocusPane::Archives {
                    self.archive_current_view();
                }
                Action::None
            }
            KeyEvent { code: KeyCode::Char('d' | 'D'), modifiers: KeyModifiers::NONE, .. }
                if self.state.focus == FocusPane::Archives =>
            {
                self.open_delete_archive_confirm();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('n' | 'N'), modifiers: KeyModifiers::NONE, .. }
                if self.state.focus == FocusPane::Archives =>
            {
                self.open_rename_archive();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('?'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_help = true;
                self.state.help_mode = HelpMode::Keymap;
                self.state.help_scroll = 0;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('q' | 'Q'), modifiers, .. }
                if !modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.quit()
            }
            KeyEvent { code: KeyCode::Char('/'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.mode = Mode::Search;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('f'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.mode = Mode::Search;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('r' | 'R'), modifiers, .. }
                if !modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.state.mode = Mode::Search;
                self.state.search.clear();
                self.state.search.insert_str("/");
                self.recompute_filter();
                Action::None
            }
            KeyEvent { code: KeyCode::Char(':'), modifiers: KeyModifiers::NONE, .. } => {
                self.enter_command();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('p'), modifiers: KeyModifiers::NONE, .. } => {
                self.toggle_pause();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('z'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.json_expanded = !self.state.json_expanded;
                self.state.detail_scroll = 0;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('m'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_decorators = !self.state.show_decorators;
                self.state.detail_scroll = 0;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('Z'), modifiers, .. }
                if !modifiers.contains(KeyModifiers::CONTROL)
                    && !modifiers.contains(KeyModifiers::ALT) =>
            {
                self.state.json_raw = !self.state.json_raw;
                self.state.detail_scroll = 0;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('y'), modifiers: KeyModifiers::NONE, .. } => {
                let _ = self.yank_selected(YankKind::Message);
                Action::None
            }
            KeyEvent { code: KeyCode::Char('Y'), modifiers, .. }
                if !modifiers.contains(KeyModifiers::CONTROL)
                    && !modifiers.contains(KeyModifiers::ALT) =>
            {
                let _ = self.yank_selected(YankKind::Detail);
                Action::None
            }
            KeyEvent { code: KeyCode::Char('e'), modifiers: KeyModifiers::NONE, .. } => {
                Action::OpenEditor
            }
            KeyEvent { code: KeyCode::Char('o'), modifiers: KeyModifiers::NONE, .. } => {
                Action::OpenOrigin
            }
            KeyEvent { code: KeyCode::Char('a'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_archives = !self.state.show_archives;
                if self.state.show_archives {
                    self.state.focus = FocusPane::Archives;
                } else {
                    self.state.focus = FocusPane::Logs;
                }
                Action::None
            }
            KeyEvent { code: KeyCode::Char('1'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_color_indicator = !self.state.show_color_indicator;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('2'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_timestamp = !self.state.show_timestamp;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('3'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_labels = !self.state.show_labels;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('4'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_filename = !self.state.show_filename;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('5'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_message = !self.state.show_message;
                Action::None
            }
            KeyEvent { code: KeyCode::Char('6'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.show_uuid = !self.state.show_uuid;
                Action::None
            }
            KeyEvent { code: KeyCode::Char(' '), modifiers: KeyModifiers::NONE, .. } => {
                self.state.mode = Mode::Space;
                self.state.show_help = true;
                self.state.help_mode = HelpMode::Space;
                self.state.help_scroll = 0;
                Action::None
            }
            _ => Action::None,
        }
    }

    fn enter_goto(&mut self) {
        if self.state.focus != FocusPane::Logs {
            return;
        }
        let total = self.state.filtered.len();
        let pos = if total == 0 { 0 } else { self.state.selected.saturating_add(1).min(total) };
        self.state.goto.clear();
        if pos > 0 {
            self.state.goto.insert_str(&pos.to_string());
        }
        self.state.goto.cursor = self.state.goto.buffer.len();
        self.state.goto_overwrite = true;
        self.state.mode = Mode::Goto;
    }

    fn exit_goto(&mut self) {
        self.state.goto.clear();
        self.state.goto_overwrite = false;
        self.state.mode = Mode::Normal;
    }

    fn handle_goto(&mut self, key: KeyEvent) -> Action {
        if self.state.focus != FocusPane::Logs {
            self.exit_goto();
            return Action::None;
        }

        match key {
            KeyEvent { code: KeyCode::Esc, .. } => {
                self.exit_goto();
                Action::None
            }
            KeyEvent { code: KeyCode::Enter, .. } => {
                let total = self.state.filtered.len();
                if total == 0 {
                    self.exit_goto();
                    return Action::None;
                }
                if let Ok(value) = self.state.goto.buffer.trim().parse::<usize>() {
                    let target = value.clamp(1, total);
                    self.state.selected = target.saturating_sub(1);
                    self.follow_tail = target == total;
                    self.state.last_detail_search = None;
                    self.state.detail_notice = None;
                    self.state.detail_scroll = 0;
                }
                self.exit_goto();
                Action::None
            }
            KeyEvent { code: KeyCode::Backspace, modifiers: KeyModifiers::NONE, .. } => {
                if self.state.goto_overwrite {
                    self.state.goto.clear();
                    self.state.goto_overwrite = false;
                } else {
                    self.state.goto.backspace();
                }
                Action::None
            }
            KeyEvent { code: KeyCode::Char(c), modifiers: KeyModifiers::NONE, .. }
                if c.is_ascii_digit() =>
            {
                if self.state.goto_overwrite {
                    self.state.goto.clear();
                    self.state.goto_overwrite = false;
                }
                if self.state.goto.buffer.len() < 9 {
                    self.state.goto.insert_str(&c.to_string());
                }
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_search(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent { code: KeyCode::Esc, .. } | KeyEvent { code: KeyCode::Enter, .. } => {
                self.state.mode = Mode::Normal;
                Action::None
            }
            KeyEvent { code: KeyCode::Backspace, modifiers: KeyModifiers::NONE, .. } => {
                self.state.search.backspace();
                self.recompute_filter();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('y'), modifiers, .. }
                if modifiers.contains(KeyModifiers::CONTROL) =>
            {
                let _ = self.paste_into_input(InputTarget::Search);
                Action::None
            }
            KeyEvent { code: KeyCode::Char(c), modifiers: KeyModifiers::NONE, .. } => {
                if self.state.search.buffer.len() < self.config.max_query_len {
                    self.state.search.insert_str(&c.to_string());
                }
                self.recompute_filter();
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_command(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent { code: KeyCode::Esc, .. } => {
                self.state.mode = Mode::Normal;
                Action::None
            }
            KeyEvent { code: KeyCode::Enter, .. } => {
                let query = self.state.command.buffer.trim().to_string();
                if !query.is_empty() {
                    let _ = self.search_detail(&query);
                }
                self.state.mode = Mode::Normal;
                Action::None
            }
            KeyEvent { code: KeyCode::Backspace, modifiers: KeyModifiers::NONE, .. } => {
                self.state.command.backspace();
                Action::None
            }
            KeyEvent { code: KeyCode::Char('y'), modifiers, .. }
                if modifiers.contains(KeyModifiers::CONTROL) =>
            {
                let _ = self.paste_into_input(InputTarget::Command);
                Action::None
            }
            KeyEvent { code: KeyCode::Char(c), modifiers: KeyModifiers::NONE, .. } => {
                if self.state.command.buffer.len() < self.config.max_query_len {
                    self.state.command.insert_str(&c.to_string());
                }
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_picker(&mut self, key: KeyEvent) -> Action {
        let mut action = PickerAction::None;
        {
            let Some(picker) = self.state.picker.as_mut() else {
                self.state.mode = Mode::Normal;
                return Action::None;
            };

            match key {
                KeyEvent { code: KeyCode::Esc, .. } => {
                    action = PickerAction::Close;
                }
                KeyEvent { code: KeyCode::Enter, .. } => {
                    if let Some(item) = picker.selected_item() {
                        if picker.multi_select {
                            action = PickerAction::Toggle(item.id.clone());
                        } else {
                            action = PickerAction::Select(item.id.clone());
                        }
                    }
                }
                KeyEvent { code: KeyCode::Char(' '), modifiers: KeyModifiers::NONE, .. } => {
                    if let Some(item) = picker.selected_item() {
                        if picker.multi_select {
                            action = PickerAction::Toggle(item.id.clone());
                        } else {
                            action = PickerAction::Select(item.id.clone());
                        }
                    }
                }
                KeyEvent {
                    code: KeyCode::Char('j') | KeyCode::Char('J'),
                    modifiers: KeyModifiers::NONE,
                    ..
                }
                | KeyEvent { code: KeyCode::Down, .. } => {
                    picker.move_selection(1);
                }
                KeyEvent {
                    code: KeyCode::Char('k') | KeyCode::Char('K'),
                    modifiers: KeyModifiers::NONE,
                    ..
                }
                | KeyEvent { code: KeyCode::Up, .. } => {
                    picker.move_selection(-1);
                }
                KeyEvent { code: KeyCode::Backspace, modifiers: KeyModifiers::NONE, .. } => {
                    picker.query.backspace();
                    picker.recompute();
                }
                KeyEvent { code: KeyCode::Char('y'), modifiers, .. }
                    if modifiers.contains(KeyModifiers::CONTROL) =>
                {
                    action = PickerAction::Paste;
                }
                KeyEvent { code: KeyCode::Char(c), modifiers: KeyModifiers::NONE, .. } => {
                    if picker.query.buffer.len() < self.config.max_query_len {
                        picker.query.insert_str(&c.to_string());
                    }
                    picker.recompute();
                }
                _ => {}
            }
        }

        match action {
            PickerAction::None => {}
            PickerAction::Close => self.close_picker(),
            PickerAction::Select(item) => {
                self.apply_picker_selection(item);
                self.close_picker();
            }
            PickerAction::Toggle(item) => {
                self.apply_picker_toggle(item);
                self.sync_picker_active_states();
            }
            PickerAction::Paste => {
                let _ = self.paste_into_picker();
            }
        }

        Action::None
    }

    fn handle_space(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent { code: KeyCode::Char('c'), modifiers: KeyModifiers::NONE, .. } => {
                self.open_color_picker();
            }
            KeyEvent { code: KeyCode::Char('s'), modifiers: KeyModifiers::NONE, .. } => {
                self.open_screen_picker();
            }
            KeyEvent { code: KeyCode::Char('t'), modifiers: KeyModifiers::NONE, .. } => {
                self.open_type_picker();
            }
            _ => {}
        }

        if self.state.mode == Mode::Space {
            self.state.mode = Mode::Normal;
            self.state.show_help = false;
        }
        Action::None
    }

    fn toggle_pause(&mut self) {
        self.state.paused = !self.state.paused;
        if !self.state.paused {
            if self.viewing_archive.is_some() {
                if let Some(live) = self.live_buffer.as_mut() {
                    if !live.queued.is_empty() {
                        live.logs.append(&mut live.queued);
                    }
                }
            } else if !self.state.queued.is_empty() {
                self.state.logs.append(&mut self.state.queued);
                self.recompute_filter();
            }
        }
    }

    fn recompute_filter(&mut self) {
        self.filter_dirty = false;
        let raw_query = self.state.search.buffer.clone();
        let trimmed = raw_query.trim();
        let base_indices = self.base_filter_indices();

        if trimmed.is_empty() {
            self.state.search_error = None;
            self.apply_filter(base_indices);
            return;
        }

        if let Some(regex_pattern) = parse_regex_input(trimmed) {
            match regex_pattern {
                Ok(pattern) => match RegexBuilder::new(pattern).case_insensitive(true).build() {
                    Ok(regex) => {
                        let filtered = self.regex_filter(&base_indices, &regex);
                        self.state.search_error = None;
                        self.apply_filter(filtered);
                    }
                    Err(err) => {
                        self.state.search_error = Some(err.to_string());
                    }
                },
                Err(err) => {
                    self.state.search_error = Some(err);
                }
            }
            return;
        }

        let filtered = self.fuzzy_filter(&base_indices, trimmed);
        self.state.search_error = None;
        self.apply_filter(filtered);
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.state.filtered.len();
        if len == 0 {
            return;
        }
        let mut next = self.state.selected as i32 + delta;
        if next < 0 {
            next = 0;
        } else if next >= len as i32 {
            next = len as i32 - 1;
        }
        self.state.selected = next as usize;
        self.follow_tail = self.state.selected.saturating_add(1) >= len;
        self.state.last_detail_search = None;
        self.state.detail_notice = None;
        self.state.detail_scroll = 0;
    }

    fn select_last_log(&mut self) {
        let len = self.state.filtered.len();
        if len == 0 {
            return;
        }
        self.state.selected = len.saturating_sub(1);
        self.follow_tail = true;
        self.state.last_detail_search = None;
        self.state.detail_notice = None;
        self.state.detail_scroll = 0;
    }

    fn move_archive_selection(&mut self, delta: i32) {
        let len = self.state.archives.len();
        if len == 0 {
            self.state.archive_selected = 0;
            return;
        }
        let mut next = self.state.archive_selected as i32 + delta;
        if next < 0 {
            next = 0;
        } else if next >= len as i32 {
            next = len as i32 - 1;
        }
        self.state.archive_selected = next as usize;
    }

    fn max_detail_scroll(&mut self) -> u16 {
        let viewport = self.state.detail_viewport_height.max(1) as usize;
        let lines = self.detail_cached().display_stats.lines;
        let max = lines.saturating_sub(viewport);
        max.min(u16::MAX as usize) as u16
    }

    fn help_scroll_by(&mut self, delta: i32) {
        if delta == 0 {
            return;
        }
        if delta < 0 {
            self.state.help_scroll = self.state.help_scroll.saturating_sub((-delta) as u16);
        } else {
            self.state.help_scroll = self.state.help_scroll.saturating_add(delta as u16);
        }
    }

    fn help_scroll_page(&mut self, direction: i32) {
        let page = self.state.help_viewport_height.max(1).saturating_sub(1) as i32;
        let step = if page <= 0 { 1 } else { page };
        self.help_scroll_by(direction.signum() * step);
    }

    fn scroll_detail_by(&mut self, delta: i32) {
        let max = self.max_detail_scroll() as i32;
        let current = self.state.detail_scroll as i32;
        let next = (current + delta).clamp(0, max);
        self.state.detail_scroll = next as u16;
    }

    fn scroll_detail_page(&mut self, direction: i32) {
        let page = self.state.detail_viewport_height.max(1).saturating_sub(1) as i32;
        let step = if page <= 0 { 1 } else { page };
        self.scroll_detail_by(direction.saturating_mul(step));
    }

    pub fn clear_screen_for(&mut self, screen: Option<&str>) {
        let (logs, queued) = if self.viewing_archive.is_some() {
            let live = self.live_buffer.get_or_insert_with(LiveBuffer::default);
            (&mut live.logs, &mut live.queued)
        } else {
            (&mut self.state.logs, &mut self.state.queued)
        };

        let mut removed = 0usize;
        match screen {
            Some(screen_name) => {
                logs.retain(|entry| {
                    let matches = entry.screen.as_deref() == Some(screen_name);
                    if matches {
                        removed += 1;
                    }
                    !matches
                });
                queued.retain(|entry| entry.screen.as_deref() != Some(screen_name));
            }
            None => {
                removed = logs.len();
                logs.clear();
                queued.clear();
            }
        }

        if removed > 0 {
            self.state.detail_notice = Some(format!("cleared {removed} entries"));
        }

        // Only recompute the view filter if we're clearing the currently viewed dataset.
        if self.viewing_archive.is_none() {
            self.rebuild_screens();
            self.state.filtered.clear();
            self.state.selected = 0;
            self.follow_tail = false;
            self.state.last_detail_search = None;
            self.detail_cache = None;
            self.recompute_filter();
        }
    }

    fn load_selected_archive(&mut self) {
        let Some(selected) = self.state.archives.get(self.state.archive_selected).cloned() else {
            self.state.detail_notice = Some("no archive selected".to_string());
            return;
        };

        if selected.live {
            self.switch_to_live();
        } else {
            self.switch_to_archive(selected.path);
        }
    }

    fn switch_to_archive(&mut self, path: PathBuf) {
        if self.viewing_archive.as_deref() == Some(&path) {
            return;
        }

        if self.viewing_archive.is_none() {
            self.live_buffer = Some(LiveBuffer {
                logs: std::mem::take(&mut self.state.logs),
                queued: std::mem::take(&mut self.state.queued),
            });
        }

        let (logs, skipped) = match read_archive_jsonl(&path) {
            Ok(result) => result,
            Err(err) => {
                self.state.detail_notice = Some(format!("failed to load archive: {err}"));
                return;
            }
        };

        self.state.logs = logs;
        self.state.queued.clear();
        self.state.search.clear();
        self.state.search_error = None;
        self.state.filters.types.clear();
        self.state.filters.colors.clear();
        self.state.active_screen = None;
        self.viewing_archive = Some(path.clone());
        self.rebuild_screens();
        self.state.selected = 0;
        self.follow_tail = false;
        self.state.detail_scroll = 0;
        self.state.last_detail_search = None;
        self.detail_cache = None;
        self.recompute_filter();

        let name = archive_display_name(&path);
        if skipped > 0 {
            self.state.detail_notice = Some(format!("loaded {name} (skipped {skipped} lines)"));
        } else {
            self.state.detail_notice = Some(format!("loaded {name}"));
        }
    }

    fn switch_to_live(&mut self) {
        let Some(live) = self.live_buffer.take() else {
            self.viewing_archive = None;
            return;
        };

        self.state.logs = live.logs;
        self.state.queued = live.queued;
        self.viewing_archive = None;
        self.rebuild_screens();
        self.state.selected = 0;
        self.follow_tail = false;
        self.state.detail_scroll = 0;
        self.state.last_detail_search = None;
        self.detail_cache = None;
        self.recompute_filter();

        self.state.detail_notice = Some("returned to live".to_string());
    }

    fn rebuild_screens(&mut self) {
        self.state.screens.clear();
        for entry in &self.state.logs {
            let Some(screen) = entry.screen.as_deref() else {
                continue;
            };
            if !self.state.screens.iter().any(|name| name == screen) {
                self.state.screens.push(screen.to_string());
            }
        }
    }

    fn archive_current_view(&mut self) {
        let Some(dir) = self.config.archive_dir.as_deref() else {
            self.state.detail_notice = Some("archive disabled".to_string());
            return;
        };

        if self.state.filtered.is_empty() {
            self.state.detail_notice = Some("nothing to archive".to_string());
            return;
        }

        let stamp = format!("{}-selection", archive_stamp(Utc::now()));
        let (path, file) = match create_unique_jsonl_file(dir, &stamp) {
            Ok(result) => result,
            Err(err) => {
                self.state.detail_notice = Some(format!("archive failed: {err}"));
                return;
            }
        };

        let mut writer = BufWriter::new(file);
        let mut written = 0usize;
        let mut failed = 0usize;

        for idx in &self.state.filtered {
            let Some(entry) = self.state.logs.get(*idx) else {
                continue;
            };
            match serde_json::to_writer(&mut writer, entry) {
                Ok(()) => {
                    let _ = writer.write_all(b"\n");
                    written += 1;
                }
                Err(_) => {
                    failed += 1;
                }
            }
        }
        let _ = writer.flush();

        if written == 0 {
            self.state.detail_notice = Some("archive produced no entries".to_string());
            return;
        }

        let name = archive_display_name(&path);
        self.state.archives.push(ArchiveFile {
            name: name.clone(),
            count: written,
            path: path.clone(),
            live: false,
        });
        self.state.archives.sort_by(|a, b| match (a.live, b.live) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => b.name.cmp(&a.name),
        });
        if let Some(idx) = self.state.archives.iter().position(|entry| entry.path == path) {
            self.state.archive_selected = idx;
        }
        self.state.show_archives = true;

        if failed > 0 {
            self.state.detail_notice =
                Some(format!("archived {written} entries to {name} (failed {failed})"));
        } else {
            self.state.detail_notice = Some(format!("archived {written} entries to {name}"));
        }
    }

    fn apply_filter(&mut self, filtered: Vec<usize>) {
        self.state.filtered = filtered;
        if self.state.filtered.is_empty() {
            self.state.selected = 0;
        } else if self.follow_tail || self.state.selected >= self.state.filtered.len() {
            self.state.selected = self.state.filtered.len() - 1;
        }
    }

    fn base_filter_indices(&self) -> Vec<usize> {
        self.state
            .logs
            .iter()
            .enumerate()
            .filter_map(
                |(idx, entry)| {
                    if self.entry_matches_filters(entry) {
                        Some(idx)
                    } else {
                        None
                    }
                },
            )
            .collect()
    }

    fn entry_matches_filters(&self, entry: &LogEntry) -> bool {
        if let Some(active) = &self.state.active_screen {
            if entry.screen.as_deref() != Some(active.as_str()) {
                return false;
            }
        }

        if !matches_filter_set(&self.state.filters.types, entry.entry_type.as_deref()) {
            return false;
        }

        if !matches_filter_set(&self.state.filters.colors, entry.color.as_deref()) {
            return false;
        }

        true
    }

    fn yank_selected(&mut self, kind: YankKind) -> Result<(), TuiError> {
        if self.selected_entry().is_none() {
            return Err(TuiError::NoSelection);
        }
        let contents = match kind {
            YankKind::Message => self.selected_entry().expect("selection checked").message.clone(),
            YankKind::Detail => self.detail_text().0,
        };
        self.clipboard.set(&contents)?;
        self.state.last_yank = Some(contents);
        Ok(())
    }

    fn paste_into_input(&mut self, target: InputTarget) -> Result<(), TuiError> {
        let pasted = self.clipboard.get()?;
        let max_len = self.config.max_query_len;
        let existing_len = match target {
            InputTarget::Search => self.state.search.buffer.len(),
            InputTarget::Command => self.state.command.buffer.len(),
        };
        let remaining = max_len.saturating_sub(existing_len);
        let pasted = if remaining == 0 {
            ""
        } else if pasted.len() <= remaining {
            pasted.as_str()
        } else {
            let mut end = remaining;
            while end > 0 && !pasted.is_char_boundary(end) {
                end -= 1;
            }
            &pasted[..end]
        };
        match target {
            InputTarget::Search => {
                self.state.search.insert_str(pasted);
                self.recompute_filter();
            }
            InputTarget::Command => {
                self.state.command.insert_str(pasted);
            }
        }
        Ok(())
    }

    fn paste_into_picker(&mut self) -> Result<(), TuiError> {
        let pasted = self.clipboard.get()?;
        if let Some(picker) = self.state.picker.as_mut() {
            let max_len = self.config.max_query_len;
            let remaining = max_len.saturating_sub(picker.query.buffer.len());
            if remaining > 0 {
                let pasted = if pasted.len() <= remaining {
                    pasted.as_str()
                } else {
                    let mut end = remaining;
                    while end > 0 && !pasted.is_char_boundary(end) {
                        end -= 1;
                    }
                    &pasted[..end]
                };
                picker.query.insert_str(pasted);
            }
            picker.recompute();
        }
        Ok(())
    }

    fn apply_picker_selection(&mut self, item: PickerItemId) {
        match item {
            PickerItemId::Screen(name) => {
                self.state.active_screen = Some(name);
                self.recompute_filter();
            }
            PickerItemId::ClearScreens => {
                self.state.active_screen = None;
                self.recompute_filter();
            }
            PickerItemId::Color(_) | PickerItemId::EntryType(_) => {
                self.apply_picker_toggle(item);
            }
            PickerItemId::ClearColors => {
                self.state.filters.colors.clear();
                self.recompute_filter();
            }
            PickerItemId::ClearTypes => {
                self.state.filters.types.clear();
                self.recompute_filter();
            }
        }
    }

    fn apply_picker_toggle(&mut self, item: PickerItemId) {
        match item {
            PickerItemId::Color(name) => {
                toggle_filter(&mut self.state.filters.colors, name);
            }
            PickerItemId::EntryType(name) => {
                toggle_filter(&mut self.state.filters.types, name);
            }
            PickerItemId::ClearColors => {
                self.state.filters.colors.clear();
            }
            PickerItemId::ClearTypes => {
                self.state.filters.types.clear();
            }
            _ => {}
        }
        self.recompute_filter();
    }

    fn handle_rename_archive(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent { code: KeyCode::Esc, .. } => {
                self.state.rename_archive = None;
            }
            KeyEvent { code: KeyCode::Enter, .. } => {
                self.rename_confirmed_archive();
            }
            KeyEvent { code: KeyCode::Backspace, modifiers: KeyModifiers::NONE, .. } => {
                if let Some(rename) = self.state.rename_archive.as_mut() {
                    if rename.overwrite {
                        rename.input.clear();
                        rename.overwrite = false;
                    } else {
                        rename.input.backspace();
                    }
                }
            }
            KeyEvent { code: KeyCode::Char(c), modifiers: KeyModifiers::NONE, .. } => {
                if let Some(rename) = self.state.rename_archive.as_mut() {
                    if rename.overwrite {
                        rename.input.clear();
                        rename.overwrite = false;
                    }
                    if rename.input.buffer.len() < self.config.max_query_len
                        && !matches!(c, '/' | '\\' | '\0')
                    {
                        rename.input.insert_str(&c.to_string());
                    }
                }
            }
            _ => {}
        }
        Action::None
    }

    fn rename_confirmed_archive(&mut self) {
        let Some(mut rename) = self.state.rename_archive.take() else {
            return;
        };

        let raw = rename.input.buffer.trim();
        if raw.is_empty() {
            self.state.detail_notice = Some("rename failed: name is empty".to_string());
            self.state.rename_archive = Some(rename);
            return;
        }
        if raw == "." || raw == ".." {
            self.state.detail_notice = Some("rename failed: invalid name".to_string());
            self.state.rename_archive = Some(rename);
            return;
        }

        let raw_lower = raw.to_ascii_lowercase();
        let stem = raw_lower
            .strip_suffix(".jsonl")
            .map(|_| raw[..raw.len().saturating_sub(".jsonl".len())].trim())
            .unwrap_or(raw);
        if stem.is_empty() {
            self.state.detail_notice = Some("rename failed: name is empty".to_string());
            self.state.rename_archive = Some(rename);
            return;
        }

        let old_path = rename.path.clone();
        let Some(parent) = old_path.parent() else {
            self.state.detail_notice = Some("rename failed: missing archive directory".to_string());
            self.state.rename_archive = Some(rename);
            return;
        };

        let file_name = format!("{stem}.jsonl");
        let new_path = parent.join(&file_name);

        if new_path == old_path {
            self.state.detail_notice = Some("rename unchanged".to_string());
            return;
        }

        if new_path.exists() {
            self.state.detail_notice = Some("rename failed: target already exists".to_string());
            rename.path = old_path;
            self.state.rename_archive = Some(rename);
            return;
        }

        match fs::rename(&old_path, &new_path) {
            Ok(()) => {}
            Err(err) => {
                self.state.detail_notice = Some(format!("rename failed: {err}"));
                rename.path = old_path;
                self.state.rename_archive = Some(rename);
                return;
            }
        }

        let old_name = archive_display_name(&old_path);
        let new_name = archive_display_name(&new_path);

        if self.viewing_archive.as_deref() == Some(old_path.as_path()) {
            self.viewing_archive = Some(new_path.clone());
        }

        if let Some(entry) = self.state.archives.iter_mut().find(|entry| entry.path == old_path) {
            entry.path = new_path.clone();
            entry.name = new_name.clone();
        }

        // Keep the live archive pinned at the top, then sort newest-first by name.
        self.state.archives.sort_by(|a, b| match (a.live, b.live) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => b.name.cmp(&a.name),
        });

        if let Some(idx) = self.state.archives.iter().position(|entry| entry.path == new_path) {
            self.state.archive_selected = idx;
        }

        self.state.detail_notice = Some(format!("renamed {old_name} -> {new_name}"));
    }

    fn handle_delete_archive_confirm(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent { code: KeyCode::Esc, .. }
            | KeyEvent { code: KeyCode::Char('n' | 'N'), modifiers: KeyModifiers::NONE, .. } => {
                self.state.delete_archive_confirm = None;
            }
            KeyEvent { code: KeyCode::Enter, .. }
            | KeyEvent { code: KeyCode::Char('y' | 'Y'), modifiers: KeyModifiers::NONE, .. } => {
                self.delete_confirmed_archive();
            }
            _ => {}
        }
        Action::None
    }

    fn delete_confirmed_archive(&mut self) {
        let Some(path) = self.state.delete_archive_confirm.take() else {
            return;
        };

        if self.state.archives.iter().any(|entry| entry.live && entry.path == path) {
            return;
        }

        let name = archive_display_name(&path);
        let loaded = self.viewing_archive.as_deref() == Some(path.as_path());

        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                self.state.detail_notice = Some(format!("delete failed: {err}"));
                return;
            }
        }

        let old_selected = self
            .state
            .archives
            .iter()
            .position(|entry| entry.path == path)
            .unwrap_or(self.state.archive_selected);
        self.state.archives.retain(|entry| entry.path != path);
        if self.state.archives.is_empty() {
            self.state.archive_selected = 0;
        } else if old_selected >= self.state.archives.len() {
            self.state.archive_selected = self.state.archives.len() - 1;
        }

        if loaded {
            self.switch_to_live();
            self.state.detail_notice = Some(format!("deleted {name}; returned to live"));
        } else {
            self.state.detail_notice = Some(format!("deleted {name}"));
        }
    }

    fn open_in_editor(&mut self) -> Result<PathBuf, TuiError> {
        if self.selected_entry().is_none() {
            return Err(TuiError::NoSelection);
        }
        let mut temp = NamedTempFile::new()?;
        let (detail, _) = self.detail_text();
        temp.write_all(detail.as_bytes())?;
        let temp_path = temp.into_temp_path();
        let path_buf = temp_path.to_path_buf();

        let command = self
            .config
            .editor_command
            .clone()
            .or_else(|| env::var("VISUAL").ok())
            .or_else(|| env::var("EDITOR").ok())
            .or_else(|| Some("vim".to_string()))
            .ok_or(TuiError::MissingEditor)?;

        launch_command(&command, &path_buf)?;
        self.open_temp = Some(temp_path);
        Ok(path_buf)
    }

    fn open_origin_in_ide(&mut self) -> Result<(), TuiError> {
        let entry = self.selected_entry().ok_or(TuiError::NoSelection)?;
        let origin = entry.origin.as_deref().ok_or(TuiError::MissingIde)?;
        let command = self
            .config
            .ide_command
            .clone()
            .or_else(|| env::var("RAYMON_IDE").ok())
            .or_else(|| Some("code".to_string()))
            .ok_or(TuiError::MissingIde)?;

        launch_command(&command, origin)?;
        Ok(())
    }

    fn render_top_bar(&self, frame: &mut Frame<'_>, area: Rect) {
        let focused = matches!(self.state.mode, Mode::Search | Mode::Command) && !self.modal_open();
        let border_style = self.panel_border_style(focused);
        let title_style = self.panel_title_style(focused);

        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(14), Constraint::Length(1), Constraint::Min(0)])
            .split(area);
        let run_area = top_chunks[0];
        let search_area = top_chunks[2];

        let run_bg = if self.viewing_archive.is_some() {
            self.ansi_color(Ansi16::Blue)
        } else if self.state.paused {
            self.ansi_color(Ansi16::Yellow)
        } else {
            self.ansi_color(Ansi16::Green)
        };
        let run_style = self.base_style().fg(run_bg).add_modifier(Modifier::BOLD);
        let run_label = if self.viewing_archive.is_some() {
            "⏸ Archive"
        } else if self.state.paused {
            "⏸ Pause"
        } else {
            "▶ Live"
        };

        // Use corners only (no border lines) to keep the status indicator lightweight.
        let live_corner_border = ratatui::symbols::border::Set {
            top_left: "⌜",
            top_right: "⌝",
            bottom_left: "⌞",
            bottom_right: "⌟",
            vertical_left: " ",
            vertical_right: " ",
            horizontal_top: " ",
            horizontal_bottom: " ",
        };
        // When paused, use the same corner glyphs as the main cards (Logs/Detail/Archives).
        let paused_corner_border = ratatui::symbols::border::Set {
            top_left: "┌",
            top_right: "┐",
            bottom_left: "└",
            bottom_right: "┘",
            vertical_left: " ",
            vertical_right: " ",
            horizontal_top: " ",
            horizontal_bottom: " ",
        };
        let run_corner_border = if self.viewing_archive.is_some() || self.state.paused {
            paused_corner_border
        } else {
            live_corner_border
        };
        let run_block = Block::default()
            .borders(Borders::ALL)
            .border_set(run_corner_border)
            .border_style(self.base_style().fg(run_bg).add_modifier(Modifier::BOLD));
        let run_inner = run_block.inner(run_area);
        frame.render_widget(run_block, run_area);
        frame.render_widget(
            Paragraph::new(run_label).alignment(Alignment::Center).style(run_style),
            run_inner,
        );

        let block = Block::default()
            .borders(Borders::ALL)
            .title("───── Search ")
            .border_style(border_style)
            .title_style(title_style);
        let inner = block.inner(search_area);
        frame.render_widget(block, search_area);

        let search_kind = if self.state.mode == Mode::Command {
            "JQ "
        } else if self.state.search.buffer.trim_start().starts_with('/') {
            "REG"
        } else {
            "FUZ"
        };
        let kind_style = self.base_style().add_modifier(Modifier::REVERSED | Modifier::BOLD);

        let (query, query_active) = match self.state.mode {
            Mode::Command => (self.state.command.buffer.as_str(), true),
            Mode::Search => (self.state.search.buffer.as_str(), true),
            _ => (self.state.search.buffer.as_str(), false),
        };
        let query_style = if query_active {
            self.base_style().add_modifier(Modifier::BOLD)
        } else {
            self.base_style()
        };

        let mut spans = vec![
            Span::styled(format!(" {search_kind} "), kind_style),
            Span::raw(" "),
            Span::styled(query.to_string(), query_style),
        ];
        if let Some(error) = &self.state.search_error {
            spans.push(Span::styled(
                format!(" Error: {}", error),
                self.base_style().fg(self.ansi_color(Ansi16::Red)),
            ));
        }
        if let Some(notice) = &self.state.detail_notice {
            spans.push(Span::styled(
                format!(" Notice: {}", notice),
                self.base_style().fg(self.ansi_color(Ansi16::Yellow)),
            ));
        }

        frame.render_widget(
            Paragraph::new(Line::from(spans)).alignment(Alignment::Left).style(self.base_style()),
            inner,
        );
    }

    fn render_main(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let (logs_area, detail_area, archives_area) = self.main_areas(area);

        self.render_logs(frame, logs_area);
        self.render_detail(frame, detail_area);
        if let Some(archives_area) = archives_area {
            self.render_archives(frame, archives_area);
        }
    }

    fn logs_list_area(&self, size: Rect) -> Option<Rect> {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(2)])
            .split(size);
        let main_area = *chunks.get(1)?;

        let (logs_area, _, _) = self.main_areas(main_area);

        let inner = Block::default().borders(Borders::ALL).inner(logs_area);
        let (list_area, _) = split_for_scrollbar(inner);
        Some(list_area)
    }

    fn logs_title_line(&self) -> Line<'static> {
        let mut spans: Vec<Span<'static>> = Vec::new();
        spans.push(Span::raw("─ Logs "));

        if let Some(screen) = &self.state.active_screen {
            spans.push(Span::styled(
                format!("@{screen}"),
                self.base_style().fg(self.ansi_color(Ansi16::Cyan)),
            ));
            spans.push(Span::raw(" "));
        }

        let has_color_filters = !self.state.filters.colors.is_empty();
        for (idx, &color) in OFFICIAL_COLORS.iter().enumerate() {
            if idx > 0 {
                spans.push(Span::raw(" "));
            }
            let active = has_color_filters && self.state.filters.colors.contains(color);
            let symbol = if active { "⏺" } else { "⊙" };
            let style = self
                .color_from_name(color)
                .map(|color| self.base_style().fg(color))
                .unwrap_or_else(|| self.base_style());
            spans.push(Span::styled(symbol.to_string(), style));
        }

        spans.push(Span::raw(" "));

        let types = if self.state.filters.types.is_empty() {
            " ".to_string()
        } else {
            summarize_set(&self.state.filters.types)
        };
        spans.push(Span::raw(format!("[{types}]")));
        spans.push(Span::raw(" "));

        Line::from(spans)
    }

    fn archives_list_area(&self, size: Rect) -> Option<Rect> {
        if !self.state.show_archives {
            return None;
        }
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(2)])
            .split(size);
        let main_area = *chunks.get(1)?;

        let (_, _, archives_area) = self.main_areas(main_area);
        let archives_area = archives_area?;

        let inner = Block::default().borders(Borders::ALL).inner(archives_area);
        let (list_area, _) = split_for_scrollbar(inner);
        Some(list_area)
    }

    fn render_logs(&self, frame: &mut Frame<'_>, area: Rect) {
        let focused = matches!(self.state.mode, Mode::Normal | Mode::Goto)
            && self.state.focus == FocusPane::Logs
            && !self.modal_open();
        let total = self.state.filtered.len();
        let pos = if total == 0 { 0 } else { self.state.selected.saturating_add(1).min(total) };
        let events_per_min = self.events_per_min;
        let title = self.logs_title_line();
        let columns = [
            self.state.show_color_indicator,
            self.state.show_timestamp,
            self.state.show_labels,
            self.state.show_filename,
            self.state.show_message,
            self.state.show_uuid,
        ];
        let inactive_col_style = self.base_style().fg(self.ansi_color(Ansi16::BrightBlack));
        let mut columns_spans: Vec<Span<'static>> = vec![Span::raw("─ ")];
        for (idx, enabled) in columns.iter().enumerate() {
            let digit = char::from_digit((idx + 1) as u32, 10).expect("1..=6 digits");
            if *enabled {
                columns_spans.push(Span::raw(digit.to_string()));
            } else {
                columns_spans.push(Span::styled(digit.to_string(), inactive_col_style));
            }
        }
        columns_spans.push(Span::raw(" ─"));
        let columns_line = Line::from(columns_spans).left_aligned();
        let bottom = if self.state.mode == Mode::Goto && self.state.focus == FocusPane::Logs {
            let cursor_style = self.base_style().add_modifier(Modifier::REVERSED | Modifier::BOLD);
            let display = if self.state.goto.buffer.is_empty() {
                " ".to_string()
            } else {
                self.state.goto.buffer.clone()
            };
            Line::from(vec![
                Span::raw("─ "),
                Span::styled(display, cursor_style),
                Span::raw(format!(" of {total} · {events_per_min} / min ─")),
            ])
        } else {
            Line::from(format!("─ {pos} of {total} · {events_per_min} / min ─"))
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_bottom(columns_line)
            .title_bottom(bottom.right_aligned())
            .border_style(self.panel_border_style(focused))
            .title_style(self.panel_title_style(focused));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        // We intentionally *don't* use reverse-video for the selected row here: reverse-video
        // would invert the colored dot into a black dot with a colored background.
        let selected_style = self
            .base_style()
            .fg(self.ansi_color(Ansi16::Black))
            .bg(self.ansi_color(Ansi16::White))
            .add_modifier(Modifier::BOLD);

        let items: Vec<ListItem> = self
            .state
            .filtered
            .iter()
            .enumerate()
            .filter_map(|(pos, idx)| {
                let entry = self.state.logs.get(*idx)?;
                let mut item = ListItem::new(self.format_log_line(entry));
                if pos == self.state.selected {
                    item = item.style(selected_style);
                }
                Some(item)
            })
            .collect();
        let content_len = items.len();
        let mut state = ListState::default();
        if !self.state.filtered.is_empty() {
            state.select(Some(self.state.selected));
        }
        let list = List::new(items)
            .style(self.base_style())
            .highlight_style(Style::default())
            .highlight_symbol("");

        let (list_area, scrollbar_area) = split_for_scrollbar(inner);
        frame.render_stateful_widget(list, list_area, &mut state);

        if let Some(scrollbar_area) = scrollbar_area {
            if content_len > 0 && list_area.height > 0 {
                let thumb_style = if focused {
                    self.base_style().fg(self.ansi_color(Ansi16::Green))
                } else {
                    self.dimmed_style()
                };
                let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .thumb_style(thumb_style)
                    .track_style(self.dimmed_style());
                let viewport_len = list_area.height as usize;
                let scroll_len = content_len.saturating_sub(viewport_len).saturating_add(1);
                let mut scrollbar_state = ScrollbarState::new(scroll_len)
                    .position(state.offset())
                    .viewport_content_length(viewport_len);
                frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
            }
        }
    }

    fn format_log_line<'a>(&self, entry: &'a LogEntry) -> Line<'a> {
        let mut spans = Vec::new();
        if self.state.show_color_indicator {
            let dot = if let Some(color_name) = entry.color.as_deref() {
                self.color_from_name(color_name)
                    .map(|color| Span::styled("● ", self.base_style().fg(color)))
                    .unwrap_or_else(|| Span::raw("  "))
            } else {
                Span::raw("  ")
            };
            spans.push(dot);
        }
        if self.state.show_timestamp {
            if let Some(ts) = entry.timestamp {
                spans.push(Span::raw(format!("[{}] ", ts)));
            }
        }
        if self.state.show_labels {
            if let Some(label) = entry.entry_type.as_deref() {
                spans.push(Span::raw(format!("[{}] ", label)));
            }
        }
        if self.state.show_filename {
            if let Some(file) = entry.origin_file.as_deref() {
                let label = if let Some(line) = entry.origin_line {
                    format!("{file}:{line}")
                } else {
                    file.to_string()
                };
                spans.push(Span::raw(format!("{} ", label)));
            }
        }
        if self.state.show_message {
            spans.push(Span::raw(entry.message.clone()));
        }
        if self.state.show_uuid {
            let prefix = entry.uuid.get(..5).unwrap_or(entry.uuid.as_str());
            spans.push(Span::raw(" "));
            spans.push(Span::styled(prefix, self.dimmed_style()));
        }
        Line::from(spans)
    }

    fn render_detail(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let focused = self.state.mode == Mode::Normal
            && self.state.focus == FocusPane::Detail
            && !self.modal_open();
        let border_style = self.panel_border_style(focused);
        let title_style = self.panel_title_style(focused);
        let transformed = matches!(
            self.state.last_detail_search.as_ref(),
            Some(DetailSearchResult::JsonPath(_)) | Some(DetailSearchResult::Jq(_))
        );
        let uuid = self.selected_entry().map(|entry| entry.uuid.clone());
        let (display_stats, blob_stats, timestamp_iso) = {
            let cached = self.detail_cached();
            (cached.display_stats, cached.blob_stats, cached.timestamp_iso.clone())
        };
        let mut title_spans: Vec<Span<'static>> = vec![Span::raw("─ ")];
        if transformed {
            title_spans.push(Span::styled(
                "Detail",
                self.base_style().fg(self.ansi_color(Ansi16::Red)).add_modifier(Modifier::BOLD),
            ));
        } else {
            title_spans.push(Span::raw("Detail"));
        }
        if let Some(ts) = &timestamp_iso {
            title_spans.push(Span::raw(" "));
            title_spans.push(Span::styled(
                ts.clone(),
                self.base_style().fg(self.ansi_color(Ansi16::Yellow)),
            ));
        }
        if let Some(uuid) = uuid {
            title_spans.push(Span::raw(" "));
            title_spans.push(Span::styled(uuid, self.dimmed_style()));
        }
        title_spans.push(Span::raw(" "));
        let title = Line::from(title_spans);
        let bottom = format!(
            "─ {} lines · {} bytes · {} tok ─",
            blob_stats.lines, blob_stats.bytes, blob_stats.tokens
        );
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_bottom(Line::from(bottom).right_aligned())
            .border_style(border_style)
            .title_style(title_style);
        let inner = block.inner(area);
        self.state.detail_viewport_height = inner.height;
        let max_scroll =
            display_stats.lines.saturating_sub(inner.height as usize).min(u16::MAX as usize) as u16;
        self.state.detail_scroll = self.state.detail_scroll.min(max_scroll);
        let scroll = self.state.detail_scroll;
        let cached = self.detail_cached();
        let paragraph = Paragraph::new(cached.render.clone())
            .block(block)
            .scroll((scroll, 0))
            .style(self.base_style());
        frame.render_widget(paragraph, area);
    }

    fn render_archives(&self, frame: &mut Frame<'_>, area: Rect) {
        let total = self.state.archives.len();
        let pos =
            if total == 0 { 0 } else { self.state.archive_selected.saturating_add(1).min(total) };
        let title = "─ Archives ".to_string();
        let bottom = format!("─ {pos} of {total} ─");
        let focused = self.state.mode == Mode::Normal
            && self.state.focus == FocusPane::Archives
            && !self.modal_open();
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .title_bottom(Line::from(bottom).right_aligned())
            .border_style(self.panel_border_style(focused))
            .title_style(self.panel_title_style(focused));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let active = self.viewing_archive.as_deref();
        let selected_style = self
            .base_style()
            .fg(self.ansi_color(Ansi16::Black))
            .bg(self.ansi_color(Ansi16::White))
            .add_modifier(Modifier::BOLD);
        let selected_idx =
            self.state.archive_selected.min(self.state.archives.len().saturating_sub(1));
        let items: Vec<ListItem> = self
            .state
            .archives
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                let (marker, marker_style) = if entry.live && self.state.paused {
                    (
                        "⏸ ",
                        Style::default()
                            .fg(self.ansi_color(Ansi16::Yellow))
                            .add_modifier(Modifier::BOLD),
                    )
                } else if entry.live {
                    ("▶ ", Style::default().fg(self.ansi_color(Ansi16::Green)))
                } else if active == Some(entry.path.as_path()) {
                    ("◼ ", Style::default().fg(self.ansi_color(Ansi16::Blue)))
                } else {
                    ("◻ ", Style::default().fg(self.ansi_color(Ansi16::BrightBlack)))
                };

                let line = Line::from(vec![
                    Span::styled(marker, marker_style),
                    Span::raw(format!("{} ({})", entry.name, entry.count)),
                ]);
                let mut item = ListItem::new(line);
                if idx == selected_idx {
                    item = item.style(selected_style);
                }
                item
            })
            .collect();
        let content_len = items.len();
        let mut state = ListState::default();
        if !self.state.archives.is_empty() {
            state.select(Some(self.state.archive_selected.min(self.state.archives.len() - 1)));
        }
        let list = List::new(items)
            .style(self.base_style())
            .highlight_style(Style::default())
            .highlight_symbol("");

        let (list_area, scrollbar_area) = split_for_scrollbar(inner);
        frame.render_stateful_widget(list, list_area, &mut state);

        if let Some(scrollbar_area) = scrollbar_area {
            if content_len > 0 && list_area.height > 0 {
                let thumb_style = self.dimmed_style();
                let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .thumb_style(thumb_style)
                    .track_style(self.dimmed_style());
                let viewport_len = list_area.height as usize;
                let scroll_len = content_len.saturating_sub(viewport_len).saturating_add(1);
                let mut scrollbar_state = ScrollbarState::new(scroll_len)
                    .position(state.offset())
                    .viewport_content_length(viewport_len);
                frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
            }
        }
    }

    fn render_footer(&self, frame: &mut Frame<'_>, area: Rect) {
        // Clear/fill the whole footer area so any extra spacing above the footer line is blank.
        frame.render_widget(Block::default().style(self.base_style()), area);

        let footer_area = if area.height > 1 {
            Rect { x: area.x, y: area.y + area.height - 1, width: area.width, height: 1 }
        } else {
            area
        };

        let key_style = self.help_key_style();
        let sep_style = self.dimmed_style();
        let compact = self.stack_panes_vertically(area);
        let sep = " | ";

        let mut spans: Vec<Span<'static>> = Vec::new();
        let push_sep = |spans: &mut Vec<Span<'static>>| {
            if !spans.is_empty() {
                spans.push(Span::styled(sep, sep_style));
            }
        };
        let push_item = |spans: &mut Vec<Span<'static>>, label: &'static str, key: &'static str| {
            push_sep(spans);
            spans.push(Span::styled(label, sep_style));
            spans.push(Span::raw(":"));
            spans.push(Span::styled(key, key_style));
        };

        if compact && !matches!(self.state.mode, Mode::Search | Mode::Command) {
            push_item(&mut spans, "Pause", "p");
            push_item(&mut spans, "Menu", "Space");
            push_item(&mut spans, "Help", "?");
            push_item(&mut spans, "Quit", "q");
        } else {
            match self.state.mode {
                Mode::Search | Mode::Command => {
                    push_item(&mut spans, "Search", "/");
                    push_item(&mut spans, "Regex", "r");
                    push_item(&mut spans, "Command", ":");
                    push_item(&mut spans, "Close", "Esc");
                }
                _ => match self.state.focus {
                    FocusPane::Logs => {
                        push_item(&mut spans, "Move", "j/k");
                        push_item(&mut spans, "Scroll", "J/K");
                        push_item(&mut spans, "Goto", "g");
                        push_item(&mut spans, "Snap", "s");
                        push_item(&mut spans, "Columns", "1-6");
                        push_item(&mut spans, "Archive", "x");
                        push_item(&mut spans, "Reset", "u");
                        push_item(&mut spans, "Pause", "p");
                        push_item(&mut spans, "Menu", "Space");
                        push_item(&mut spans, "Help", "?");
                        push_item(&mut spans, "Quit", "q");
                    }
                    FocusPane::Detail => {
                        push_item(&mut spans, "Move", "j/k");
                        push_item(&mut spans, "Scroll", "J/K");
                        push_item(&mut spans, "Meta", "m");
                        push_item(&mut spans, "Edit", "e");
                        push_item(&mut spans, "Open", "o");
                        push_item(&mut spans, "Yank", "y/Y");
                        push_item(&mut spans, "Pause", "p");
                        push_item(&mut spans, "Menu", "Space");
                        push_item(&mut spans, "Help", "?");
                        push_item(&mut spans, "Quit", "q");
                    }
                    FocusPane::Archives => {
                        push_item(&mut spans, "Move", "j/k");
                        push_item(&mut spans, "Load", "Enter");
                        push_item(&mut spans, "Rename", "n");
                        push_item(&mut spans, "Delete", "d");
                        push_item(&mut spans, "Reset", "u");
                        push_item(&mut spans, "Pause", "p");
                        push_item(&mut spans, "Menu", "Space");
                        push_item(&mut spans, "Help", "?");
                        push_item(&mut spans, "Quit", "q");
                    }
                },
            }
        }

        let left = Line::from(spans);
        let brand_width = 18;
        if footer_area.width > brand_width {
            let chunks = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Min(0), Constraint::Length(brand_width)])
                .split(footer_area);
            frame.render_widget(
                Paragraph::new(left).alignment(Alignment::Left).style(sep_style),
                chunks[0],
            );
            frame.render_widget(
                Paragraph::new("🆁 🅰 🆈 🅼 🅾 🅽 ")
                    .alignment(Alignment::Right)
                    .style(self.base_style().add_modifier(Modifier::BOLD)),
                chunks[1],
            );
        } else {
            frame.render_widget(
                Paragraph::new(left).alignment(Alignment::Left).style(sep_style),
                footer_area,
            );
        }
    }

    fn render_help(&mut self, frame: &mut Frame<'_>) {
        let (w, h) = match self.state.help_mode {
            HelpMode::Space => (60, 45),
            HelpMode::Keymap => (72, 80),
        };
        let area = centered_rect(w, h, frame.area());
        frame.render_widget(Clear, area);
        let key_style = self.help_key_style();
        let header_style = self.help_header_style();
        let dim_style = self.dimmed_style();

        let key_col_width = "J/K, PgUp/PgDn".len().max("Enter / Space".len());
        let kv = |key: &str, desc: &str| -> Line<'static> {
            Line::from(vec![
                Span::styled(format!("{key:>width$}", width = key_col_width), key_style),
                Span::raw("  "),
                Span::raw(desc.to_string()),
            ])
        };

        let mut text = Vec::new();
        match self.state.help_mode {
            HelpMode::Space => {
                text.push(Line::from(""));
                text.push(kv("s", "Screens picker"));
                text.push(kv("c", "Color filters"));
                text.push(kv("t", "Type filters"));
                text.push(Line::from(""));
                text.push(Line::from(vec![
                    Span::styled("Close: ", dim_style),
                    Span::styled("Esc", key_style),
                ]));
            }
            HelpMode::Keymap => {
                text.push(Line::from(Span::styled("--- Normal ---", header_style)));
                text.push(kv("j/k, ↑/↓", "Move (focused pane)"));
                text.push(kv("J/K", "Scroll detail up/down (Logs + Detail panes)"));
                text.push(kv("Tab/Shift-Tab", "Focus next/prev pane"));
                text.push(kv("h / ←", "Focus pane left"));
                text.push(kv("l / →", "Focus pane right"));
                text.push(kv("PgUp/PgDn", "Scroll detail by page (Logs + Detail panes)"));
                text.push(kv("Mouse", "Click selects/focuses, wheel moves"));
                text.push(kv("?", "Help"));
                text.push(kv("q", "Quit"));
                text.push(kv("/", "Search (fuzzy; message + file; paths are literal)"));
                text.push(kv("r", "Search (regex; message + file)"));
                text.push(kv(":", "Search inside detail (jq)"));
                text.push(kv("g", "Goto position"));
                text.push(kv("G", "Jump to last log"));
                text.push(kv("s", "Snap color + type filters to selected log"));
                text.push(kv("p", "Pause/resume live updates"));
                text.push(kv("Ctrl+l", "Clear live logs list"));
                text.push(kv("x", "Archive current view to file"));
                text.push(kv("y", "Yank message"));
                text.push(kv("Y", "Yank detail"));
                text.push(kv("u", "Reset search + filters"));
                text.push(kv("Ctrl+y", "Paste into inputs"));
                text.push(kv("e", "Open detail in $EDITOR"));
                text.push(kv("o", "Open origin in IDE"));
                text.push(kv("a", "Toggle archives pane"));
                text.push(kv("Enter", "Load selected archive (Archives pane)"));
                text.push(kv("n", "Rename selected archive (Archives pane)"));
                text.push(kv("d", "Delete selected archive (Archives pane)"));
                text.push(kv("z / Z", "Toggle JSON expanded / raw"));
                text.push(kv("m", "Toggle style/meta payloads in detail"));
                text.push(kv("1-6", "Toggle color/timestamp/type label/file/message/uuid"));
                text.push(Line::from(""));
                text.push(Line::from(Span::styled("--- Pickers ---", header_style)));
                text.push(kv("j/k, ↑/↓", "Move selection"));
                text.push(kv("Enter / Space", "Select / toggle"));
                text.push(kv("Backspace", "Edit query"));
                text.push(kv("Ctrl+y", "Paste into query"));
                text.push(kv("Esc", "Close picker"));
                text.push(Line::from(""));
                text.push(Line::from(vec![
                    Span::styled("Also: ", dim_style),
                    Span::styled("Ctrl+c", key_style),
                    Span::styled(" quits from anywhere.", dim_style),
                ]));
            }
        }
        let title = match self.state.help_mode {
            HelpMode::Space => "Menu",
            HelpMode::Keymap => "Keybindings",
        };
        let title = format!("─ {title} ─");
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(self.panel_border_style(true))
            .title_style(self.panel_title_style(true));
        let inner = block.inner(area);
        self.state.help_viewport_height = inner.height;
        let max_scroll =
            text.len().saturating_sub(inner.height.max(1) as usize).min(u16::MAX as usize) as u16;
        self.state.help_scroll = self.state.help_scroll.min(max_scroll);
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Left)
            .style(self.base_style())
            .wrap(Wrap { trim: false })
            .scroll((self.state.help_scroll, 0));
        frame.render_widget(paragraph, area);
    }

    fn render_rename_archive(&self, frame: &mut Frame<'_>) {
        let Some(rename) = self.state.rename_archive.as_ref() else {
            return;
        };

        let old_name = archive_display_name(&rename.path);
        let input_style = self.base_style().add_modifier(Modifier::REVERSED | Modifier::BOLD);
        let dim_style = self.dimmed_style();
        let key_style = self.help_key_style();

        let area = centered_rect(62, 22, frame.area());
        frame.render_widget(Clear, area);

        let title = "─ Rename archive ─";
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(self.panel_border_style(true))
            .title_style(self.panel_title_style(true));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let trimmed = rename.input.buffer.trim_end();
        let has_ext = trimmed.to_ascii_lowercase().ends_with(".jsonl");
        let display = if trimmed.is_empty() { " " } else { trimmed };

        let mut text = Vec::new();
        text.push(Line::from(vec![
            Span::raw("Rename "),
            Span::styled(old_name, self.base_style().add_modifier(Modifier::BOLD)),
            Span::raw(" to:"),
        ]));
        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled(display.to_string(), input_style),
            Span::styled(if has_ext { "" } else { ".jsonl" }, dim_style),
        ]));
        text.push(Line::from(""));
        text.push(Line::from(Span::styled("File is renamed on disk.", dim_style)));
        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("Enter", key_style),
            Span::styled(": rename  ", dim_style),
            Span::styled("Esc", key_style),
            Span::styled(": cancel", dim_style),
        ]));

        let paragraph = Paragraph::new(text)
            .block(Block::default())
            .alignment(Alignment::Left)
            .style(self.base_style())
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, inner);
    }

    fn render_delete_archive_confirm(&self, frame: &mut Frame<'_>) {
        let Some(path) = self.state.delete_archive_confirm.as_deref() else {
            return;
        };

        let name = archive_display_name(path);
        let count =
            self.state.archives.iter().find(|entry| entry.path == path).map(|entry| entry.count);

        let area = centered_rect(55, 22, frame.area());
        frame.render_widget(Clear, area);

        let title = "─ Delete archive? ─";
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(self.panel_border_style(true))
            .title_style(self.panel_title_style(true));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let key_style = self.help_key_style();
        let dim_style = self.dimmed_style();

        let mut text = Vec::new();
        let mut first = vec![
            Span::raw("Delete "),
            Span::styled(name, self.base_style().add_modifier(Modifier::BOLD)),
            Span::raw("?"),
        ];
        if let Some(count) = count {
            first.push(Span::styled(format!(" ({count})"), dim_style));
        }
        text.push(Line::from(first));
        text.push(Line::from(""));
        text.push(Line::from(Span::styled("This removes the archive file from disk.", dim_style)));
        text.push(Line::from(""));
        text.push(Line::from(vec![
            Span::styled("Enter", key_style),
            Span::styled(": delete  ", dim_style),
            Span::styled("Esc", key_style),
            Span::styled(": cancel", dim_style),
        ]));

        let paragraph = Paragraph::new(text)
            .block(Block::default())
            .alignment(Alignment::Left)
            .style(self.base_style())
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, inner);
    }

    fn render_picker(&self, frame: &mut Frame<'_>) {
        let Some(picker) = &self.state.picker else {
            return;
        };
        let area = centered_rect(70, 60, frame.area());
        frame.render_widget(Clear, area);

        let title = match picker.kind {
            PickerKind::Screens => "Screens",
            PickerKind::Colors => "Color Filters",
            PickerKind::Types => "Type Filters",
        };
        let title = format!("─ {title} ─");
        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(self.panel_border_style(true))
            .title_style(self.panel_title_style(true));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(2)])
            .split(inner);

        let prompt = if matches!(picker.kind, PickerKind::Colors | PickerKind::Types) {
            "Filter"
        } else {
            "Search"
        };
        let header = Paragraph::new(Line::from(vec![
            Span::styled(format!("{prompt}: "), self.dimmed_style()),
            Span::styled(
                picker.query.buffer.clone(),
                self.base_style().add_modifier(Modifier::BOLD),
            ),
        ]))
        .alignment(Alignment::Left)
        .style(self.base_style());
        frame.render_widget(header, chunks[0]);

        let items: Vec<ListItem> = if picker.filtered.is_empty() {
            vec![ListItem::new("No matches")]
        } else {
            picker
                .filtered
                .iter()
                .filter_map(|idx| picker.items.get(*idx))
                .map(|item| {
                    let mut spans = Vec::new();
                    if picker.multi_select {
                        spans.push(Span::raw(if item.active { "[x] " } else { "[ ] " }));
                    }
                    if matches!(picker.kind, PickerKind::Colors) {
                        if let Some(color) = self.color_from_name(&item.label) {
                            spans.push(Span::styled(
                                item.label.clone(),
                                self.base_style().fg(color),
                            ));
                        } else {
                            spans.push(Span::raw(item.label.clone()));
                        }
                    } else {
                        spans.push(Span::raw(item.label.clone()));
                    }
                    if let Some(meta) = &item.meta {
                        spans.push(Span::styled(format!(" {}", meta), self.dimmed_style()));
                    }
                    ListItem::new(Line::from(spans))
                })
                .collect()
        };
        let mut state = ListState::default();
        if !picker.filtered.is_empty() {
            state.select(Some(picker.selected));
        }
        let list = List::new(items)
            .style(self.base_style())
            .highlight_style(self.selection_style())
            .highlight_symbol("");
        let content_len = picker.filtered.len();
        let (list_area, scrollbar_area) = split_for_scrollbar(chunks[1]);
        frame.render_stateful_widget(list, list_area, &mut state);
        if let Some(scrollbar_area) = scrollbar_area {
            if content_len > 0 && list_area.height > 0 {
                let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .thumb_style(self.base_style().fg(self.ansi_color(Ansi16::Green)))
                    .track_style(self.dimmed_style());
                let viewport_len = list_area.height as usize;
                let scroll_len = content_len.saturating_sub(viewport_len).saturating_add(1);
                let mut scrollbar_state = ScrollbarState::new(scroll_len)
                    .position(state.offset())
                    .viewport_content_length(viewport_len);
                frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
            }
        }

        let footer_text = if picker.multi_select {
            "Space/Enter: toggle  Esc: close"
        } else {
            "Space/Enter: select  Esc: close"
        };
        let footer = Paragraph::new(footer_text)
            .alignment(Alignment::Left)
            .style(self.dimmed_style())
            .wrap(Wrap { trim: true });
        frame.render_widget(footer, chunks[2]);
    }

    fn detail_cache_key(&self) -> DetailCacheKey {
        let (entry_id, entry_timestamp) = match self.selected_entry() {
            Some(entry) => (Some(entry.id), entry.timestamp),
            None => (None, None),
        };
        let jq_fingerprint = match &self.state.last_detail_search {
            Some(DetailSearchResult::JsonPath(result)) | Some(DetailSearchResult::Jq(result)) => {
                Some(JqFingerprint::new(result))
            }
            _ => None,
        };
        DetailCacheKey {
            entry_id,
            entry_timestamp,
            json_expanded: self.state.json_expanded,
            json_raw: self.state.json_raw,
            show_decorators: self.state.show_decorators,
            jq_fingerprint,
        }
    }

    fn detail_cached(&mut self) -> &DetailCache {
        let key = self.detail_cache_key();
        let needs_refresh = match &self.detail_cache {
            Some(cache) => cache.key != key,
            None => true,
        };

        if needs_refresh {
            let (text, is_json) = self.detail_text();
            let display_stats = detail_stats_for_text(&text);
            let render = if is_json { self.json_syntax_highlight(&text) } else { Text::from(text) };
            let blob_text = self.detail_blob_text();
            let blob_stats = detail_stats_for_text(&blob_text);
            let timestamp_iso = key.entry_timestamp.and_then(format_iso_timestamp_millis);
            self.detail_cache =
                Some(DetailCache { key, timestamp_iso, render, display_stats, blob_stats });
            self.state.detail_scroll = 0;
        }

        self.detail_cache.as_ref().expect("detail cache should be present after refresh")
    }

    fn detail_blob_text(&self) -> String {
        let Some(entry) = self.selected_entry() else {
            return "No selection.".to_string();
        };
        if let Some(DetailSearchResult::JsonPath(result) | DetailSearchResult::Jq(result)) =
            &self.state.last_detail_search
        {
            return result.clone();
        }
        entry.detail.clone()
    }

    fn detail_text(&self) -> (String, bool) {
        let Some(entry) = self.selected_entry() else {
            return ("No selection.".to_string(), false);
        };
        if let Some(DetailSearchResult::JsonPath(result) | DetailSearchResult::Jq(result)) =
            &self.state.last_detail_search
        {
            let is_json = serde_json::from_str::<Value>(result).is_ok();
            return (result.clone(), is_json);
        }

        let parsed = match serde_json::from_str::<Value>(&entry.detail) {
            Ok(value) => value,
            Err(_) => return (entry.detail.clone(), false),
        };

        let decorated = detail_value_with_decorators(parsed, self.state.show_decorators);

        if self.state.json_expanded {
            let compact =
                serde_json::to_string(&decorated).unwrap_or_else(|_| entry.detail.clone());
            let text = if self.state.json_raw {
                compact
            } else {
                serde_json::to_string_pretty(&decorated).unwrap_or(compact)
            };
            (text, true)
        } else {
            (json_summary(&decorated), false)
        }
    }

    fn regex_filter(&self, indices: &[usize], regex: &regex::Regex) -> Vec<usize> {
        indices
            .iter()
            .copied()
            .filter(|idx| {
                self.state.logs.get(*idx).is_some_and(|entry| {
                    regex.is_match(&entry.message)
                        || entry.origin.as_deref().is_some_and(|origin| regex.is_match(origin))
                        || entry.origin_file.as_deref().is_some_and(|file| regex.is_match(file))
                        || regex.is_match(&entry.uuid)
                })
            })
            .collect()
    }

    fn fuzzy_filter(&self, indices: &[usize], query: &str) -> Vec<usize> {
        let query_lower = query.to_lowercase();
        let threshold = if query_lower.len() <= 2 { 0.2 } else { 0.35 };
        let query_trimmed = query_lower.trim_start_matches('/');
        let path_like_query = query_lower.chars().any(|ch| matches!(ch, '/' | '\\' | '.' | ':'));
        #[cfg(feature = "rayon")]
        let use_parallel = indices.len() >= 200;
        let candidates: Vec<(usize, String, Option<String>, String)> = indices
            .iter()
            .filter_map(|idx| {
                self.state.logs.get(*idx).map(|entry| {
                    let origin = entry.origin.as_deref().or(entry.origin_file.as_deref());
                    (
                        *idx,
                        entry.message.to_lowercase(),
                        origin.map(|value| value.to_lowercase()),
                        entry.uuid.to_ascii_lowercase(),
                    )
                })
            })
            .collect();

        let score_entry = |(idx, message_lower, origin_lower, uuid_lower): &(
            usize,
            String,
            Option<String>,
            String,
        )| {
            let contains = |haystack: &str| {
                haystack.contains(&query_lower)
                    || (!query_trimmed.is_empty() && haystack.contains(query_trimmed))
            };

            if contains(message_lower)
                || origin_lower.as_ref().is_some_and(|origin| contains(origin))
                || contains(uuid_lower)
            {
                return Some((*idx, 1.0));
            }

            if path_like_query {
                return None;
            }

            let mut best = fuzz::ratio(query_lower.chars(), message_lower.chars());
            if let Some(origin) = origin_lower.as_ref() {
                best = best.max(fuzz::ratio(query_lower.chars(), origin.chars()));
            }

            if best >= threshold {
                Some((*idx, best))
            } else {
                None
            }
        };

        let mut scored: Vec<(usize, f64)> = {
            #[cfg(feature = "rayon")]
            {
                if use_parallel {
                    candidates.par_iter().filter_map(score_entry).collect()
                } else {
                    candidates.iter().filter_map(score_entry).collect()
                }
            }
            #[cfg(not(feature = "rayon"))]
            {
                candidates.iter().filter_map(score_entry).collect()
            }
        };

        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal).then_with(|| a.0.cmp(&b.0))
        });

        scored.into_iter().map(|(idx, _)| idx).collect()
    }
}

#[derive(Debug, Clone, Copy)]
enum YankKind {
    Message,
    Detail,
}

#[derive(Debug, Clone, Copy)]
enum InputTarget {
    Search,
    Command,
}

#[derive(Debug)]
enum PickerAction {
    None,
    Close,
    Select(PickerItemId),
    Toggle(PickerItemId),
    Paste,
}

fn detail_value_with_decorators(value: Value, show_decorators: bool) -> Value {
    let Value::Array(items) = value else {
        return value;
    };

    let mut content = Vec::new();
    let mut decorators = Vec::new();

    for item in items {
        if is_styling_payload_value(&item) {
            decorators.push(item);
        } else {
            content.push(item);
        }
    }

    if decorators.is_empty() {
        return Value::Array(content);
    }

    if show_decorators {
        let mut map = serde_json::Map::new();
        map.insert("content".to_string(), Value::Array(content));
        map.insert("decorators".to_string(), Value::Array(decorators));
        Value::Object(map)
    } else {
        Value::Array(content)
    }
}

fn is_styling_payload_value(value: &Value) -> bool {
    let Value::Object(map) = value else {
        return false;
    };

    if map.len() != 1 {
        return false;
    }

    if let Some(value) = map.get("color").and_then(|value| value.as_str()) {
        return canonical_color_name(value).is_some();
    }

    if let Some(value) = map.get("label").and_then(|value| value.as_str()) {
        return !value.trim().is_empty();
    }

    if let Some(value) = map.get("size").and_then(|value| value.as_str()) {
        return matches!(value.trim().to_ascii_lowercase().as_str(), "small" | "normal" | "large");
    }

    false
}

fn json_summary(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let keys: Vec<&String> = map.keys().collect();
            if keys.is_empty() {
                "JSON (empty object)".to_string()
            } else {
                let list =
                    keys.iter().take(6).map(|key| key.as_str()).collect::<Vec<_>>().join(", ");
                format!("JSON (collapsed): keys: {}", list)
            }
        }
        Value::Array(values) => format!("JSON (collapsed): array [{}]", values.len()),
        _ => "JSON (collapsed)".to_string(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonHighlightKind {
    Key,
    String,
    Number,
    Bool,
    Null,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonObjectPhase {
    KeyOrEnd,
    Colon,
    Value,
    CommaOrEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonArrayPhase {
    ValueOrEnd,
    CommaOrEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonContext {
    Object(JsonObjectPhase),
    Array(JsonArrayPhase),
}

fn json_after_value(context: &mut [JsonContext]) {
    match context.last_mut() {
        Some(JsonContext::Object(phase)) if *phase == JsonObjectPhase::Value => {
            *phase = JsonObjectPhase::CommaOrEnd;
        }
        Some(JsonContext::Array(phase)) if *phase == JsonArrayPhase::ValueOrEnd => {
            *phase = JsonArrayPhase::CommaOrEnd;
        }
        _ => {}
    }
}

fn json_highlight_segments(input: &str) -> Vec<(JsonHighlightKind, &str)> {
    let bytes = input.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();
    let mut context: Vec<JsonContext> = Vec::new();

    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'"' => {
                let start = i;
                i += 1;
                let mut escaped = false;
                while i < bytes.len() {
                    let byte = bytes[i];
                    if escaped {
                        escaped = false;
                        i += 1;
                        continue;
                    }
                    match byte {
                        b'\\' => {
                            escaped = true;
                            i += 1;
                        }
                        b'"' => {
                            i += 1;
                            break;
                        }
                        _ => i += 1,
                    }
                }

                let kind = match context.last_mut() {
                    Some(JsonContext::Object(phase)) if *phase == JsonObjectPhase::KeyOrEnd => {
                        *phase = JsonObjectPhase::Colon;
                        JsonHighlightKind::Key
                    }
                    _ => {
                        json_after_value(&mut context);
                        JsonHighlightKind::String
                    }
                };
                out.push((kind, &input[start..i]));
            }
            b'{' => {
                let start = i;
                i += 1;
                out.push((JsonHighlightKind::Other, &input[start..i]));
                context.push(JsonContext::Object(JsonObjectPhase::KeyOrEnd));
            }
            b'}' => {
                let start = i;
                i += 1;
                out.push((JsonHighlightKind::Other, &input[start..i]));
                if matches!(context.last(), Some(JsonContext::Object(_))) {
                    context.pop();
                    json_after_value(&mut context);
                }
            }
            b'[' => {
                let start = i;
                i += 1;
                out.push((JsonHighlightKind::Other, &input[start..i]));
                context.push(JsonContext::Array(JsonArrayPhase::ValueOrEnd));
            }
            b']' => {
                let start = i;
                i += 1;
                out.push((JsonHighlightKind::Other, &input[start..i]));
                if matches!(context.last(), Some(JsonContext::Array(_))) {
                    context.pop();
                    json_after_value(&mut context);
                }
            }
            b':' => {
                let start = i;
                i += 1;
                out.push((JsonHighlightKind::Other, &input[start..i]));
                if let Some(JsonContext::Object(phase)) = context.last_mut() {
                    if *phase == JsonObjectPhase::Colon {
                        *phase = JsonObjectPhase::Value;
                    }
                }
            }
            b',' => {
                let start = i;
                i += 1;
                out.push((JsonHighlightKind::Other, &input[start..i]));
                match context.last_mut() {
                    Some(JsonContext::Object(phase)) if *phase == JsonObjectPhase::CommaOrEnd => {
                        *phase = JsonObjectPhase::KeyOrEnd;
                    }
                    Some(JsonContext::Array(phase)) if *phase == JsonArrayPhase::CommaOrEnd => {
                        *phase = JsonArrayPhase::ValueOrEnd;
                    }
                    _ => {}
                }
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                if bytes[i] == b'-' {
                    i += 1;
                }
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                if i < bytes.len() && bytes[i] == b'.' {
                    i += 1;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                if i < bytes.len() && matches!(bytes[i], b'e' | b'E') {
                    i += 1;
                    if i < bytes.len() && matches!(bytes[i], b'+' | b'-') {
                        i += 1;
                    }
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                out.push((JsonHighlightKind::Number, &input[start..i]));
                json_after_value(&mut context);
            }
            b't' if bytes[i..].starts_with(b"true") => {
                let start = i;
                i += 4;
                out.push((JsonHighlightKind::Bool, &input[start..i]));
                json_after_value(&mut context);
            }
            b'f' if bytes[i..].starts_with(b"false") => {
                let start = i;
                i += 5;
                out.push((JsonHighlightKind::Bool, &input[start..i]));
                json_after_value(&mut context);
            }
            b'n' if bytes[i..].starts_with(b"null") => {
                let start = i;
                i += 4;
                out.push((JsonHighlightKind::Null, &input[start..i]));
                json_after_value(&mut context);
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                let start = i;
                i += 1;
                while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\r' | b'\n') {
                    i += 1;
                }
                out.push((JsonHighlightKind::Other, &input[start..i]));
            }
            _ => {
                let start = i;
                i += 1;
                out.push((JsonHighlightKind::Other, &input[start..i]));
            }
        }
    }

    out
}

fn archive_stamp(now: DateTime<Utc>) -> String {
    let millis = now.timestamp_subsec_millis();
    format!("{}-{:03}Z", now.format("%Y%m%dT%H%M%S"), millis)
}

fn archive_display_name(path: &Path) -> String {
    path.file_stem().and_then(|value| value.to_str()).unwrap_or("archive").to_string()
}

fn create_unique_jsonl_file(
    dir: &Path,
    base_name: &str,
) -> Result<(PathBuf, std::fs::File), std::io::Error> {
    for attempt in 0..=999u16 {
        let filename = if attempt == 0 {
            format!("{base_name}.jsonl")
        } else {
            format!("{base_name}-{attempt}.jsonl")
        };
        let path = dir.join(filename);
        match OpenOptions::new().create_new(true).append(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "archive file already exists"))
}

fn scan_archives(dir: &Path, live_path: Option<&Path>) -> Result<Vec<ArchiveFile>, std::io::Error> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut archives = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }

        let name = archive_display_name(&path);
        let count = count_jsonl_lines(&path)?;
        let live = live_path.is_some_and(|live| live == path.as_path());
        archives.push(ArchiveFile { name, count, path, live });
    }

    Ok(archives)
}

fn count_jsonl_lines(path: &Path) -> Result<usize, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0usize;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
    }
    Ok(count)
}

fn read_archive_jsonl(path: &Path) -> Result<(Vec<LogEntry>, usize), std::io::Error> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut logs = Vec::new();
    let mut skipped = 0usize;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<LogEntry>(trimmed) {
            Ok(entry) => logs.push(entry),
            Err(_) => skipped += 1,
        }
    }

    Ok((logs, skipped))
}

fn parse_regex_input(input: &str) -> Option<Result<&str, String>> {
    if !input.starts_with('/') {
        return None;
    }
    if !input.ends_with('/') {
        return Some(Err("regex must end with '/'".to_string()));
    }
    if input.len() <= 2 {
        return Some(Err("regex pattern is empty".to_string()));
    }
    Some(Ok(&input[1..input.len() - 1]))
}

fn normalize_label(value: &str) -> String {
    value.trim().to_lowercase()
}

fn matches_filter_set(set: &BTreeSet<String>, value: Option<&str>) -> bool {
    if set.is_empty() {
        return true;
    }
    let Some(value) = value else {
        return false;
    };
    set.contains(&normalize_label(value))
}

fn toggle_filter(set: &mut BTreeSet<String>, value: String) {
    if set.contains(&value) {
        set.remove(&value);
    } else {
        set.insert(value);
    }
}

fn summarize_set(set: &BTreeSet<String>) -> String {
    let mut iter = set.iter();
    let mut labels = Vec::new();
    for _ in 0..3 {
        if let Some(value) = iter.next() {
            labels.push(value.clone());
        } else {
            break;
        }
    }
    if set.len() > labels.len() {
        format!("{} +{}", labels.join(","), set.len() - labels.len())
    } else {
        labels.join(",")
    }
}

fn format_iso_timestamp_millis(timestamp_millis: u64) -> Option<String> {
    let millis = i64::try_from(timestamp_millis).ok()?;
    let dt = DateTime::<Utc>::from_timestamp_millis(millis)?;
    Some(dt.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn detail_stats_for_text(text: &str) -> DetailStats {
    let bytes = text.len();
    let lines = if text.is_empty() { 0 } else { text.lines().count() };
    let tokens = o200k_base_singleton().encode_with_special_tokens(text).len();
    DetailStats { lines, bytes, tokens }
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }

    if needle_lower.len() > haystack.len() {
        return false;
    }

    if needle_lower.len() == 1 {
        let needle = needle_lower[0];
        let needle_upper = needle.to_ascii_uppercase();
        return if needle_upper == needle {
            memchr(needle, haystack).is_some()
        } else {
            memchr2(needle, needle_upper, haystack).is_some()
        };
    }

    let first = needle_lower[0];
    let first_upper = first.to_ascii_uppercase();

    let mut search = haystack;
    let mut base = 0usize;

    while let Some(pos) = if first_upper == first {
        memchr(first, search)
    } else {
        memchr2(first, first_upper, search)
    } {
        let start = base + pos;
        if haystack.len() - start < needle_lower.len() {
            return false;
        }

        let candidate = &haystack[start..start + needle_lower.len()];
        if candidate.iter().zip(needle_lower.iter()).all(|(&h, &n)| h.to_ascii_lowercase() == n) {
            return true;
        }

        base = start + 1;
        search = &haystack[base..];
    }

    false
}

pub fn fuzzy_rank_items(items: &[PickerItem], query: &str) -> Vec<usize> {
    let query_lower = query.to_lowercase();
    let threshold = if query_lower.len() <= 2 { 0.2 } else { 0.35 };
    #[cfg(feature = "rayon")]
    let use_parallel = items.len() >= 200;

    let score_item = |(idx, item): (usize, &PickerItem)| -> Option<(usize, f64)> {
        if query_lower.is_ascii() && item.label.is_ascii() {
            if contains_ascii_case_insensitive(item.label.as_bytes(), query_lower.as_bytes()) {
                return Some((idx, 1.0));
            }
            let score = fuzz::ratio(
                query_lower.as_bytes().iter().copied(),
                item.label.bytes().map(|b| b.to_ascii_lowercase()),
            );
            if score >= threshold {
                return Some((idx, score));
            }
            return None;
        }

        let candidate = item.label.to_lowercase();
        if candidate.contains(&query_lower) {
            return Some((idx, 1.0));
        }

        let score = fuzz::ratio(query_lower.chars(), candidate.chars());
        if score >= threshold {
            Some((idx, score))
        } else {
            None
        }
    };

    let mut scored: Vec<(usize, f64)> = {
        #[cfg(feature = "rayon")]
        {
            if use_parallel {
                items.par_iter().enumerate().filter_map(score_item).collect()
            } else {
                items.iter().enumerate().filter_map(score_item).collect()
            }
        }
        #[cfg(not(feature = "rayon"))]
        {
            items.iter().enumerate().filter_map(score_item).collect()
        }
    };

    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal).then_with(|| a.0.cmp(&b.0))
    });

    scored.into_iter().map(|(idx, _)| idx).collect()
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

fn split_for_scrollbar(area: Rect) -> (Rect, Option<Rect>) {
    if area.width <= 1 || area.height == 0 {
        return (area, None);
    }
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(area);
    (chunks[0], Some(chunks[1]))
}

fn logs_view_offset(selected: usize, total: usize, viewport_height: usize) -> usize {
    if viewport_height == 0 || total <= viewport_height {
        return 0;
    }
    let mut offset = selected.saturating_add(1).saturating_sub(viewport_height);
    let max_offset = total.saturating_sub(viewport_height);
    if offset > max_offset {
        offset = max_offset;
    }
    offset
}

fn launch_command(command: &str, arg: impl AsRef<Path>) -> Result<(), TuiError> {
    let parts =
        shlex::split(command).ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
    let (program, args) =
        parts.split_first().ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
    let arg = arg.as_ref();
    let arg_lossy = arg.as_os_str().to_string_lossy();
    if arg_lossy.starts_with('-') {
        return Err(TuiError::InvalidCommandLine(
            "refusing to pass argument starting with '-'".to_string(),
        ));
    }
    let mut cmd = Command::new(program);
    cmd.args(args).arg(arg);
    let status = cmd.status()?;
    if !status.success() {
        return Err(TuiError::InvalidCommandLine(format!("command failed: {}", command)));
    }
    Ok(())
}

fn run_jq_command(
    command: &str,
    detail: &str,
    query: &str,
    timeout: Duration,
) -> Result<Option<String>, TuiError> {
    let parts =
        shlex::split(command).ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
    let (program, args) =
        parts.split_first().ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
    let stdout_file = NamedTempFile::new()?;
    let stderr_file = NamedTempFile::new()?;
    let stdout = stdout_file.reopen()?;
    let stderr = stderr_file.reopen()?;
    let output = Command::new(program)
        .args(args)
        .arg("-e")
        .arg("-r")
        .arg("--")
        .arg(query)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn();

    let mut child = match output {
        Ok(child) => child,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::NotFound {
                return Err(TuiError::JqMissing);
            }
            return Err(TuiError::JqFailed(err.to_string()));
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(detail.as_bytes())?;
    }

    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TuiError::JqTimeout);
        }
        std::thread::sleep(Duration::from_millis(20));
    };

    let mut stdout_bytes = Vec::new();
    stdout_file.reopen()?.read_to_end(&mut stdout_bytes)?;
    let stdout = String::from_utf8_lossy(&stdout_bytes).trim().to_string();

    if status.success() {
        if stdout.is_empty() {
            Ok(None)
        } else {
            Ok(Some(stdout))
        }
    } else {
        let mut stderr_bytes = Vec::new();
        stderr_file.reopen()?.read_to_end(&mut stderr_bytes)?;
        if stderr_bytes.is_empty() {
            Ok(None)
        } else {
            Err(TuiError::JqFailed(String::from_utf8_lossy(&stderr_bytes).to_string()))
        }
    }
}

fn json_path_match(value: &Value, query: &str) -> Option<String> {
    let query = query.trim();
    if !query.starts_with('.') {
        return None;
    }
    let mut current = value;
    for segment in query.trim_start_matches('.').split('.') {
        if segment.is_empty() {
            continue;
        }
        if let Some(index) = segment.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let idx = index.parse::<usize>().ok()?;
            current = current.get(idx)?;
        } else {
            current = current.get(segment)?;
        }
    }
    Some(json_path_render(current))
}

fn json_path_render(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
        }
        other => other.to_string(),
    }
}

impl fmt::Debug for Tui {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tui").field("config", &self.config).field("state", &self.state).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use rstest::rstest;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[derive(Clone, Default)]
    struct MockClipboard {
        value: Arc<Mutex<String>>,
    }

    impl Clipboard for MockClipboard {
        fn get(&mut self) -> Result<String, TuiError> {
            Ok(self.value.lock().expect("lock clipboard").clone())
        }

        fn set(&mut self, contents: &str) -> Result<(), TuiError> {
            *self.value.lock().expect("lock clipboard") = contents.to_string();
            Ok(())
        }
    }

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent { code, modifiers, kind: KeyEventKind::Press, state: KeyEventState::empty() }
    }

    fn make_tui() -> (Tui, Arc<Mutex<String>>) {
        let value = Arc::new(Mutex::new(String::new()));
        let clipboard = MockClipboard { value: value.clone() };
        let tui = Tui::with_clipboard(TuiConfig::default(), Box::new(clipboard));
        (tui, value)
    }

    fn render_once(tui: &mut Tui) {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;

        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal.draw(|frame| tui.render(frame)).expect("draw");
    }

    fn seed_logs(tui: &mut Tui) {
        tui.push_log(LogEntry {
            id: 1,
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            message: "alpha".to_string(),
            detail: "{\"foo\":{\"bar\":\"baz\"}}".to_string(),
            origin: Some("file.rs:12".to_string()),
            origin_file: Some("file.rs".to_string()),
            origin_line: Some(12),
            timestamp: Some(1_000),
            entry_type: Some("log".to_string()),
            color: Some("red".to_string()),
            screen: Some("main".to_string()),
        });
        tui.push_log(LogEntry {
            id: 2,
            uuid: "00000000-0000-0000-0000-000000000002".to_string(),
            message: "beta".to_string(),
            detail: "plain detail".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(2_000),
            entry_type: Some("exception".to_string()),
            color: Some("blue".to_string()),
            screen: Some("main".to_string()),
        });
        tui.push_log(LogEntry {
            id: 3,
            uuid: "00000000-0000-0000-0000-000000000003".to_string(),
            message: "alphabet".to_string(),
            detail: "more detail".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(3_000),
            entry_type: Some("log".to_string()),
            color: Some("red".to_string()),
            screen: Some("secondary".to_string()),
        });
    }

    #[rstest]
    fn moves_selection_with_j_and_arrows() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        assert_eq!(tui.state.selected, 0);
        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 1);
        tui.handle_key(key(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 0);
        tui.handle_key(key(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 0);
    }

    #[test]
    fn json_is_expanded_by_default() {
        let (tui, _) = make_tui();
        assert!(tui.state.json_expanded);
    }

    #[rstest]
    fn uppercase_jk_scrolls_detail() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.state.detail_viewport_height = 3;
        assert_eq!(tui.state.selected, 0);
        assert_eq!(tui.state.detail_scroll, 0);
        tui.handle_key(key(KeyCode::Char('J'), KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 0);
        assert_eq!(tui.state.detail_scroll, 1);
        tui.handle_key(key(KeyCode::Char('K'), KeyModifiers::NONE));
        assert_eq!(tui.state.detail_scroll, 0);
    }

    #[rstest]
    fn page_keys_scroll_detail_by_page() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.state.detail_viewport_height = 3;
        tui.handle_key(key(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(tui.state.detail_scroll, 2);
        tui.handle_key(key(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(tui.state.detail_scroll, 2);
        tui.handle_key(key(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(tui.state.detail_scroll, 0);
    }

    #[test]
    fn mouse_click_selects_log_row() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        let rect = Rect { x: 0, y: 0, width: 100, height: 40 };
        let list_area = tui.logs_list_area(rect).expect("list area");

        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: list_area.x.saturating_add(1),
            row: list_area.y.saturating_add(1),
            modifiers: KeyModifiers::NONE,
        };
        tui.handle_mouse(mouse, rect);

        assert_eq!(tui.state.selected, 1);
    }

    #[test]
    fn mouse_click_selects_archive_row() {
        let (mut tui, _) = make_tui();
        tui.state.show_archives = true;
        tui.state.archives = vec![
            ArchiveFile {
                name: "live".to_string(),
                count: 1,
                path: PathBuf::from("/tmp/live.jsonl"),
                live: true,
            },
            ArchiveFile {
                name: "older".to_string(),
                count: 1,
                path: PathBuf::from("/tmp/older.jsonl"),
                live: false,
            },
        ];
        tui.state.archive_selected = 0;

        let rect = Rect { x: 0, y: 0, width: 140, height: 40 };
        let list_area = tui.archives_list_area(rect).expect("archives list area");

        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: list_area.x.saturating_add(1),
            row: list_area.y.saturating_add(1),
            modifiers: KeyModifiers::NONE,
        };
        tui.handle_mouse(mouse, rect);

        assert_eq!(tui.state.focus, FocusPane::Archives);
        assert_eq!(tui.state.archive_selected, 1);
    }

    #[test]
    fn mouse_click_focuses_search_bar() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.state.mode = Mode::Normal;

        let rect = Rect { x: 0, y: 0, width: 100, height: 40 };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(2)])
            .split(rect);
        let top_area = chunks[0];
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(14), Constraint::Length(1), Constraint::Min(0)])
            .split(top_area);
        let search_area = top_chunks[2];

        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: search_area.x.saturating_add(1),
            row: search_area.y.saturating_add(1),
            modifiers: KeyModifiers::NONE,
        };
        tui.handle_mouse(mouse, rect);

        assert_eq!(tui.state.mode, Mode::Search);
    }

    #[test]
    fn mouse_click_run_box_toggles_pause() {
        let (mut tui, _) = make_tui();
        tui.state.mode = Mode::Normal;
        tui.state.paused = false;

        let rect = Rect { x: 0, y: 0, width: 100, height: 40 };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(2)])
            .split(rect);
        let top_area = chunks[0];
        let top_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(14), Constraint::Length(1), Constraint::Min(0)])
            .split(top_area);
        let run_area = top_chunks[0];

        let mouse = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: run_area.x.saturating_add(1),
            row: run_area.y.saturating_add(1),
            modifiers: KeyModifiers::NONE,
        };
        tui.handle_mouse(mouse, rect);
        assert!(tui.state.paused);

        tui.handle_mouse(mouse, rect);
        assert!(!tui.state.paused);
    }

    #[test]
    fn hl_and_arrow_keys_move_focus_left_right() {
        let (mut tui, _) = make_tui();
        tui.state.mode = Mode::Normal;
        tui.state.show_archives = true;
        tui.state.focus = FocusPane::Logs;

        tui.handle_key(key(KeyCode::Char('l'), KeyModifiers::NONE));
        assert_eq!(tui.state.focus, FocusPane::Detail);

        tui.handle_key(key(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(tui.state.focus, FocusPane::Archives);

        tui.handle_key(key(KeyCode::Char('l'), KeyModifiers::NONE));
        assert_eq!(tui.state.focus, FocusPane::Archives);

        tui.handle_key(key(KeyCode::Char('h'), KeyModifiers::NONE));
        assert_eq!(tui.state.focus, FocusPane::Detail);

        tui.handle_key(key(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(tui.state.focus, FocusPane::Logs);

        tui.handle_key(key(KeyCode::Char('h'), KeyModifiers::NONE));
        assert_eq!(tui.state.focus, FocusPane::Logs);
    }

    #[test]
    fn shift_g_selects_last_log() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.state.mode = Mode::Normal;
        tui.state.focus = FocusPane::Logs;
        tui.state.selected = 0;

        tui.handle_key(key(KeyCode::Char('G'), KeyModifiers::NONE));
        assert_eq!(tui.state.selected, tui.state.filtered.len().saturating_sub(1));
    }

    #[rstest]
    fn live_search_filters_logs() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('a'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('l'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(tui.state.filtered.len(), 2);
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(tui.state.mode, Mode::Normal);
    }

    #[rstest]
    fn live_search_matches_filename() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        for ch in "file.rs".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(tui.state.filtered.first().copied(), Some(0));
    }

    #[rstest]
    fn live_search_matches_uuid() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        for ch in "000000000002".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(tui.state.filtered, vec![1]);
    }

    #[rstest]
    fn path_like_search_requires_substring_match() {
        let (mut tui, _) = make_tui();
        tui.push_log(LogEntry {
            id: 1,
            uuid: "00000000-0000-0000-0000-000000000005".to_string(),
            message: "GET /api/search -> 200".to_string(),
            detail: "{}".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(1_000),
            entry_type: Some("log".to_string()),
            color: Some("green".to_string()),
            screen: Some("main".to_string()),
        });
        tui.push_log(LogEntry {
            id: 2,
            uuid: "00000000-0000-0000-0000-000000000006".to_string(),
            message: "GET /api/search -> 200".to_string(),
            detail: "{}".to_string(),
            origin: Some("api/search.rs:307".to_string()),
            origin_file: Some("api/search.rs".to_string()),
            origin_line: Some(307),
            timestamp: Some(2_000),
            entry_type: Some("log".to_string()),
            color: Some("blue".to_string()),
            screen: Some("main".to_string()),
        });

        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        for ch in "api/search.rs:307".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }

        assert_eq!(tui.state.filtered, vec![1]);
    }

    #[test]
    fn push_log_updates_filtered_incrementally_when_query_is_empty() {
        let (mut tui, _) = make_tui();
        tui.state.active_screen = Some("main".to_string());

        tui.push_log(LogEntry {
            id: 1,
            uuid: "00000000-0000-0000-0000-000000000010".to_string(),
            message: "alpha".to_string(),
            detail: "{}".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(1_000),
            entry_type: Some("log".to_string()),
            color: Some("red".to_string()),
            screen: Some("main".to_string()),
        });

        assert!(!tui.filter_dirty);
        assert_eq!(tui.state.filtered, vec![0]);

        tui.push_log(LogEntry {
            id: 2,
            uuid: "00000000-0000-0000-0000-000000000011".to_string(),
            message: "beta".to_string(),
            detail: "{}".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(2_000),
            entry_type: Some("log".to_string()),
            color: Some("blue".to_string()),
            screen: Some("secondary".to_string()),
        });

        assert!(!tui.filter_dirty);
        assert_eq!(tui.state.filtered, vec![0]);
    }

    #[test]
    fn push_log_marks_filter_dirty_and_recomputes_on_render() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);

        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        for ch in "alp".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(tui.state.filtered.len(), 2);

        tui.push_log(LogEntry {
            id: 4,
            uuid: "00000000-0000-0000-0000-000000000004".to_string(),
            message: "alpha again".to_string(),
            detail: "{}".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(4_000),
            entry_type: Some("log".to_string()),
            color: Some("red".to_string()),
            screen: Some("main".to_string()),
        });

        assert!(tui.filter_dirty);
        assert_eq!(tui.state.filtered.len(), 2);

        render_once(&mut tui);

        assert!(!tui.filter_dirty);
        assert_eq!(tui.state.filtered.len(), 3);
        assert!(tui.state.filtered.contains(&3));
    }

    #[rstest]
    fn regex_search_matches_filename() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('r'), KeyModifiers::NONE));
        for ch in "file\\.rs/".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(tui.state.filtered.first().copied(), Some(0));
    }

    #[rstest]
    fn five_toggles_message_visibility() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        assert!(tui.state.show_message);
        tui.handle_key(key(KeyCode::Char('5'), KeyModifiers::NONE));
        assert!(!tui.state.show_message);
    }

    #[rstest]
    fn six_toggles_uuid_visibility() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        assert!(!tui.state.show_uuid);
        tui.handle_key(key(KeyCode::Char('6'), KeyModifiers::NONE));
        assert!(tui.state.show_uuid);
    }

    #[rstest]
    fn pause_queues_then_flushes() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('p'), KeyModifiers::NONE));
        assert!(tui.state.paused);
        tui.push_log(LogEntry {
            id: 4,
            uuid: "00000000-0000-0000-0000-000000000004".to_string(),
            message: "queued".to_string(),
            detail: "detail".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(4_000),
            entry_type: Some("log".to_string()),
            color: Some("red".to_string()),
            screen: Some("main".to_string()),
        });
        assert_eq!(tui.state.queued.len(), 1);
        tui.handle_key(key(KeyCode::Char('p'), KeyModifiers::NONE));
        assert!(!tui.state.paused);
        assert!(tui.state.queued.is_empty());
        assert_eq!(tui.state.logs.len(), 4);
    }

    #[rstest]
    fn space_menu_opens_and_esc_closes() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        assert_eq!(tui.state.mode, Mode::Space);
        assert!(tui.state.show_help);
        assert_eq!(tui.state.help_mode, HelpMode::Space);
        tui.handle_key(key(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!tui.state.show_help);
        assert_eq!(tui.state.mode, Mode::Normal);
    }

    #[rstest]
    fn question_mark_opens_keybindings_modal() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        assert_eq!(tui.state.mode, Mode::Normal);
        assert!(!tui.state.show_help);

        tui.handle_key(key(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(tui.state.show_help);
        assert_eq!(tui.state.help_mode, HelpMode::Keymap);
        assert_eq!(tui.state.mode, Mode::Normal);

        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 0);

        tui.handle_key(key(KeyCode::Esc, KeyModifiers::NONE));
        assert!(!tui.state.show_help);
    }

    #[rstest]
    fn paste_into_search() {
        let (mut tui, clipboard) = make_tui();
        seed_logs(&mut tui);
        *clipboard.lock().expect("lock clipboard") = "alpha".to_string();
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('y'), KeyModifiers::CONTROL));
        assert_eq!(tui.state.search.buffer, "alpha");
        assert_eq!(tui.state.filtered.len(), 2);
    }

    #[rstest]
    fn jq_like_detail_search_matches_path() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(':'), KeyModifiers::NONE));
        for ch in ".foo.bar".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert!(matches!(
            tui.state.last_detail_search,
            Some(DetailSearchResult::JsonPath(_)) | Some(DetailSearchResult::Jq(_))
        ));
    }

    #[rstest]
    fn invalid_regex_keeps_list() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        let original = tui.state.filtered.clone();
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        assert_eq!(tui.state.filtered, original);
        assert!(tui.state.search_error.is_some());
    }

    #[rstest]
    fn regex_search_filters() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('/'), KeyModifiers::NONE));
        for ch in "alp/".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        assert_eq!(tui.state.filtered.len(), 2);
        assert!(tui.state.search_error.is_none());
    }

    #[test]
    fn parse_regex_input_variants() {
        assert!(parse_regex_input("nope").is_none());
        assert!(matches!(parse_regex_input("/"), Some(Err(_))));
        assert!(matches!(parse_regex_input("/abc"), Some(Err(_))));
        assert!(matches!(parse_regex_input("/abc/"), Some(Ok("abc"))));
    }

    #[test]
    fn json_summary_for_object_and_array() {
        let object = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let summary = json_summary(&object);
        assert!(summary.starts_with("JSON (collapsed): keys:"));
        assert!(summary.contains('a'));

        let array = serde_json::json!([1, 2, 3]);
        assert_eq!(json_summary(&array), "JSON (collapsed): array [3]");
    }

    #[test]
    fn detail_value_decorator_split_hides_color_like_values() {
        let value = serde_json::json!(["hello", {"color": "red"}, {"a": 1}, {"label": "Foo"}]);

        let hidden = detail_value_with_decorators(value.clone(), false);
        assert_eq!(hidden, serde_json::json!(["hello", {"a": 1}]));

        let shown = detail_value_with_decorators(value, true);
        assert_eq!(
            shown,
            serde_json::json!({"content":["hello", {"a": 1}], "decorators":[{"color":"red"}, {"label":"Foo"}]})
        );
    }

    #[test]
    fn json_highlight_segments_classifies_keys_and_values() {
        let json = r#"{"foo":"bar","n":1,"b":true,"z":null,"arr":["x"],"obj":{"k":"v"}}"#;
        let segments = json_highlight_segments(json);

        let kind_for = |token: &str| {
            segments.iter().find(|(_, segment)| *segment == token).map(|(kind, _)| *kind)
        };

        assert_eq!(kind_for(r#""foo""#), Some(JsonHighlightKind::Key));
        assert_eq!(kind_for(r#""bar""#), Some(JsonHighlightKind::String));
        assert_eq!(kind_for("1"), Some(JsonHighlightKind::Number));
        assert_eq!(kind_for("true"), Some(JsonHighlightKind::Bool));
        assert_eq!(kind_for("null"), Some(JsonHighlightKind::Null));
        assert_eq!(kind_for(r#""arr""#), Some(JsonHighlightKind::Key));
        assert_eq!(kind_for(r#""x""#), Some(JsonHighlightKind::String));
        assert_eq!(kind_for(r#""obj""#), Some(JsonHighlightKind::Key));
        assert_eq!(kind_for(r#""k""#), Some(JsonHighlightKind::Key));
        assert_eq!(kind_for(r#""v""#), Some(JsonHighlightKind::String));
    }

    #[test]
    fn fuzzy_rank_items_prefers_contains() {
        let items = vec![
            PickerItem {
                label: "alpha".to_string(),
                meta: None,
                id: PickerItemId::Screen("alpha".to_string()),
                active: false,
            },
            PickerItem {
                label: "beta".to_string(),
                meta: None,
                id: PickerItemId::Screen("beta".to_string()),
                active: false,
            },
        ];
        let ranked = fuzzy_rank_items(&items, "alp");
        assert_eq!(ranked.first().copied(), Some(0));
    }

    #[test]
    fn toggle_filter_and_summary() {
        let mut set = BTreeSet::new();
        toggle_filter(&mut set, "red".to_string());
        assert!(set.contains("red"));
        toggle_filter(&mut set, "red".to_string());
        assert!(set.is_empty());

        set.insert("a".to_string());
        set.insert("b".to_string());
        set.insert("c".to_string());
        set.insert("d".to_string());
        let summary = summarize_set(&set);
        assert!(summary.contains("+1"));
    }

    #[rstest]
    fn r_enters_regex_search() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('r'), KeyModifiers::NONE));
        assert_eq!(tui.state.mode, Mode::Search);
        assert_eq!(tui.state.search.buffer, "/");
    }

    #[rstest]
    fn space_c_toggles_color_filter() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('c'), KeyModifiers::NONE));
        assert_eq!(tui.state.mode, Mode::Picker);
        assert_eq!(tui.state.picker.as_ref().map(|picker| picker.kind), Some(PickerKind::Colors));
        let picker = tui.state.picker.as_ref().expect("picker");
        assert_eq!(picker.items.len(), 7);
        assert!(picker.items.iter().any(|item| item.label == "green"));
        assert!(picker.items.iter().any(|item| item.label == "grey"));

        for _ in 0..5 {
            tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(tui.state.filters.colors.contains("blue"));
        assert_eq!(tui.state.filtered.len(), 1);
    }

    #[rstest]
    fn space_t_toggles_type_filter() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(tui.state.picker.as_ref().map(|picker| picker.kind), Some(PickerKind::Types));
        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(tui.state.filters.types.contains("exception"));
        assert_eq!(tui.state.filtered.len(), 1);
    }

    #[test]
    fn s_snaps_color_and_type_filters_to_selected_log() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);

        tui.state.filters.colors.insert("red".to_string());
        tui.state.filters.colors.insert("blue".to_string());
        tui.state.filters.types.insert("log".to_string());
        tui.state.filters.types.insert("exception".to_string());
        tui.recompute_filter();
        assert_eq!(tui.state.filtered.len(), 3);

        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(
            tui.selected_entry().map(|entry| entry.uuid.as_str()),
            Some("00000000-0000-0000-0000-000000000002")
        );

        tui.handle_key(key(KeyCode::Char('s'), KeyModifiers::NONE));
        assert_eq!(tui.state.filters.colors.len(), 1);
        assert!(tui.state.filters.colors.contains("blue"));
        assert_eq!(tui.state.filters.types.len(), 1);
        assert!(tui.state.filters.types.contains("exception"));
        assert_eq!(tui.state.filtered.len(), 1);
        assert_eq!(tui.state.selected, 0);
        assert_eq!(
            tui.selected_entry().map(|entry| entry.uuid.as_str()),
            Some("00000000-0000-0000-0000-000000000002")
        );
    }

    #[test]
    fn a_toggles_archives_and_updates_focus() {
        let (mut tui, _) = make_tui();
        assert!(!tui.state.show_archives);
        assert_eq!(tui.state.focus, FocusPane::Logs);

        tui.handle_key(key(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(tui.state.show_archives);
        assert_eq!(tui.state.focus, FocusPane::Archives);

        tui.handle_key(key(KeyCode::Char('a'), KeyModifiers::NONE));
        assert!(!tui.state.show_archives);
        assert_eq!(tui.state.focus, FocusPane::Logs);
    }

    #[rstest]
    fn space_s_selects_screen() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('s'), KeyModifiers::NONE));
        assert_eq!(tui.state.picker.as_ref().map(|picker| picker.kind), Some(PickerKind::Screens));
        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        assert_eq!(tui.state.active_screen.as_deref(), Some("main"));
        assert_eq!(tui.state.filtered.len(), 2);
    }

    #[test]
    fn g_opens_goto_and_enter_jumps_to_position() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);

        assert_eq!(tui.state.selected, 0);
        tui.handle_key(key(KeyCode::Char('g'), KeyModifiers::NONE));
        assert_eq!(tui.state.mode, Mode::Goto);
        assert_eq!(tui.state.goto.buffer, "1");

        tui.handle_key(key(KeyCode::Char('2'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(tui.state.mode, Mode::Normal);
        assert_eq!(tui.state.selected, 1);
        assert!(tui.state.goto.buffer.is_empty());
    }

    #[test]
    fn live_view_follows_tail_when_at_end() {
        let (mut tui, _) = make_tui();
        tui.push_log(LogEntry {
            id: 1,
            uuid: "00000000-0000-0000-0000-000000000101".to_string(),
            message: "first".to_string(),
            detail: "detail".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(1_000),
            entry_type: Some("log".to_string()),
            color: Some("green".to_string()),
            screen: Some("main".to_string()),
        });
        tui.push_log(LogEntry {
            id: 2,
            uuid: "00000000-0000-0000-0000-000000000102".to_string(),
            message: "second".to_string(),
            detail: "detail".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(2_000),
            entry_type: Some("log".to_string()),
            color: Some("green".to_string()),
            screen: Some("main".to_string()),
        });

        tui.state.filters.colors.insert("green".to_string());
        tui.recompute_filter();
        assert_eq!(tui.state.filtered.len(), 2);

        tui.handle_key(key(KeyCode::Char('g'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('4'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('0'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('0'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 1);

        tui.push_log(LogEntry {
            id: 3,
            uuid: "00000000-0000-0000-0000-000000000103".to_string(),
            message: "third".to_string(),
            detail: "detail".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(3_000),
            entry_type: Some("log".to_string()),
            color: Some("green".to_string()),
            screen: Some("main".to_string()),
        });

        assert_eq!(tui.state.filtered.len(), 3);
        assert_eq!(tui.state.selected, 2);
    }

    #[test]
    fn d_does_nothing_for_live_archive() {
        let (mut tui, _) = make_tui();
        tui.state.archives.push(ArchiveFile {
            name: "live".to_string(),
            count: 1,
            path: PathBuf::from("/tmp/live.jsonl"),
            live: true,
        });
        tui.state.archive_selected = 0;
        tui.state.focus = FocusPane::Archives;

        tui.handle_key(key(KeyCode::Char('d'), KeyModifiers::NONE));
        assert!(tui.state.delete_archive_confirm.is_none());
    }

    #[test]
    fn d_deletes_loaded_archive_and_returns_to_live() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        assert_eq!(tui.state.logs.len(), 3);

        let live_first_uuid = tui.state.logs.first().map(|entry| entry.uuid.clone());

        let dir = tempdir().expect("tempdir");
        let archive_path = dir.path().join("old-session.jsonl");
        let archive_entry = LogEntry {
            id: 10,
            uuid: "00000000-0000-0000-0000-000000000010".to_string(),
            message: "archived".to_string(),
            detail: "{}".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(10_000),
            entry_type: Some("log".to_string()),
            color: Some("green".to_string()),
            screen: Some("archived".to_string()),
        };
        let line = serde_json::to_string(&archive_entry).expect("serialize");
        fs::write(&archive_path, format!("{line}\n")).expect("write archive");

        tui.state.archives = vec![
            ArchiveFile {
                name: "live".to_string(),
                count: 3,
                path: dir.path().join("live.jsonl"),
                live: true,
            },
            ArchiveFile {
                name: "old-session".to_string(),
                count: 1,
                path: archive_path.clone(),
                live: false,
            },
        ];
        tui.state.archive_selected = 1;
        tui.state.focus = FocusPane::Archives;

        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(tui.viewing_archive.as_deref(), Some(archive_path.as_path()));
        assert_eq!(tui.state.logs.len(), 1);

        tui.handle_key(key(KeyCode::Char('d'), KeyModifiers::NONE));
        assert_eq!(tui.state.delete_archive_confirm.as_deref(), Some(archive_path.as_path()));
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));

        assert!(tui.state.delete_archive_confirm.is_none());
        assert!(tui.viewing_archive.is_none());
        assert_eq!(tui.state.logs.len(), 3);
        assert_eq!(tui.state.logs.first().map(|entry| &entry.uuid), live_first_uuid.as_ref());
        assert!(!archive_path.exists());
        assert!(!tui.state.archives.iter().any(|entry| entry.path == archive_path));
    }

    #[test]
    fn n_does_nothing_for_live_archive() {
        let (mut tui, _) = make_tui();
        tui.state.archives.push(ArchiveFile {
            name: "live".to_string(),
            count: 1,
            path: PathBuf::from("/tmp/live.jsonl"),
            live: true,
        });
        tui.state.archive_selected = 0;
        tui.state.focus = FocusPane::Archives;

        tui.handle_key(key(KeyCode::Char('n'), KeyModifiers::NONE));
        assert!(tui.state.rename_archive.is_none());
    }

    #[test]
    fn n_renames_loaded_archive_and_keeps_it_loaded() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);

        let dir = tempdir().expect("tempdir");
        let archive_path = dir.path().join("old-session.jsonl");
        let archive_entry = LogEntry {
            id: 10,
            uuid: "00000000-0000-0000-0000-000000000010".to_string(),
            message: "archived".to_string(),
            detail: "{}".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(10_000),
            entry_type: Some("log".to_string()),
            color: Some("green".to_string()),
            screen: Some("archived".to_string()),
        };
        let line = serde_json::to_string(&archive_entry).expect("serialize");
        fs::write(&archive_path, format!("{line}\n")).expect("write archive");

        tui.state.archives = vec![
            ArchiveFile {
                name: "live".to_string(),
                count: 3,
                path: dir.path().join("live.jsonl"),
                live: true,
            },
            ArchiveFile {
                name: "old-session".to_string(),
                count: 1,
                path: archive_path.clone(),
                live: false,
            },
        ];
        tui.state.archive_selected = 1;
        tui.state.focus = FocusPane::Archives;

        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(tui.viewing_archive.as_deref(), Some(archive_path.as_path()));
        assert_eq!(tui.state.logs.len(), 1);

        tui.handle_key(key(KeyCode::Char('n'), KeyModifiers::NONE));
        assert_eq!(
            tui.state.rename_archive.as_ref().map(|rename| rename.path.as_path()),
            Some(archive_path.as_path())
        );
        assert_eq!(
            tui.state.rename_archive.as_ref().map(|rename| rename.input.buffer.as_str()),
            Some("old-session")
        );

        for ch in "renamed".chars() {
            tui.handle_key(key(KeyCode::Char(ch), KeyModifiers::NONE));
        }
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));

        let new_path = dir.path().join("renamed.jsonl");
        assert!(!archive_path.exists());
        assert!(new_path.exists());
        assert!(tui.state.rename_archive.is_none());
        assert_eq!(tui.viewing_archive.as_deref(), Some(new_path.as_path()));
        assert_eq!(tui.state.logs.len(), 1);
        assert!(tui
            .state
            .archives
            .iter()
            .any(|entry| entry.path == new_path && entry.name == "renamed"));
        let selected_path =
            tui.state.archives.get(tui.state.archive_selected).map(|entry| entry.path.clone());
        assert_eq!(selected_path.as_deref(), Some(new_path.as_path()));
    }

    #[test]
    fn collapsed_json_does_not_change_blob_stats() {
        let (mut tui, _) = make_tui();
        tui.push_log(LogEntry {
            id: 1,
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            message: "alpha".to_string(),
            detail: "{\n  \"foo\": {\n    \"bar\": \"baz\"\n  }\n}\n".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(1_000),
            entry_type: Some("log".to_string()),
            color: Some("red".to_string()),
            screen: Some("main".to_string()),
        });

        tui.state.json_expanded = true;
        let expanded = tui.detail_cached();
        let expanded_blob = expanded.blob_stats;
        let expanded_display_lines = expanded.display_stats.lines;

        tui.state.json_expanded = false;
        let collapsed = tui.detail_cached();
        let collapsed_blob = collapsed.blob_stats;
        let collapsed_display_lines = collapsed.display_stats.lines;

        assert_eq!(expanded_blob, collapsed_blob);
        assert!(expanded_display_lines > 1);
        assert_eq!(collapsed_display_lines, 1);
    }

    #[test]
    fn live_archive_batches_flushes() {
        let dir = tempdir().expect("tempdir");
        let config =
            TuiConfig { archive_dir: Some(dir.path().to_path_buf()), ..Default::default() };

        let value = Arc::new(Mutex::new(String::new()));
        let clipboard = MockClipboard { value };
        let mut tui = Tui::with_clipboard(config, Box::new(clipboard));

        let live_path =
            tui.live_archive.as_ref().map(|live| live.path.clone()).expect("live archive");
        assert_eq!(fs::metadata(&live_path).expect("metadata").len(), 0);

        let entry = LogEntry {
            id: 1,
            uuid: "00000000-0000-0000-0000-000000000001".to_string(),
            message: "alpha".to_string(),
            detail: "{}".to_string(),
            origin: None,
            origin_file: None,
            origin_line: None,
            timestamp: Some(1_000),
            entry_type: Some("log".to_string()),
            color: Some("red".to_string()),
            screen: Some("main".to_string()),
        };

        tui.append_to_live_archive(&entry);
        assert_eq!(fs::metadata(&live_path).expect("metadata").len(), 0);

        for _ in 1..LIVE_ARCHIVE_FLUSH_EVERY_ENTRIES {
            tui.append_to_live_archive(&entry);
        }

        assert!(fs::metadata(&live_path).expect("metadata").len() > 0);
    }

    #[rstest]
    fn q_quits() {
        let (mut tui, _) = make_tui();
        let action = tui.handle_key(key(KeyCode::Char('q'), KeyModifiers::NONE));
        assert_eq!(action, Action::Quit);
    }

    #[rstest]
    fn ctrl_c_quits() {
        let (mut tui, _) = make_tui();
        let action = tui.handle_key(key(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(action, Action::Quit);
    }

    #[rstest]
    fn ctrl_l_clears_logs() {
        let (mut tui, _) = make_tui();
        let action = tui.handle_key(key(KeyCode::Char('l'), KeyModifiers::CONTROL));
        assert_eq!(action, Action::ClearLogs);
    }

    #[rstest]
    fn u_resets_search_and_filters() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.state.search.insert_str("alp");
        tui.state.active_screen = Some("main".to_string());
        tui.state.filters.colors.insert("red".to_string());
        tui.state.filters.types.insert("exception".to_string());
        tui.recompute_filter();
        assert_ne!(tui.state.filtered.len(), tui.state.logs.len());

        let action = tui.handle_key(key(KeyCode::Char('u'), KeyModifiers::NONE));
        assert_eq!(action, Action::None);
        assert!(tui.state.search.buffer.is_empty());
        assert!(tui.state.filters.colors.is_empty());
        assert!(tui.state.filters.types.is_empty());
        assert!(tui.state.active_screen.is_none());
        assert_eq!(tui.state.filtered.len(), tui.state.logs.len());
    }
}
