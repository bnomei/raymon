//! Ratatui interface for Raymon.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::env;
use std::fmt;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use memchr::{memchr, memchr2};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use rapidfuzz::fuzz;
#[cfg(feature = "rayon")]
use rayon::prelude::*;
use regex::RegexBuilder;
use serde_json::Value;
use tempfile::{NamedTempFile, TempPath};
use thiserror::Error;

/// Key handling modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    Command,
    Space,
    Picker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpMode {
    Space,
    Keymap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PickerKind {
    Logs,
    Screens,
    Archives,
    Colors,
    Types,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PickerItemId {
    Log(usize),
    Screen(String),
    Archive(usize),
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
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub id: u64,
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

/// Archived screens entry.
#[derive(Debug, Clone)]
pub struct ArchivedScreen {
    pub name: String,
    pub count: usize,
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

/// Configuration for editor/IDE integrations.
#[derive(Debug, Clone)]
pub struct TuiConfig {
    pub editor_command: Option<String>,
    pub ide_command: Option<String>,
    pub jq_command: Option<String>,
    pub show_archives_by_default: bool,
    pub max_query_len: usize,
    pub jq_timeout_ms: u64,
}

impl Default for TuiConfig {
    fn default() -> Self {
        Self {
            editor_command: env::var("VISUAL").ok().or_else(|| env::var("EDITOR").ok()),
            ide_command: env::var("RAYMON_IDE").ok(),
            jq_command: env::var("RAYMON_JQ").ok(),
            show_archives_by_default: false,
            max_query_len: 265,
            jq_timeout_ms: 10_000,
        }
    }
}

/// TUI state used for rendering and event handling.
#[derive(Debug, Clone)]
pub struct TuiState {
    pub mode: Mode,
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
    pub archives: Vec<ArchivedScreen>,
    pub archive_selected: usize,
    pub json_expanded: bool,
    pub json_raw: bool,
    pub show_timestamp: bool,
    pub show_filename: bool,
    pub show_color_indicator: bool,
    pub show_labels: bool,
    pub show_help: bool,
    pub help_mode: HelpMode,
    pub picker: Option<PickerState>,
    pub last_detail_search: Option<DetailSearchResult>,
    pub last_yank: Option<String>,
}

impl Default for TuiState {
    fn default() -> Self {
        Self {
            mode: Mode::Normal,
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
            json_expanded: false,
            json_raw: false,
            show_timestamp: false,
            show_filename: false,
            show_color_indicator: false,
            show_labels: false,
            show_help: false,
            help_mode: HelpMode::Space,
            picker: None,
            last_detail_search: None,
            last_yank: None,
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
    TextMatch,
    JsonPathMatch,
    JqMatch(String),
    NoMatch,
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

/// Main TUI container.
pub struct Tui {
    pub config: TuiConfig,
    pub state: TuiState,
    clipboard: Box<dyn Clipboard>,
    open_temp: Option<TempPath>,
}

impl Default for Tui {
    fn default() -> Self {
        Self::new(TuiConfig::default())
    }
}

impl Tui {
    pub fn new(config: TuiConfig) -> Self {
        let mut state = TuiState::default();
        state.show_archives = config.show_archives_by_default;
        Self {
            config,
            state,
            clipboard: Box::new(SystemClipboard::new()),
            open_temp: None,
        }
    }

    pub fn with_clipboard(config: TuiConfig, clipboard: Box<dyn Clipboard>) -> Self {
        let mut state = TuiState::default();
        state.show_archives = config.show_archives_by_default;
        Self {
            config,
            state,
            clipboard,
            open_temp: None,
        }
    }

    pub fn push_log(&mut self, entry: LogEntry) {
        if let Some(screen) = entry.screen.as_deref() {
            if !self.state.screens.iter().any(|name| name == screen) {
                self.state.screens.push(screen.to_string());
            }
        }
        if self.state.paused {
            self.state.queued.push(entry);
        } else {
            self.state.logs.push(entry);
            self.recompute_filter();
        }
    }

    pub fn archives_mut(&mut self) -> &mut Vec<ArchivedScreen> {
        &mut self.state.archives
    }

    pub fn selected_entry(&self) -> Option<&LogEntry> {
        let idx = *self.state.filtered.get(self.state.selected)?;
        self.state.logs.get(idx)
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Action {
        match self.state.mode {
            Mode::Normal => self.handle_normal(key),
            Mode::Search => self.handle_search(key),
            Mode::Command => self.handle_command(key),
            Mode::Space => self.handle_space(key),
            Mode::Picker => self.handle_picker(key),
        }
    }

    pub fn perform_action(&mut self, action: Action) -> Result<ActionOutcome, TuiError> {
        match action {
            Action::None => Err(TuiError::InvalidCommandLine("no action".to_string())),
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

    pub fn render(&self, frame: &mut Frame<'_>) {
        let size = frame.area();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(size);

        self.render_top_bar(frame, chunks[0]);
        self.render_main(frame, chunks[1]);

        if self.state.picker.is_some() {
            self.render_picker(frame);
        } else if self.state.show_help {
            self.render_help(frame);
        }
    }

    pub fn enter_search(&mut self) {
        self.state.mode = Mode::Search;
        self.state.detail_notice = None;
    }

    fn run_jq(&self, detail: &str, query: &str) -> Result<Option<String>, TuiError> {
        let command = self
            .config
            .jq_command
            .clone()
            .unwrap_or_else(|| "jq".to_string());
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

    fn open_log_picker(&mut self) {
        let indices = self.base_filter_indices();
        let items: Vec<PickerItem> = indices
            .iter()
            .filter_map(|idx| self.state.logs.get(*idx).map(|entry| (idx, entry)))
            .map(|(idx, entry)| PickerItem {
                label: entry.message.clone(),
                meta: entry.entry_type.clone(),
                id: PickerItemId::Log(*idx),
                active: false,
            })
            .collect();
        self.open_picker(PickerState::new(PickerKind::Logs, items, false));
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

    fn open_archive_picker(&mut self) {
        let items: Vec<PickerItem> = self
            .state
            .archives
            .iter()
            .enumerate()
            .map(|(idx, entry)| PickerItem {
                label: format!("{} ({})", entry.name, entry.count),
                meta: Some("archived".to_string()),
                id: PickerItemId::Archive(idx),
                active: self.state.archive_selected == idx,
            })
            .collect();
        self.open_picker(PickerState::new(PickerKind::Archives, items, false));
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
                if self.state.active_screen.as_deref().is_some_and(|screen| {
                    entry.screen.as_deref() != Some(screen)
                }) {
                    continue;
                }
                types.insert(normalize_label(value));
            }
        }
        types.into_iter().collect()
    }

    fn available_colors(&self) -> Vec<String> {
        let mut colors = BTreeSet::new();
        for entry in &self.state.logs {
            if let Some(value) = entry.color.as_deref() {
                if self.state.active_screen.as_deref().is_some_and(|screen| {
                    entry.screen.as_deref() != Some(screen)
                }) {
                    continue;
                }
                colors.insert(normalize_label(value));
            }
        }
        colors.into_iter().collect()
    }

    fn select_log_index(&mut self, log_index: usize) {
        if let Some(pos) = self.state.filtered.iter().position(|idx| *idx == log_index) {
            self.state.selected = pos;
            return;
        }
        self.state.search.clear();
        self.state.search_error = None;
        self.recompute_filter();
        if let Some(pos) = self.state.filtered.iter().position(|idx| *idx == log_index) {
            self.state.selected = pos;
        }
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
            _ => {}
        }
    }

    pub fn search_detail(&mut self, query: &str) -> DetailSearchResult {
        self.state.detail_notice = None;
        let detail = match self.selected_entry() {
            Some(entry) => &entry.detail,
            None => {
                self.state.last_detail_search = Some(DetailSearchResult::NoMatch);
                return DetailSearchResult::NoMatch;
            }
        };

        if detail.contains(query) {
            self.state.last_detail_search = Some(DetailSearchResult::TextMatch);
            return DetailSearchResult::TextMatch;
        }

        let parsed: Value = match serde_json::from_str(detail) {
            Ok(value) => value,
            Err(_) => {
                self.state.last_detail_search = Some(DetailSearchResult::NoMatch);
                return DetailSearchResult::NoMatch;
            }
        };

        if let Some(_) = json_path_match(&parsed, query) {
            self.state.last_detail_search = Some(DetailSearchResult::JsonPathMatch);
            return DetailSearchResult::JsonPathMatch;
        }

        match self.run_jq(detail, query) {
            Ok(Some(result)) => {
                let outcome = DetailSearchResult::JqMatch(result);
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

        self.state.last_detail_search = Some(DetailSearchResult::NoMatch);
        DetailSearchResult::NoMatch
    }

    fn handle_normal(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent {
                code: KeyCode::Char('j'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.move_selection(1);
                Action::None
            }
            KeyEvent {
                code: KeyCode::Down,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.move_selection(1);
                Action::None
            }
            KeyEvent {
                code: KeyCode::Up,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.move_selection(-1);
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('k'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.clear_screen();
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('/'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.mode = Mode::Search;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('f'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.mode = Mode::Search;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char(':'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.enter_command();
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('p'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.toggle_pause();
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('z'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.json_expanded = !self.state.json_expanded;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('Z'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.json_raw = !self.state.json_raw;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('y'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                let _ = self.yank_selected(YankKind::Message);
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('Y'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                let _ = self.yank_selected(YankKind::Detail);
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('e'),
                modifiers: KeyModifiers::NONE,
                ..
            } => Action::OpenEditor,
            KeyEvent {
                code: KeyCode::Char('o'),
                modifiers: KeyModifiers::NONE,
                ..
            } => Action::OpenOrigin,
            KeyEvent {
                code: KeyCode::Char('a'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.show_archives = !self.state.show_archives;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('1'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.show_timestamp = !self.state.show_timestamp;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('2'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.show_filename = !self.state.show_filename;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('3'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.show_color_indicator = !self.state.show_color_indicator;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('4'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.show_labels = !self.state.show_labels;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char(' '),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.mode = Mode::Space;
                self.state.show_help = true;
                self.state.help_mode = HelpMode::Space;
                Action::None
            }
            _ => Action::None,
        }
    }

    fn handle_search(&mut self, key: KeyEvent) -> Action {
        match key {
            KeyEvent {
                code: KeyCode::Esc,
                ..
            }
            | KeyEvent {
                code: KeyCode::Enter,
                ..
            } => {
                self.state.mode = Mode::Normal;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Backspace,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.search.backspace();
                self.recompute_filter();
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('y'),
                modifiers,
                ..
            } if modifiers.contains(KeyModifiers::CONTROL) => {
                let _ = self.paste_into_input(InputTarget::Search);
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
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
            KeyEvent {
                code: KeyCode::Esc,
                ..
            } => {
                self.state.mode = Mode::Normal;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Enter,
                ..
            } => {
                let query = self.state.command.buffer.trim().to_string();
                if !query.is_empty() {
                    let _ = self.search_detail(&query);
                }
                self.state.mode = Mode::Normal;
                Action::None
            }
            KeyEvent {
                code: KeyCode::Backspace,
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.command.backspace();
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char('y'),
                modifiers,
                ..
            } if modifiers.contains(KeyModifiers::CONTROL) => {
                let _ = self.paste_into_input(InputTarget::Command);
                Action::None
            }
            KeyEvent {
                code: KeyCode::Char(c),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
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
                KeyEvent {
                    code: KeyCode::Esc,
                    ..
                }
                | KeyEvent {
                    code: KeyCode::Char('q'),
                    modifiers: KeyModifiers::NONE,
                    ..
                } => {
                    action = PickerAction::Close;
                }
                KeyEvent {
                    code: KeyCode::Enter,
                    ..
                } => {
                    if let Some(item) = picker.selected_item() {
                        if picker.multi_select {
                            action = PickerAction::Toggle(item.id.clone());
                        } else {
                            action = PickerAction::Select(item.id.clone());
                        }
                    }
                }
                KeyEvent {
                    code: KeyCode::Char('j'),
                    modifiers: KeyModifiers::NONE,
                    ..
                }
                | KeyEvent {
                    code: KeyCode::Down,
                    ..
                } => {
                    picker.move_selection(1);
                }
                KeyEvent {
                    code: KeyCode::Char('k'),
                    modifiers: KeyModifiers::NONE,
                    ..
                }
                | KeyEvent {
                    code: KeyCode::Up,
                    ..
                } => {
                    picker.move_selection(-1);
                }
                KeyEvent {
                    code: KeyCode::Backspace,
                    modifiers: KeyModifiers::NONE,
                    ..
                } => {
                    picker.query.backspace();
                    picker.recompute();
                }
                KeyEvent {
                    code: KeyCode::Char('y'),
                    modifiers,
                    ..
                } if modifiers.contains(KeyModifiers::CONTROL) => {
                    action = PickerAction::Paste;
                }
                KeyEvent {
                    code: KeyCode::Char(c),
                    modifiers: KeyModifiers::NONE,
                    ..
                } => {
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
        let mut exit = true;
        match key {
            KeyEvent {
                code: KeyCode::Char('?'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.show_help = true;
                self.state.help_mode = HelpMode::Keymap;
                exit = false;
            }
            KeyEvent {
                code: KeyCode::Char('f'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.open_log_picker();
            }
            KeyEvent {
                code: KeyCode::Char('c'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.open_color_picker();
            }
            KeyEvent {
                code: KeyCode::Char('s'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.open_screen_picker();
            }
            KeyEvent {
                code: KeyCode::Char('r'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.state.mode = Mode::Search;
                self.state.search.clear();
                self.state.search.insert_str("/");
                self.recompute_filter();
                self.state.show_help = false;
            }
            KeyEvent {
                code: KeyCode::Char('t'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.open_type_picker();
            }
            KeyEvent {
                code: KeyCode::Char('j'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.enter_command();
                self.state.show_help = false;
            }
            KeyEvent {
                code: KeyCode::Char('a'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                self.open_archive_picker();
            }
            KeyEvent {
                code: KeyCode::Char('q'),
                modifiers: KeyModifiers::NONE,
                ..
            } => {
                return Action::Quit;
            }
            _ => {}
        }

        if exit && self.state.mode == Mode::Space {
            self.state.mode = Mode::Normal;
            self.state.show_help = false;
        }
        Action::None
    }

    fn toggle_pause(&mut self) {
        self.state.paused = !self.state.paused;
        if !self.state.paused && !self.state.queued.is_empty() {
            self.state.logs.append(&mut self.state.queued);
            self.recompute_filter();
        }
    }

    fn recompute_filter(&mut self) {
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
                Ok(pattern) => match RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                {
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
        self.state.last_detail_search = None;
        self.state.detail_notice = None;
    }

    fn clear_screen(&mut self) {
        let screen = self.state.active_screen.clone();
        self.clear_screen_for(screen.as_deref());
    }

    pub fn clear_screen_for(&mut self, screen: Option<&str>) {
        let mut removed = 0usize;
        match screen {
            Some(screen_name) => {
                self.state.logs.retain(|entry| {
                    let matches = entry.screen.as_deref() == Some(screen_name);
                    if matches {
                        removed += 1;
                    }
                    !matches
                });
                self.state.queued.retain(|entry| entry.screen.as_deref() != Some(screen_name));
            }
            None => {
                removed = self.state.logs.len();
                self.state.logs.clear();
                self.state.queued.clear();
            }
        }

        if removed > 0 {
            let name = screen.unwrap_or("all").to_string();
            self.state.archives.push(ArchivedScreen { name, count: removed });
            self.state.archive_selected = self.state.archives.len().saturating_sub(1);
            self.state.show_archives = true;
        }

        self.state.filtered.clear();
        self.state.selected = 0;
        self.state.last_detail_search = None;
        self.state.detail_notice = None;
        self.recompute_filter();
    }

    fn apply_filter(&mut self, filtered: Vec<usize>) {
        self.state.filtered = filtered;
        if self.state.filtered.is_empty() {
            self.state.selected = 0;
        } else if self.state.selected >= self.state.filtered.len() {
            self.state.selected = self.state.filtered.len() - 1;
        }
    }

    fn base_filter_indices(&self) -> Vec<usize> {
        self.state
            .logs
            .iter()
            .enumerate()
            .filter_map(|(idx, entry)| {
                if self.entry_matches_filters(entry) {
                    Some(idx)
                } else {
                    None
                }
            })
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
        let entry = self.selected_entry().ok_or(TuiError::NoSelection)?;
        let contents = match kind {
            YankKind::Message => entry.message.clone(),
            YankKind::Detail => entry.detail.clone(),
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
            PickerItemId::Log(idx) => {
                self.select_log_index(idx);
            }
            PickerItemId::Screen(name) => {
                self.state.active_screen = Some(name);
                self.recompute_filter();
            }
            PickerItemId::ClearScreens => {
                self.state.active_screen = None;
                self.recompute_filter();
            }
            PickerItemId::Archive(idx) => {
                self.state.archive_selected = idx;
                self.state.show_archives = true;
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

    fn open_in_editor(&mut self) -> Result<PathBuf, TuiError> {
        let entry = self.selected_entry().ok_or(TuiError::NoSelection)?;
        let mut temp = NamedTempFile::new()?;
        temp.write_all(entry.detail.as_bytes())?;
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
        let status = if self.state.paused { "Paused" } else { "Live" };
        let mode = format!("{:?}", self.state.mode);
        let input = match self.state.mode {
            Mode::Search => {
                if self.state.search.buffer.starts_with('/') {
                    self.state.search.buffer.clone()
                } else {
                    format!("/{}", self.state.search.buffer)
                }
            }
            Mode::Command => format!(":{}", self.state.command.buffer),
            _ => format!("Search: {}", self.state.search.buffer),
        };
        let mut spans = vec![
            Span::styled(format!(" {} ", status), Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(format!(" Mode: {} ", mode)),
            Span::raw(input),
        ];
        if let Some(summary) = self.filters_summary() {
            spans.push(Span::raw(format!(" Filters: {}", summary)));
        }
        if let Some(error) = &self.state.search_error {
            spans.push(Span::styled(
                format!(" Error: {}", error),
                Style::default().fg(Color::Red),
            ));
        }
        if let Some(notice) = &self.state.detail_notice {
            spans.push(Span::styled(
                format!(" Notice: {}", notice),
                Style::default().fg(Color::Yellow),
            ));
        }
        let line = Line::from(spans);

        let block = Block::default().borders(Borders::ALL).title("Raymon");
        let paragraph = Paragraph::new(line).block(block).alignment(Alignment::Left);
        frame.render_widget(paragraph, area);
    }

    fn render_main(&self, frame: &mut Frame<'_>, area: Rect) {
        let columns = if self.state.show_archives {
            vec![
                Constraint::Percentage(30),
                Constraint::Percentage(50),
                Constraint::Percentage(20),
            ]
        } else {
            vec![Constraint::Percentage(35), Constraint::Percentage(65)]
        };
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(columns)
            .split(area);

        self.render_logs(frame, chunks[0]);
        self.render_detail(frame, chunks[1]);

        if self.state.show_archives {
            self.render_archives(frame, chunks[2]);
        }
    }

    fn render_logs(&self, frame: &mut Frame<'_>, area: Rect) {
        let items: Vec<ListItem> = self
            .state
            .filtered
            .iter()
            .filter_map(|idx| self.state.logs.get(*idx))
            .map(|entry| ListItem::new(self.format_log_line(entry)))
            .collect();
        let mut state = ListState::default();
        if !self.state.filtered.is_empty() {
            state.select(Some(self.state.selected));
        }
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Logs"))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn format_log_line(&self, entry: &LogEntry) -> Line<'_> {
        let mut spans = Vec::new();
        if self.state.show_timestamp {
            if let Some(ts) = entry.timestamp {
                spans.push(Span::raw(format!("[{}] ", ts)));
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
        if self.state.show_labels {
            if let Some(label) = entry.entry_type.as_deref() {
                spans.push(Span::raw(format!("[{}] ", label)));
            }
        }
        if self.state.show_color_indicator {
            if let Some(color_name) = entry.color.as_deref() {
                if let Some(color) = color_from_name(color_name) {
                    spans.push(Span::styled("o ", Style::default().fg(color)));
                }
            }
        }
        spans.push(Span::raw(entry.message.clone()));
        Line::from(spans)
    }

    fn render_detail(&self, frame: &mut Frame<'_>, area: Rect) {
        let text = self.detail_text();
        let block = Block::default().borders(Borders::ALL).title("Detail");
        let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
        frame.render_widget(paragraph, area);
    }

    fn render_archives(&self, frame: &mut Frame<'_>, area: Rect) {
        let items: Vec<ListItem> = self
            .state
            .archives
            .iter()
            .map(|entry| ListItem::new(format!("{} ({})", entry.name, entry.count)))
            .collect();
        let mut state = ListState::default();
        if !self.state.archives.is_empty() {
            state.select(Some(self.state.archive_selected.min(self.state.archives.len() - 1)));
        }
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Archives"))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn render_help(&self, frame: &mut Frame<'_>) {
        let area = centered_rect(60, 50, frame.area());
        frame.render_widget(Clear, area);
        let text = match self.state.help_mode {
            HelpMode::Space => vec![
                Line::from("Space modal"),
                Line::from("f logs picker  r regex search  s screens picker"),
                Line::from("c color filters  t type filters  j jq detail search"),
                Line::from("a archives picker  q quit  ? keymap help  Esc close"),
            ],
            HelpMode::Keymap => vec![
                Line::from("Normal: j/down move, up move, / or f search, : detail search, p pause"),
                Line::from("k clear screen, z expand JSON, Z raw JSON, y/Y yank, Ctrl+y paste"),
                Line::from("1 ts 2 file 3 color 4 labels, a archives, e editor, o origin"),
                Line::from("Space: f logs, r regex, s screens, c colors, t types, j jq, a archives"),
            ],
        };
        let title = match self.state.help_mode {
            HelpMode::Space => "Space",
            HelpMode::Keymap => "Keymap",
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let paragraph = Paragraph::new(text)
            .block(block)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true });
        frame.render_widget(paragraph, area);
    }

    fn render_picker(&self, frame: &mut Frame<'_>) {
        let Some(picker) = &self.state.picker else {
            return;
        };
        let area = centered_rect(70, 60, frame.area());
        frame.render_widget(Clear, area);

        let title = match picker.kind {
            PickerKind::Logs => "Logs",
            PickerKind::Screens => "Screens",
            PickerKind::Archives => "Archived Screens",
            PickerKind::Colors => "Color Filters",
            PickerKind::Types => "Type Filters",
        };
        let block = Block::default().borders(Borders::ALL).title(title);
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
        let header = Paragraph::new(format!("{}: {}", prompt, picker.query.buffer))
            .alignment(Alignment::Left);
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
                    spans.push(Span::raw(item.label.clone()));
                    if let Some(meta) = &item.meta {
                        spans.push(Span::styled(
                            format!(" {}", meta),
                            Style::default().fg(Color::DarkGray),
                        ));
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
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol(">> ");
        frame.render_stateful_widget(list, chunks[1], &mut state);

        let footer_text = if picker.multi_select {
            "Enter: toggle  Esc: close"
        } else {
            "Enter: select  Esc: close"
        };
        let footer = Paragraph::new(footer_text)
            .alignment(Alignment::Left)
            .wrap(Wrap { trim: true });
        frame.render_widget(footer, chunks[2]);
    }

    fn detail_text(&self) -> String {
        let Some(entry) = self.selected_entry() else {
            return "No selection.".to_string();
        };
        if let Some(DetailSearchResult::JqMatch(result)) = &self.state.last_detail_search {
            return result.clone();
        }
        if let Ok(value) = serde_json::from_str::<Value>(&entry.detail) {
            if self.state.json_expanded {
                if self.state.json_raw {
                    entry.detail.clone()
                } else {
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| entry.detail.clone())
                }
            } else {
                json_summary(&value)
            }
        } else {
            entry.detail.clone()
        }
    }

    fn filters_summary(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(screen) = &self.state.active_screen {
            parts.push(format!("screen={}", screen));
        }
        if !self.state.filters.types.is_empty() {
            parts.push(format!(
                "type={}",
                summarize_set(&self.state.filters.types)
            ));
        }
        if !self.state.filters.colors.is_empty() {
            parts.push(format!(
                "color={}",
                summarize_set(&self.state.filters.colors)
            ));
        }
        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" | "))
        }
    }

    fn regex_filter(&self, indices: &[usize], regex: &regex::Regex) -> Vec<usize> {
        indices
            .iter()
            .copied()
            .filter(|idx| {
                self.state
                    .logs
                    .get(*idx)
                    .is_some_and(|entry| regex.is_match(&entry.message))
            })
            .collect()
    }

    fn fuzzy_filter(&self, indices: &[usize], query: &str) -> Vec<usize> {
        let query_lower = query.to_lowercase();
        let threshold = if query_lower.len() <= 2 { 0.2 } else { 0.35 };
        #[cfg(feature = "rayon")]
        let use_parallel = indices.len() >= 200;
        let candidates: Vec<(usize, String)> = indices
            .iter()
            .filter_map(|idx| {
                self.state
                    .logs
                    .get(*idx)
                    .map(|entry| (*idx, entry.message.to_lowercase()))
            })
            .collect();

        let score_entry = |(idx, message_lower): &(usize, String)| -> Option<(usize, f64)> {
            if message_lower.contains(&query_lower) {
                return Some((*idx, 1.0));
            }
            let score = fuzz::ratio(query_lower.chars(), message_lower.chars());
            if score >= threshold {
                Some((*idx, score))
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
            b.1.partial_cmp(&a.1)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
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

fn json_summary(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let keys: Vec<&String> = map.keys().collect();
            if keys.is_empty() {
                "JSON (empty object)".to_string()
            } else {
                let list = keys
                    .iter()
                    .take(6)
                    .map(|key| key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("JSON (collapsed): keys: {}", list)
            }
        }
        Value::Array(values) => format!("JSON (collapsed): array [{}]", values.len()),
        _ => "JSON (collapsed)".to_string(),
    }
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

fn color_from_name(value: &str) -> Option<Color> {
    match value.trim().to_ascii_lowercase().as_str() {
        "red" => Some(Color::Red),
        "green" => Some(Color::Green),
        "blue" => Some(Color::Blue),
        "yellow" => Some(Color::Yellow),
        "orange" => Some(Color::Yellow),
        "purple" | "magenta" => Some(Color::Magenta),
        "cyan" => Some(Color::Cyan),
        "white" => Some(Color::White),
        "gray" | "grey" => Some(Color::Gray),
        _ => None,
    }
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
        if candidate
            .iter()
            .zip(needle_lower.iter())
            .all(|(&h, &n)| h.to_ascii_lowercase() == n)
        {
            return true;
        }

        base = start + 1;
        search = &haystack[base..];
    }

    false
}

pub(crate) fn fuzzy_rank_items(items: &[PickerItem], query: &str) -> Vec<usize> {
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
        b.1.partial_cmp(&a.1)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.0.cmp(&b.0))
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

fn launch_command(command: &str, arg: impl AsRef<Path>) -> Result<(), TuiError> {
    let parts = shlex::split(command).ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
    let (program, args) = parts
        .split_first()
        .ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
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
        return Err(TuiError::InvalidCommandLine(format!(
            "command failed: {}",
            command
        )));
    }
    Ok(())
}

fn run_jq_command(
    command: &str,
    detail: &str,
    query: &str,
    timeout: Duration,
) -> Result<Option<String>, TuiError> {
    let parts = shlex::split(command).ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
    let (program, args) = parts
        .split_first()
        .ok_or_else(|| TuiError::InvalidCommandLine(command.into()))?;
    let mut stdout_file = NamedTempFile::new()?;
    let mut stderr_file = NamedTempFile::new()?;
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
            Err(TuiError::JqFailed(
                String::from_utf8_lossy(&stderr_bytes).to_string(),
            ))
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
    Some(current.to_string())
}

impl fmt::Debug for Tui {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tui")
            .field("config", &self.config)
            .field("state", &self.state)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use rstest::rstest;
    use std::sync::{Arc, Mutex};

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
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn make_tui() -> (Tui, Arc<Mutex<String>>) {
        let value = Arc::new(Mutex::new(String::new()));
        let clipboard = MockClipboard {
            value: value.clone(),
        };
        let tui = Tui::with_clipboard(TuiConfig::default(), Box::new(clipboard));
        (tui, value)
    }

    fn seed_logs(tui: &mut Tui) {
        tui.push_log(LogEntry {
            id: 1,
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
        tui.handle_key(key(KeyCode::Up, KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 0);
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
    fn pause_queues_then_flushes() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char('p'), KeyModifiers::NONE));
        assert!(tui.state.paused);
        tui.push_log(LogEntry {
            id: 4,
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
    fn space_help_toggle() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        assert_eq!(tui.state.mode, Mode::Space);
        assert!(tui.state.show_help);
        assert_eq!(tui.state.help_mode, HelpMode::Space);
        tui.handle_key(key(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(tui.state.show_help);
        assert_eq!(tui.state.help_mode, HelpMode::Keymap);
        assert_eq!(tui.state.mode, Mode::Space);
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
            Some(DetailSearchResult::JsonPathMatch) | Some(DetailSearchResult::JqMatch(_))
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
        assert!(matches!(parse_regex_input("nope"), None));
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
    fn fuzzy_rank_items_prefers_contains() {
        let items = vec![
            PickerItem {
                label: "alpha".to_string(),
                meta: None,
                id: PickerItemId::Log(0),
                active: false,
            },
            PickerItem {
                label: "beta".to_string(),
                meta: None,
                id: PickerItemId::Log(1),
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
    fn space_r_enters_regex_search() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
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
        assert_eq!(
            tui.state.picker.as_ref().map(|picker| picker.kind),
            Some(PickerKind::Colors)
        );
        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert!(tui.state.filters.colors.contains("blue"));
        assert_eq!(tui.state.filtered.len(), 1);
    }

    #[rstest]
    fn space_t_toggles_type_filter() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(
            tui.state.picker.as_ref().map(|picker| picker.kind),
            Some(PickerKind::Types)
        );
        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert!(tui.state.filters.types.contains("exception"));
        assert_eq!(tui.state.filtered.len(), 1);
    }

    #[rstest]
    fn space_s_selects_screen() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('s'), KeyModifiers::NONE));
        assert_eq!(
            tui.state.picker.as_ref().map(|picker| picker.kind),
            Some(PickerKind::Screens)
        );
        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(tui.state.active_screen.as_deref(), Some("main"));
        assert_eq!(tui.state.filtered.len(), 2);
    }

    #[rstest]
    fn space_f_selects_log() {
        let (mut tui, _) = make_tui();
        seed_logs(&mut tui);
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('f'), KeyModifiers::NONE));
        assert_eq!(
            tui.state.picker.as_ref().map(|picker| picker.kind),
            Some(PickerKind::Logs)
        );
        tui.handle_key(key(KeyCode::Char('j'), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert_eq!(tui.state.selected, 1);
    }

    #[rstest]
    fn space_a_selects_archive() {
        let (mut tui, _) = make_tui();
        tui.state.archives.push(ArchivedScreen {
            name: "old-session".to_string(),
            count: 3,
        });
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        tui.handle_key(key(KeyCode::Char('a'), KeyModifiers::NONE));
        assert_eq!(
            tui.state.picker.as_ref().map(|picker| picker.kind),
            Some(PickerKind::Archives)
        );
        tui.handle_key(key(KeyCode::Enter, KeyModifiers::NONE));
        assert!(tui.state.show_archives);
        assert_eq!(tui.state.archive_selected, 0);
    }

    #[rstest]
    fn space_q_quits() {
        let (mut tui, _) = make_tui();
        tui.handle_key(key(KeyCode::Char(' '), KeyModifiers::NONE));
        let action = tui.handle_key(key(KeyCode::Char('q'), KeyModifiers::NONE));
        assert_eq!(action, Action::Quit);
    }
}
