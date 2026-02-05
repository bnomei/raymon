use std::{
    collections::{BTreeMap, HashSet},
    env,
    hash::{Hash, Hasher},
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use crate::raymon_core::{
    Entry as CoreEntry, Event as CoreEvent, EventBus as CoreEventBusTrait, Filters, RayEnvelope,
    RayMeta, RayOrigin, RayPayload, Screen, StateStore as CoreStateStoreTrait,
};
use crate::colors::canonical_color_name;
use crate::raymon_ingest::Ingestor;
use crate::raymon_mcp::{RaymonMcp, RaymonMcpService};
use crate::raymon_storage::{
    EntryInput,
    EntryPayload as StoragePayload,
    Storage as RaymonStorage,
    StoredEntry,
    StoredPayload,
    ENTRIES_FILE,
};
use crate::raymon_tui::{Action, LogEntry, Tui, TuiConfig, TuiPalette};
use axum::{
    body::{Body, Bytes},
    extract::DefaultBodyLimit,
    extract::Request as AxumRequest,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use clap::Parser;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, layout::Rect, Terminal};
use serde::Deserialize;
use serde_json::Value;
use tokio::{
    sync::{broadcast, watch},
    time,
};
use tower::ServiceExt;
use tracing::{info, warn};
use uuid::Uuid;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 7777;
const DEFAULT_TUI_ENABLED: bool = true;
const SUMMARY_LIMIT: usize = 160;
const TUI_TICK_MS: u64 = 50;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_QUERY_LEN: usize = 265;
const DEFAULT_JQ_TIMEOUT_MS: u64 = 10_000;

pub type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
enum UiEvent {
    Log(LogEntry),
    ClearScreen(String),
    ClearAll,
    Quit,
}

#[derive(Parser, Debug)]
#[command(name = "raymon", version, about = "Raymon CLI")]
struct Cli {
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    ide: Option<String>,
    #[arg(long)]
    editor: Option<String>,
    #[arg(long)]
    jq: Option<String>,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    tui: bool,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    no_tui: bool,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    demo: bool,
}

#[derive(Debug, Clone)]
struct Config {
    enabled: bool,
    host: String,
    port: u16,
    ide: Option<String>,
    editor: Option<String>,
    jq: Option<String>,
    tui_enabled: bool,
    max_body_bytes: usize,
    max_query_len: usize,
    jq_timeout_ms: u64,
    allow_remote: bool,
    auth_token: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct PartialConfig {
    enabled: Option<bool>,
    host: Option<String>,
    port: Option<u16>,
    ide: Option<String>,
    editor: Option<String>,
    jq: Option<String>,
    tui_enabled: Option<bool>,
    max_body_bytes: Option<usize>,
    max_query_len: Option<usize>,
    jq_timeout_ms: Option<u64>,
    allow_remote: Option<bool>,
    auth_token: Option<String>,
}

impl PartialConfig {
    fn merge(&mut self, other: PartialConfig) {
        if other.enabled.is_some() {
            self.enabled = other.enabled;
        }
        if other.host.is_some() {
            self.host = other.host;
        }
        if other.port.is_some() {
            self.port = other.port;
        }
        if other.ide.is_some() {
            self.ide = other.ide;
        }
        if other.editor.is_some() {
            self.editor = other.editor;
        }
        if other.jq.is_some() {
            self.jq = other.jq;
        }
        if other.tui_enabled.is_some() {
            self.tui_enabled = other.tui_enabled;
        }
        if other.max_body_bytes.is_some() {
            self.max_body_bytes = other.max_body_bytes;
        }
        if other.max_query_len.is_some() {
            self.max_query_len = other.max_query_len;
        }
        if other.jq_timeout_ms.is_some() {
            self.jq_timeout_ms = other.jq_timeout_ms;
        }
        if other.allow_remote.is_some() {
            self.allow_remote = other.allow_remote;
        }
        if other.auth_token.is_some() {
            self.auth_token = other.auth_token;
        }
    }
}

impl Config {
    fn from_partial(partial: PartialConfig) -> Self {
        Self {
            enabled: partial.enabled.unwrap_or(true),
            host: partial.host.unwrap_or_else(|| DEFAULT_HOST.to_string()),
            port: partial.port.unwrap_or(DEFAULT_PORT),
            ide: partial.ide,
            editor: partial.editor,
            jq: partial.jq,
            tui_enabled: partial.tui_enabled.unwrap_or(DEFAULT_TUI_ENABLED),
            max_body_bytes: partial.max_body_bytes.unwrap_or(DEFAULT_MAX_BODY_BYTES),
            max_query_len: partial.max_query_len.unwrap_or(DEFAULT_MAX_QUERY_LEN),
            jq_timeout_ms: partial.jq_timeout_ms.unwrap_or(DEFAULT_JQ_TIMEOUT_MS),
            allow_remote: partial.allow_remote.unwrap_or(false),
            auth_token: partial.auth_token,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct FileConfig {
    enabled: Option<bool>,
    host: Option<String>,
    port: Option<u16>,
    ide: Option<String>,
    editor: Option<String>,
    jq: Option<String>,
    tui: Option<bool>,
    #[serde(alias = "noTui", alias = "no-tui")]
    no_tui: Option<bool>,
    max_body_bytes: Option<usize>,
    max_query_len: Option<usize>,
    jq_timeout_ms: Option<u64>,
    allow_remote: Option<bool>,
    auth_token: Option<String>,
}

impl FileConfig {
    fn into_partial(self) -> PartialConfig {
        let tui_enabled = match (self.tui, self.no_tui) {
            (_, Some(no_tui)) => Some(!no_tui),
            (Some(tui), None) => Some(tui),
            (None, None) => None,
        };

        PartialConfig {
            enabled: self.enabled,
            host: self.host,
            port: self.port,
            ide: self.ide,
            editor: self.editor,
            jq: self.jq,
            tui_enabled,
            max_body_bytes: self.max_body_bytes,
            max_query_len: self.max_query_len,
            jq_timeout_ms: self.jq_timeout_ms,
            allow_remote: self.allow_remote,
            auth_token: self.auth_token,
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile { path: PathBuf, source: std::io::Error },
    #[error("failed to parse config file {path}: {source}")]
    ParseFile { path: PathBuf, source: serde_json::Error },
    #[error("config file not found: {path}")]
    MissingConfig { path: PathBuf },
    #[error("invalid value for {name}: {value}")]
    InvalidEnv { name: String, value: String },
}

#[derive(Clone)]
struct AppState {
    core: CoreState,
    storage: StorageHandle,
    bus: CoreBus,
}

#[derive(Clone)]
struct RouterState {
    app: AppState,
    mcp: RaymonMcpService<CoreState, CoreBus>,
}

type IngestorHandle = Ingestor<IngestState, StorageHandle, IngestBus, fn() -> u64>;

impl AppState {
    fn ingestor(&self) -> IngestorHandle {
        Ingestor::new(
            IngestState { core: self.core.clone() },
            self.storage.clone(),
            IngestBus { bus: self.bus.clone() },
            crate::raymon_ingest::now_millis,
        )
    }
}

#[derive(Clone, Default)]
struct CoreState {
    inner: Arc<RwLock<StateInner>>,
}

#[derive(Default)]
struct StateInner {
    entries: Vec<CoreEntry>,
}

#[derive(Debug, thiserror::Error)]
enum StateError {
    #[error("state lock poisoned")]
    Poisoned,
    #[error("filter error: {0}")]
    Filter(String),
}

impl CoreState {
    fn insert(&self, entry: CoreEntry) -> Result<(), StateError> {
        let mut inner = self.inner.write().map_err(|_| StateError::Poisoned)?;
        inner.entries.push(entry);
        Ok(())
    }

    fn update(&self, entry: CoreEntry) -> Result<(), StateError> {
        let mut inner = self.inner.write().map_err(|_| StateError::Poisoned)?;
        if let Some(existing) =
            inner.entries.iter_mut().find(|existing| existing.uuid == entry.uuid)
        {
            *existing = entry;
        } else {
            inner.entries.push(entry);
        }
        Ok(())
    }

    fn get(&self, uuid: &str) -> Result<Option<CoreEntry>, StateError> {
        let inner = self.inner.read().map_err(|_| StateError::Poisoned)?;
        Ok(inner.entries.iter().find(|entry| entry.uuid == uuid).cloned())
    }

    fn list(&self, filters: &Filters) -> Result<Vec<CoreEntry>, StateError> {
        let inner = self.inner.read().map_err(|_| StateError::Poisoned)?;
        let matches = filters
            .apply(inner.entries.iter())
            .map_err(|error| StateError::Filter(error.to_string()))?;
        Ok(matches.into_iter().cloned().collect())
    }

    fn list_screens(&self) -> Result<Vec<Screen>, StateError> {
        let inner = self.inner.read().map_err(|_| StateError::Poisoned)?;
        let mut unique = HashSet::new();
        for entry in &inner.entries {
            unique.insert(entry.screen.clone());
        }
        Ok(unique.into_iter().collect())
    }

    fn clear_screen(&self, screen: &Screen) -> Result<(), StateError> {
        let mut inner = self.inner.write().map_err(|_| StateError::Poisoned)?;
        inner.entries.retain(|entry| &entry.screen != screen);
        Ok(())
    }

    fn clear_all(&self) -> Result<(), StateError> {
        let mut inner = self.inner.write().map_err(|_| StateError::Poisoned)?;
        inner.entries.clear();
        Ok(())
    }
}

impl CoreStateStoreTrait for CoreState {
    type Error = StateError;

    fn insert_entry(&mut self, entry: CoreEntry) -> Result<(), Self::Error> {
        self.insert(entry)
    }

    fn update_entry(&mut self, entry: CoreEntry) -> Result<(), Self::Error> {
        self.update(entry)
    }

    fn get_entry(&self, uuid: &str) -> Result<Option<CoreEntry>, Self::Error> {
        self.get(uuid)
    }

    fn list_entries(&self, filters: &Filters) -> Result<Vec<CoreEntry>, Self::Error> {
        self.list(filters)
    }

    fn list_screens(&self) -> Result<Vec<Screen>, Self::Error> {
        self.list_screens()
    }

    fn clear_screen(&mut self, screen: &Screen) -> Result<(), Self::Error> {
        CoreState::clear_screen(self, screen)
    }

    fn clear_all(&mut self) -> Result<(), Self::Error> {
        CoreState::clear_all(self)
    }
}

#[derive(Clone)]
struct CoreBus {
    sender: broadcast::Sender<CoreEvent>,
}

impl CoreBus {
    fn new() -> Self {
        let (sender, _) = broadcast::channel(128);
        Self { sender }
    }
}

impl CoreEventBusTrait for CoreBus {
    type Error = String;
    type Subscription = broadcast::Receiver<CoreEvent>;

    fn emit(&self, event: CoreEvent) -> Result<(), Self::Error> {
        let _ = self.sender.send(event);
        Ok(())
    }

    fn subscribe(&self) -> Result<Self::Subscription, Self::Error> {
        Ok(self.sender.subscribe())
    }
}

#[derive(Clone)]
struct StorageHandle {
    inner: Arc<Mutex<RaymonStorage>>,
}

impl StorageHandle {
    fn new(storage: RaymonStorage) -> Self {
        Self { inner: Arc::new(Mutex::new(storage)) }
    }

    fn append_ingest_entry(&self, entry: &CoreEntry) -> Result<(), String> {
        let input = entry_to_storage_input(entry)?;
        let mut storage = self.inner.lock().map_err(|_| "storage lock poisoned".to_string())?;
        storage.append_entry(input).map_err(|error| error.to_string())?;
        Ok(())
    }
}

impl crate::raymon_ingest::Storage for StorageHandle {
    fn append_entry(&self, entry: &CoreEntry) -> Result<(), String> {
        self.append_ingest_entry(entry)
    }
}

#[derive(Clone)]
struct IngestState {
    core: CoreState,
}

impl crate::raymon_ingest::StateStore for IngestState {
    fn insert_entry(&self, entry: CoreEntry) -> Result<(), String> {
        self.core.insert(entry).map_err(|error| error.to_string())
    }

    fn update_entry(&self, entry: CoreEntry) -> Result<(), String> {
        self.core.update(entry).map_err(|error| error.to_string())
    }

    fn get_entry(&self, uuid: &str) -> Result<Option<CoreEntry>, String> {
        self.core.get(uuid).map_err(|error| error.to_string())
    }
}

#[derive(Clone)]
struct IngestBus {
    bus: CoreBus,
}

impl crate::raymon_ingest::EventBus for IngestBus {
    fn emit(&self, event: CoreEvent) -> Result<(), String> {
        self.bus.emit(event).map_err(|error| error.to_string())
    }
}

fn restore_from_storage(
    core: &CoreState,
    storage: &RaymonStorage,
    collect_logs: bool,
) -> Result<Vec<LogEntry>, DynError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let entries_path = storage.data_dir().join(ENTRIES_FILE);
    let file = match File::open(&entries_path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };

    let mut reader = BufReader::new(file);
    let mut offset = 0u64;
    let mut buf = Vec::new();
    let mut restored = 0usize;
    let mut skipped = 0usize;
    let mut logs = Vec::new();
    let mut seen = HashSet::new();

    loop {
        buf.clear();
        let bytes = reader.read_until(b'\n', &mut buf)?;
        if bytes == 0 {
            break;
        }

        let mut line_bytes = buf.as_slice();
        if line_bytes.ends_with(b"\n") {
            line_bytes = &line_bytes[..line_bytes.len() - 1];
        }
        if line_bytes.ends_with(b"\r") {
            line_bytes = &line_bytes[..line_bytes.len() - 1];
        }
        if line_bytes.is_empty() {
            offset += bytes as u64;
            continue;
        }

        let stored: StoredEntry = match serde_json::from_slice(line_bytes) {
            Ok(entry) => entry,
            Err(err) => {
                warn!(?err, offset, "Skipping corrupt JSONL entry");
                skipped += 1;
                offset += bytes as u64;
                continue;
            }
        };

        let core_entry = match stored.payload {
            StoredPayload::Text { text } => match serde_json::from_str::<CoreEntry>(&text) {
                Ok(entry) => entry,
                Err(err) => {
                    warn!(?err, offset, "Skipping JSONL entry with invalid payload");
                    skipped += 1;
                    offset += bytes as u64;
                    continue;
                }
            },
            StoredPayload::Blob { .. } => {
                warn!(offset, "Skipping JSONL entry with blob payload");
                skipped += 1;
                offset += bytes as u64;
                continue;
            }
        };

        let log_entry = collect_logs.then(|| log_entry_from_core(&core_entry));
        let is_first = seen.insert(core_entry.uuid.clone());

        if is_first {
            core.insert(core_entry)
                .map_err(|error| -> DynError { Box::new(error) })?;
        } else {
            core.update(core_entry)
                .map_err(|error| -> DynError { Box::new(error) })?;
        }

        if let Some(log_entry) = log_entry {
            logs.push(log_entry);
        }

        restored += 1;
        offset += bytes as u64;
    }

    if restored > 0 || skipped > 0 {
        info!(
            restored,
            skipped,
            path = %entries_path.display(),
            "restored entries from storage"
        );
    }

    Ok(logs)
}

fn build_state(storage_root: &Path, collect_logs: bool) -> Result<(AppState, Vec<LogEntry>), DynError> {
    let storage = RaymonStorage::new(storage_root)?;
    let core = CoreState::default();
    let logs = restore_from_storage(&core, &storage, collect_logs)?;
    Ok((
        AppState {
            core,
            storage: StorageHandle::new(storage),
            bus: CoreBus::new(),
        },
        logs,
    ))
}

fn entry_to_storage_input(entry: &CoreEntry) -> Result<EntryInput, String> {
    let payload_text = serde_json::to_string(entry).map_err(|error| error.to_string())?;
    let summary = summarize_entry(entry, &payload_text);
    let search = build_search_text(entry, &payload_text);

    Ok(EntryInput {
        id: entry.uuid.clone(),
        screen: entry.screen.as_str().to_string(),
        session: entry
            .session_id
            .as_ref()
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        project: entry.project.clone(),
        host: entry.host.clone(),
        summary,
        search_text: search.search_text,
        types: search.types,
        colors: search.colors,
        payload: StoragePayload::Text(payload_text),
    })
}

fn summarize_entry(entry: &CoreEntry, payload_text: &str) -> String {
    if let Some(payload) = entry.payloads.first() {
        if let Some(message) = payload.content.get("message").and_then(|value| value.as_str()) {
            return truncate(message, SUMMARY_LIMIT);
        }
    }
    truncate(payload_text, SUMMARY_LIMIT)
}

struct SearchTextMetadata {
    search_text: String,
    types: Vec<String>,
    colors: Vec<String>,
}

fn build_search_text(entry: &CoreEntry, payload_text: &str) -> SearchTextMetadata {
    fn push_token(out: &mut String, is_first: &mut bool, token: &str) {
        if token.is_empty() {
            return;
        }
        if !*is_first {
            out.push(' ');
        } else {
            *is_first = false;
        }
        out.push_str(token);
    }

    let mut cap = entry.project.len()
        + entry.host.len()
        + entry.screen.as_str().len()
        + payload_text.len()
        + 4;
    if let Some(session) = &entry.session_id {
        cap += session.as_str().len() + 1;
    }
    for payload in &entry.payloads {
        cap += payload.r#type.len() + 1;
        if let Some(color) = payload.content.get("color").and_then(|value| value.as_str()) {
            cap += color.len() + 1;
        }
        if let Some(file) = payload.origin.file.as_deref() {
            cap += file.len() + 1;
        }
        if let Some(function_name) = payload.origin.function_name.as_deref() {
            cap += function_name.len() + 1;
        }
        if payload.origin.line_number.is_some() {
            cap += 11;
        }
    }

    let mut search_text = String::with_capacity(cap);
    let mut is_first = true;
    push_token(&mut search_text, &mut is_first, &entry.project);
    push_token(&mut search_text, &mut is_first, &entry.host);
    push_token(&mut search_text, &mut is_first, entry.screen.as_str());
    if let Some(session) = &entry.session_id {
        push_token(&mut search_text, &mut is_first, session.as_str());
    }

    let mut types = Vec::new();
    let mut colors = Vec::new();
    let mut seen_types = HashSet::new();
    let mut seen_colors = HashSet::new();

    for payload in &entry.payloads {
        if seen_types.insert(payload.r#type.as_str()) {
            types.push(payload.r#type.clone());
        }
        push_token(&mut search_text, &mut is_first, &payload.r#type);

        if let Some(color) = payload
            .content
            .get("color")
            .and_then(|value| value.as_str())
            .and_then(canonical_color_name)
        {
            if seen_colors.insert(color) {
                colors.push(color.to_string());
            }
            push_token(&mut search_text, &mut is_first, color);
        }
        if let Some(file) = payload.origin.file.as_deref() {
            push_token(&mut search_text, &mut is_first, file);
        }
        if let Some(function_name) = payload.origin.function_name.as_deref() {
            push_token(&mut search_text, &mut is_first, function_name);
        }
        if let Some(line) = payload.origin.line_number {
            let mut buffer = itoa::Buffer::new();
            push_token(&mut search_text, &mut is_first, buffer.format(line));
        }
    }
    push_token(&mut search_text, &mut is_first, payload_text);

    SearchTextMetadata { search_text, types, colors }
}

fn truncate(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    value.chars().take(max_len).collect()
}

fn log_id(uuid: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    uuid.hash(&mut hasher);
    hasher.finish()
}

fn log_entry_from_core(entry: &CoreEntry) -> LogEntry {
    let fallback = entry.payloads.first().map(|payload| payload.r#type.as_str()).unwrap_or("entry");
    let message = entry
        .payloads
        .first()
        .and_then(|payload| payload.content.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or(fallback);
    let detail_value = extract_entry_detail_value(entry);
    let detail = match detail_value {
        Some(value) => serde_json::to_string(&value).unwrap_or_else(|_| value.to_string()),
        None => {
            let contents: Vec<&Value> =
                entry.payloads.iter().map(|payload| &payload.content).collect();
            match contents.as_slice() {
                [only] => serde_json::to_string(only).unwrap_or_else(|_| only.to_string()),
                _ => serde_json::to_string(&contents).unwrap_or_else(|_| format!("{entry:?}")),
            }
        }
    };
    let (origin_file, origin_line) = entry
        .payloads
        .first()
        .map(|payload| (payload.origin.file.clone(), payload.origin.line_number))
        .unwrap_or((None, None));
    let origin = origin_file.as_deref().map(|file| {
        if let Some(line) = origin_line {
            format!("{file}:{line}")
        } else {
            file.to_string()
        }
    });

    let entry_type = entry.payloads.first().map(|payload| payload.r#type.clone());
    let color = entry.payloads.iter().find_map(|payload| {
        payload
            .content
            .get("color")
            .and_then(|value| value.as_str())
            .and_then(canonical_color_name)
            .map(|value| value.to_string())
    });
    let screen = Some(entry.screen.as_str().to_string());

    LogEntry {
        id: log_id(&entry.uuid),
        uuid: entry.uuid.clone(),
        message: truncate(message, SUMMARY_LIMIT),
        detail,
        origin,
        origin_file,
        origin_line,
        timestamp: Some(entry.received_at),
        entry_type,
        color,
        screen,
    }
}

fn extract_entry_detail_value(entry: &CoreEntry) -> Option<Value> {
    let mut values: Vec<Value> =
        entry.payloads.iter().filter_map(|payload| payload.content.get("data").cloned()).collect();

    if values.is_empty() {
        return None;
    }

    if values.len() == 1 {
        return values.pop();
    }

    let all_arrays = values.iter().all(|value| matches!(value, Value::Array(_)));
    if all_arrays {
        let mut flattened = Vec::new();
        for value in values {
            if let Value::Array(items) = value {
                flattened.extend(items);
            }
        }
        return Some(Value::Array(flattened));
    }

    Some(Value::Array(values))
}

fn cli_overrides(cli: &Cli) -> PartialConfig {
    let tui_enabled = if cli.no_tui {
        Some(false)
    } else if cli.tui {
        Some(true)
    } else {
        None
    };
    PartialConfig {
        enabled: None,
        host: cli.host.clone(),
        port: cli.port,
        ide: cli.ide.clone(),
        editor: cli.editor.clone(),
        jq: cli.jq.clone(),
        tui_enabled,
        ..PartialConfig::default()
    }
}

fn env_overrides(env: &BTreeMap<String, String>) -> Result<PartialConfig, ConfigError> {
    let mut partial = PartialConfig::default();
    if let Some(enabled) = env.get("RAYMON_ENABLED") {
        partial.enabled = Some(parse_bool("RAYMON_ENABLED", enabled)?);
    }
    if let Some(host) = env.get("RAYMON_HOST") {
        partial.host = Some(host.clone());
    }
    if let Some(port) = env.get("RAYMON_PORT") {
        partial.port = Some(parse_u16("RAYMON_PORT", port)?);
    }
    if let Some(ide) = env.get("RAYMON_IDE") {
        partial.ide = Some(ide.clone());
    }
    if let Some(editor) = env.get("RAYMON_EDITOR") {
        partial.editor = Some(editor.clone());
    }
    if let Some(jq) = env.get("RAYMON_JQ") {
        partial.jq = Some(jq.clone());
    }
    if let Some(value) = env.get("RAYMON_MAX_BODY_BYTES") {
        partial.max_body_bytes = Some(parse_usize("RAYMON_MAX_BODY_BYTES", value)?);
    }
    if let Some(value) = env.get("RAYMON_MAX_QUERY_LEN") {
        partial.max_query_len = Some(parse_usize("RAYMON_MAX_QUERY_LEN", value)?);
    }
    if let Some(value) = env.get("RAYMON_JQ_TIMEOUT_MS") {
        partial.jq_timeout_ms = Some(parse_u64("RAYMON_JQ_TIMEOUT_MS", value)?);
    }
    if let Some(value) = env.get("RAYMON_ALLOW_REMOTE") {
        partial.allow_remote = Some(parse_bool("RAYMON_ALLOW_REMOTE", value)?);
    }
    if let Some(value) = env.get("RAYMON_AUTH_TOKEN").or_else(|| env.get("RAYMON_TOKEN")) {
        if !value.trim().is_empty() {
            partial.auth_token = Some(value.clone());
        }
    }
    if let Some(no_tui) = env.get("RAYMON_NO_TUI") {
        let disabled = parse_bool("RAYMON_NO_TUI", no_tui)?;
        partial.tui_enabled = Some(!disabled);
    }
    if partial.tui_enabled.is_none() {
        if let Some(tui) = env.get("RAYMON_TUI") {
            partial.tui_enabled = Some(parse_bool("RAYMON_TUI", tui)?);
        }
    }
    Ok(partial)
}

fn tui_palette_override(env: &BTreeMap<String, String>) -> Result<Option<TuiPalette>, ConfigError> {
    let (name, value) = match env.get("RAYMON_TUI_PALETTE") {
        Some(value) => ("RAYMON_TUI_PALETTE", value),
        None => match env.get("RAYMON_PALETTE") {
            Some(value) => ("RAYMON_PALETTE", value),
            None => return Ok(None),
        },
    };

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let parsed = TuiPalette::parse_csv(trimmed).map_err(|error| ConfigError::InvalidEnv {
        name: name.to_string(),
        value: format!("{trimmed} ({error})"),
    })?;
    Ok(Some(parsed))
}

fn parse_u16(name: &str, value: &str) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidEnv { name: name.to_string(), value: value.to_string() })
}

fn parse_usize(name: &str, value: &str) -> Result<usize, ConfigError> {
    value
        .parse::<usize>()
        .map_err(|_| ConfigError::InvalidEnv { name: name.to_string(), value: value.to_string() })
}

fn parse_u64(name: &str, value: &str) -> Result<u64, ConfigError> {
    value
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidEnv { name: name.to_string(), value: value.to_string() })
}

fn parse_bool(name: &str, value: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidEnv { name: name.to_string(), value: value.to_string() }),
    }
}

fn load_config_file(path: &Path) -> Result<PartialConfig, ConfigError> {
    let contents = std::fs::read_to_string(path)
        .map_err(|source| ConfigError::ReadFile { path: path.to_path_buf(), source })?;
    let parsed: FileConfig = serde_json::from_str(&contents)
        .map_err(|source| ConfigError::ParseFile { path: path.to_path_buf(), source })?;
    Ok(parsed.into_partial())
}

fn find_config_path(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join("ray.json");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !current.pop() {
            break;
        }
    }
    None
}

fn resolve_config(
    cli: &Cli,
    cwd: &Path,
    env: &BTreeMap<String, String>,
) -> Result<(Config, Option<PathBuf>), ConfigError> {
    let mut partial = PartialConfig::default();

    let config_path = if let Some(path) = &cli.config {
        if !path.is_file() {
            return Err(ConfigError::MissingConfig { path: path.clone() });
        }
        Some(path.clone())
    } else {
        find_config_path(cwd)
    };

    if let Some(path) = config_path.as_ref() {
        let file_partial = load_config_file(path)?;
        partial.merge(file_partial);
    }

    let env_partial = env_overrides(env)?;
    partial.merge(env_partial);

    let cli_partial = cli_overrides(cli);
    partial.merge(cli_partial);

    let mut config = Config::from_partial(partial);
    if config.editor.is_none() {
        if let Some(value) = env.get("VISUAL") {
            config.editor = Some(value.clone());
        } else if let Some(value) = env.get("EDITOR") {
            config.editor = Some(value.clone());
        } else {
            config.editor = Some("vim".to_string());
        }
    }
    if config.ide.is_none() {
        config.ide = Some("code".to_string());
    }
    Ok((config, config_path))
}

fn resolve_bind_addr(host: &str, port: u16) -> Result<SocketAddr, std::io::Error> {
    let mut addrs = (host, port).to_socket_addrs()?;
    addrs.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no bind addresses resolved")
    })
}

fn storage_root(cwd: &Path, config_path: Option<&PathBuf>) -> PathBuf {
    config_path.and_then(|path| path.parent()).unwrap_or(cwd).to_path_buf()
}

async fn run_server(
    config: Config,
    state: AppState,
    mut shutdown: broadcast::Receiver<()>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<(), DynError> {
    let addr = resolve_bind_addr(&config.host, config.port)?;
    if !config.allow_remote && !addr.ip().is_loopback() {
        return Err(format!(
            "refusing to bind to non-loopback address {addr}. Set RAYMON_ALLOW_REMOTE=1 if you really want remote access."
        )
        .into());
    }
    let app = build_router(
        state,
        shutdown_tx,
        config.auth_token.clone(),
        config.max_body_bytes,
        config.max_query_len,
    )?;
    info!(%addr, "starting http server");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.recv().await;
        })
        .await?;

    Ok(())
}

async fn run_tui(
    config: TuiConfig,
    bus: CoreBus,
    initial_logs: Vec<LogEntry>,
    mut shutdown: broadcast::Receiver<()>,
    shutdown_tx: broadcast::Sender<()>,
    pause_tx: Option<watch::Sender<bool>>,
) -> Result<(), DynError> {
    let mut event_rx =
        bus.subscribe().map_err(|error| format!("event bus subscribe failed: {error}"))?;
    let (log_tx, log_rx) = std::sync::mpsc::channel::<UiEvent>();
    let log_tx_forward = log_tx.clone();
    let log_tx_shutdown = log_tx.clone();
    let running = Arc::new(AtomicBool::new(true));
    let running_signal = running.clone();

    for entry in initial_logs {
        if log_tx.send(UiEvent::Log(entry)).is_err() {
            break;
        }
    }

    let forward_handle = tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    let ui_event = match event {
                        CoreEvent::EntryInserted(entry) | CoreEvent::EntryUpdated(entry) => {
                            Some(UiEvent::Log(log_entry_from_core(&entry)))
                        }
                        CoreEvent::ScreenCleared(screen) => {
                            Some(UiEvent::ClearScreen(screen.as_str().to_string()))
                        }
                        CoreEvent::StateCleared => Some(UiEvent::ClearAll),
                    };

                    if let Some(ui_event) = ui_event {
                        if log_tx_forward.send(ui_event).is_err() {
                            break;
                        }
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let shutdown_handle = tokio::spawn(async move {
        let _ = shutdown.recv().await;
        let _ = log_tx_shutdown.send(UiEvent::Quit);
        running_signal.store(false, Ordering::SeqCst);
    });

    tokio::task::spawn_blocking(move || run_tui_loop(config, log_rx, running, shutdown_tx, pause_tx))
        .await??;

    forward_handle.abort();
    shutdown_handle.abort();

    Ok(())
}

fn run_tui_loop(
    config: TuiConfig,
    log_rx: std::sync::mpsc::Receiver<UiEvent>,
    running: Arc<AtomicBool>,
    shutdown_tx: broadcast::Sender<()>,
    pause_tx: Option<watch::Sender<bool>>,
) -> Result<(), DynError> {
    let _guard = TerminalGuard::enter()?;
    let stdout = io::stdout();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    terminal.hide_cursor()?;

    let mut tui = Tui::new(config);

    while running.load(Ordering::SeqCst) {
        while let Ok(event) = log_rx.try_recv() {
            match event {
                UiEvent::Log(entry) => tui.push_log(entry),
                UiEvent::ClearScreen(screen) => tui.clear_screen_for(Some(&screen)),
                UiEvent::ClearAll => tui.clear_screen_for(None),
                UiEvent::Quit => {
                    let _ = shutdown_tx.send(());
                    running.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }

        if !running.load(Ordering::SeqCst) {
            break;
        }

        terminal.draw(|frame| {
            tui.render(frame);
        })?;

        if event::poll(Duration::from_millis(TUI_TICK_MS))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let was_paused = tui.state.paused;
                    let action = tui.handle_key(key);
                    if let Some(pause_tx) = &pause_tx {
                        let now_paused = tui.state.paused;
                        if now_paused != was_paused {
                            let _ = pause_tx.send(now_paused);
                        }
                    }
                    if action == Action::Quit {
                        let _ = shutdown_tx.send(());
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                    if action != Action::None {
                        if matches!(action, Action::OpenEditor | Action::OpenOrigin) {
                            match TerminalSuspendGuard::new(&mut terminal) {
                                Ok(_guard) => {
                                    if let Err(error) = tui.perform_action(action) {
                                        warn!(error = %error, "tui action failed");
                                    }
                                }
                                Err(error) => {
                                    warn!(error = %error, "tui terminal suspend failed");
                                    tui.state.detail_notice = Some(
                                        "failed to suspend terminal for external command"
                                            .to_string(),
                                    );
                                }
                            }
                        } else if let Err(error) = tui.perform_action(action) {
                            warn!(error = %error, "tui action failed");
                        }
                    }
                }
                Event::Mouse(mouse) => {
                    let size = terminal.size()?;
                    let rect = Rect { x: 0, y: 0, width: size.width, height: size.height };
                    let action = tui.handle_mouse(mouse, rect);
                    if action == Action::Quit {
                        let _ = shutdown_tx.send(());
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                    if action != Action::None {
                        if matches!(action, Action::OpenEditor | Action::OpenOrigin) {
                            match TerminalSuspendGuard::new(&mut terminal) {
                                Ok(_guard) => {
                                    if let Err(error) = tui.perform_action(action) {
                                        warn!(error = %error, "tui action failed");
                                    }
                                }
                                Err(error) => {
                                    warn!(error = %error, "tui terminal suspend failed");
                                    tui.state.detail_notice =
                                        Some("failed to suspend terminal for external command".to_string());
                                }
                            }
                        } else if let Err(error) = tui.perform_action(action) {
                            warn!(error = %error, "tui action failed");
                        }
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }

    terminal.show_cursor()?;
    Ok(())
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self, DynError> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), DisableMouseCapture, LeaveAlternateScreen);
    }
}

struct TerminalSuspendGuard<'a> {
    terminal: &'a mut Terminal<CrosstermBackend<io::Stdout>>,
}

impl<'a> TerminalSuspendGuard<'a> {
    fn new(terminal: &'a mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<Self, DynError> {
        terminal.show_cursor()?;
        disable_raw_mode()?;
        if let Err(error) = execute!(terminal.backend_mut(), DisableMouseCapture, LeaveAlternateScreen) {
            let _ = enable_raw_mode();
            let _ = execute!(terminal.backend_mut(), EnterAlternateScreen, EnableMouseCapture);
            let _ = terminal.hide_cursor();
            let _ = terminal.backend_mut().flush();
            return Err(error.into());
        }
        terminal.backend_mut().flush()?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalSuspendGuard<'_> {
    fn drop(&mut self) {
        let _ = enable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), EnterAlternateScreen, EnableMouseCapture);
        let _ = self.terminal.clear();
        let _ = self.terminal.hide_cursor();
        let _ = self.terminal.backend_mut().flush();
    }
}

fn build_router(
    state: AppState,
    shutdown_tx: broadcast::Sender<()>,
    auth_token: Option<String>,
    max_body_bytes: usize,
    max_query_len: usize,
) -> Result<Router, DynError> {
    let mcp_service = RaymonMcp::streamable_http_service_with_shutdown_and_limits(
        state.core.clone(),
        state.bus.clone(),
        shutdown_tx.clone(),
        max_query_len,
    )?;
    let router_state = RouterState { app: state, mcp: mcp_service.clone() };
    let auth_state = AuthState { token: auth_token };
    let router = Router::new()
        .route("/", post(ingest_or_mcp_handler))
        .route_service("/mcp", mcp_service)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .route_layer(middleware::from_fn_with_state(auth_state, auth_middleware))
        .with_state(router_state);
    Ok(router)
}

#[derive(Clone)]
struct AuthState {
    token: Option<String>,
}

async fn auth_middleware(
    State(auth): State<AuthState>,
    request: AxumRequest,
    next: Next,
) -> Response {
    let Some(expected) = auth.token.as_deref() else {
        return next.run(request).await;
    };

    let bearer = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);
    let header = request
        .headers()
        .get("x-raymon-token")
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    let provided = bearer.or(header);
    if provided == Some(expected) {
        next.run(request).await
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
async fn ingest_or_mcp_handler(State(state): State<RouterState>, body: Bytes) -> impl IntoResponse {
    let ingestor = state.app.ingestor();
    let response = ingestor.handle(&body);
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    if response.status == 422 && looks_like_mcp_request(&body) {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()));

        if let Ok(request) = request {
            let response =
                state.mcp.clone().oneshot(request).await.unwrap_or_else(|err| match err {});
            return response.into_response();
        }
    }

    let payload = serde_json::json!({
        "ok": response.error.is_none(),
        "error": response.error,
    });
    (status, Json(payload)).into_response()
}

fn looks_like_mcp_request(body: &Bytes) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    match value {
        serde_json::Value::Object(object) => {
            matches!(object.get("jsonrpc").and_then(|value| value.as_str()), Some("2.0"))
                && object.get("method").is_some()
        }
        serde_json::Value::Array(items) => items.iter().any(|item| {
            item.as_object().is_some_and(|object| {
                matches!(object.get("jsonrpc").and_then(|value| value.as_str()), Some("2.0"))
                    && object.get("method").is_some()
            })
        }),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy)]
enum DemoEventKind {
    PlainLine,
    ColoredJson,
    Http,
    Sql,
    Error,
    LongLine,
    MultiPayload,
}

struct DemoRng {
    state: u64,
}

impl DemoRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        // splitmix64
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn gen_range_u32(&mut self, range: std::ops::Range<u32>) -> u32 {
        let width = range.end.saturating_sub(range.start);
        if width == 0 {
            return range.start;
        }
        range.start + (self.next_u64() % u64::from(width)) as u32
    }

    fn chance(&mut self, numerator: u32, denominator: u32) -> bool {
        if denominator == 0 {
            return false;
        }
        self.gen_range_u32(0..denominator) < numerator.min(denominator)
    }

    fn choose<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let idx = self.gen_range_u32(0..items.len().max(1) as u32) as usize % items.len();
        &items[idx]
    }
}

fn demo_kind(rng: &mut DemoRng) -> DemoEventKind {
    let roll = rng.gen_range_u32(0..100);
    match roll {
        0..=34 => DemoEventKind::PlainLine,
        35..=64 => DemoEventKind::ColoredJson,
        65..=79 => DemoEventKind::Http,
        80..=89 => DemoEventKind::Sql,
        90..=95 => DemoEventKind::Error,
        96..=98 => DemoEventKind::LongLine,
        _ => DemoEventKind::MultiPayload,
    }
}

fn demo_tags(rng: &mut DemoRng, kind: DemoEventKind) -> Vec<&'static str> {
    const TAGS: &[&str] = &["demo", "ui", "api", "db", "cache", "auth", "perf", "worker", "trace"];
    let mut tags = Vec::new();
    tags.push("demo");

    match kind {
        DemoEventKind::Http => tags.push("http"),
        DemoEventKind::Sql => tags.push("sql"),
        DemoEventKind::Error => tags.push("error"),
        DemoEventKind::MultiPayload => tags.push("context"),
        _ => {}
    }

    let extra = 1 + rng.gen_range_u32(0..3);
    for _ in 0..extra {
        let tag = *rng.choose(TAGS);
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }

    tags
}

fn demo_origin(rng: &mut DemoRng) -> RayOrigin {
    const FILES: &[&str] = &[
        "src/api/users.rs",
        "src/api/search.rs",
        "src/db/mod.rs",
        "src/ui/tui.rs",
        "src/worker/jobs.rs",
    ];
    const FUNCS: &[&str] =
        &["handle_request", "render_frame", "query_db", "rebuild_index", "flush_buffer"];

    let mut origin = RayOrigin {
        hostname: "local".to_string(),
        function_name: None,
        file: None,
        line_number: None,
    };

    // Rarely attach file/function/line metadata.
    if rng.chance(1, 20) {
        origin.file = Some((*rng.choose(FILES)).to_string());
        origin.function_name = Some((*rng.choose(FUNCS)).to_string());
        origin.line_number = Some(1 + rng.gen_range_u32(0..500));
    }

    origin
}

fn demo_envelope(rng: &mut DemoRng, seq: u64) -> RayEnvelope {
    let kind = demo_kind(rng);
    let tags = demo_tags(rng, kind);

    let meta = RayMeta {
        project: Some("demo".to_string()),
        host: Some("local".to_string()),
        screen: Some("demo:local:default".to_string()),
        session_id: None,
    };

    let uuid = Uuid::new_v4().to_string();

    let payloads = match kind {
        DemoEventKind::PlainLine => {
            const LINES: &[&str] = &[
                "demo: hello world",
                "cache miss for key=user:42",
                "rendered frame in 7ms",
                "worker heartbeat ok",
                "loaded config and started",
            ];
            vec![RayPayload {
                r#type: "log".to_string(),
                content: serde_json::json!({
                    "message": rng.choose(LINES),
                    "tags": tags,
                    "seq": seq,
                }),
                origin: demo_origin(rng),
            }]
        }
        DemoEventKind::ColoredJson => {
            const COLORS: &[(&str, &str)] =
                &[("info", "green"), ("debug", "blue"), ("warn", "yellow"), ("log", "grey")];
            const TOPICS: &[&str] = &["render", "search", "ingest", "index", "mcp", "tui"];
            let (entry_type, color) = rng.choose(COLORS);
            let topic = rng.choose(TOPICS);
            vec![RayPayload {
                r#type: (*entry_type).to_string(),
                content: serde_json::json!({
                    "message": format!("demo {topic} event #{seq}"),
                    "color": color,
                    "tags": tags,
                    "data": {
                        "topic": topic,
                        "ok": true,
                        "retry": rng.chance(1, 10),
                        "count": rng.gen_range_u32(0..1000),
                    }
                }),
                origin: demo_origin(rng),
            }]
        }
        DemoEventKind::Http => {
            const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE"];
            const PATHS: &[&str] =
                &["/api/users", "/api/sessions", "/api/search", "/health", "/api/events"];
            let method = rng.choose(METHODS);
            let path = rng.choose(PATHS);
            let status_bucket = rng.gen_range_u32(0..100);
            let status = match status_bucket {
                0..=84 => 200,
                85..=92 => 204,
                93..=97 => 404,
                _ => 500,
            };
            let duration_ms = 1 + rng.gen_range_u32(0..850);
            let color = match status {
                200..=299 => "green",
                400..=499 => "yellow",
                _ => "red",
            };

            vec![RayPayload {
                r#type: "http".to_string(),
                content: serde_json::json!({
                    "message": format!("{method} {path} -> {status} ({duration_ms}ms)"),
                    "color": color,
                    "tags": tags,
                    "method": method,
                    "path": path,
                    "status": status,
                    "duration_ms": duration_ms,
                }),
                origin: demo_origin(rng),
            }]
        }
        DemoEventKind::Sql => {
            const QUERIES: &[&str] = &[
                "SELECT id, email FROM users WHERE id = ?",
                "UPDATE sessions SET last_seen = ? WHERE id = ?",
                "INSERT INTO events(kind, payload) VALUES(?, ?)",
                "SELECT * FROM logs ORDER BY received_at DESC LIMIT 50",
            ];
            let query = rng.choose(QUERIES);
            let duration_ms = 1 + rng.gen_range_u32(0..120);
            let rows = rng.gen_range_u32(0..50);
            vec![RayPayload {
                r#type: "sql".to_string(),
                content: serde_json::json!({
                    "message": format!("sql ({duration_ms}ms, {rows} rows)"),
                    "color": "purple",
                    "tags": tags,
                    "query": query,
                    "duration_ms": duration_ms,
                    "rows": rows,
                }),
                origin: demo_origin(rng),
            }]
        }
        DemoEventKind::Error => {
            const ERRORS: &[&str] = &[
                "timeout while calling upstream",
                "failed to deserialize payload",
                "db connection dropped",
                "permission denied",
            ];
            let message = rng.choose(ERRORS);
            vec![RayPayload {
                r#type: "error".to_string(),
                content: serde_json::json!({
                    "message": format!("error: {message}"),
                    "color": "red",
                    "tags": tags,
                    "error": {
                        "kind": "DemoError",
                        "message": message,
                        "retryable": rng.chance(1, 3),
                        "code": 1000 + rng.gen_range_u32(0..200),
                    },
                }),
                origin: demo_origin(rng),
            }]
        }
        DemoEventKind::LongLine => {
            let base = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";
            let repeats = 2 + rng.gen_range_u32(0..6);
            let mut message = String::new();
            for _ in 0..repeats {
                if !message.is_empty() {
                    message.push(' ');
                }
                message.push_str(base);
            }

            vec![RayPayload {
                r#type: "log".to_string(),
                content: serde_json::json!({
                    "message": format!("demo long line #{seq}: {message}"),
                    "color": "blue",
                    "tags": tags,
                    "seq": seq,
                }),
                origin: demo_origin(rng),
            }]
        }
        DemoEventKind::MultiPayload => {
            let payload_a = RayPayload {
                r#type: "log".to_string(),
                content: serde_json::json!({
                    "message": format!("demo multi-payload entry #{seq}"),
                    "color": "blue",
                    "tags": tags,
                    "seq": seq,
                }),
                origin: demo_origin(rng),
            };
            let payload_b = RayPayload {
                r#type: "context".to_string(),
                content: serde_json::json!({
                    "service": "raymon",
                    "version": env!("CARGO_PKG_VERSION"),
                    "pid": std::process::id(),
                    "flags": {
                        "demo": true,
                    },
                }),
                origin: demo_origin(rng),
            };
            vec![payload_a, payload_b]
        }
    };

    RayEnvelope { uuid, payloads, meta: Some(meta) }
}

async fn run_demo(
    mut shutdown: broadcast::Receiver<()>,
    mut paused: watch::Receiver<bool>,
    ingestor: IngestorHandle,
) {
    let seed = crate::raymon_ingest::now_millis()
        ^ (std::process::id() as u64).wrapping_mul(0x9E3779B97F4A7C15);
    let mut rng = DemoRng::new(seed);
    let mut seq = 0u64;

    // Small delay so the server/TUI are already up.
    time::sleep(Duration::from_millis(250)).await;

    loop {
        if *paused.borrow() {
            tokio::select! {
                res = shutdown.recv() => {
                    match res {
                        Ok(()) | Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
                res = paused.changed() => { let _ = res; }
            }
            continue;
        }

        let delay_ms = 120 + u64::from(rng.gen_range_u32(0..330));
        tokio::select! {
            res = shutdown.recv() => {
                match res {
                    Ok(()) | Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
            res = paused.changed() => { let _ = res; }
            _ = time::sleep(Duration::from_millis(delay_ms)) => {
                seq = seq.wrapping_add(1);
                let envelope = demo_envelope(&mut rng, seq);
                let Ok(payload) = serde_json::to_vec(&envelope) else {
                    continue;
                };
                let response = ingestor.handle(&payload);
                if let Some(error) = response.error {
                    warn!(%error, "demo ingest failed");
                }
            }
        }
    }
}

pub async fn run() -> Result<(), DynError> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let cwd = env::current_dir()?;
    let env_map: BTreeMap<String, String> = env::vars().collect();
    let (config, config_path) = resolve_config(&cli, &cwd, &env_map)?;

    if let Some(path) = &config_path {
        info!(path = %path.display(), "loaded config file");
    } else {
        warn!("no ray.json found, using defaults and env/cli overrides");
    }

    info!(
        enabled = config.enabled,
        host = %config.host,
        port = config.port,
        tui_enabled = config.tui_enabled,
        allow_remote = config.allow_remote,
        max_body_bytes = config.max_body_bytes,
        max_query_len = config.max_query_len,
        jq_timeout_ms = config.jq_timeout_ms,
        auth_enabled = config.auth_token.is_some(),
        ide = ?config.ide,
        editor = ?config.editor,
        jq = ?config.jq,
        "resolved config"
    );

    if !config.enabled {
        warn!("raymon disabled via config/env");
        return Ok(());
    }

    let storage_root = storage_root(&cwd, config_path.as_ref());
    info!(path = %storage_root.display(), "storage root");

    // Archives are file-backed per TUI session; start the live stream empty.
    let (state, initial_logs) = build_state(&storage_root, false)?;
    let (shutdown_tx, _) = broadcast::channel(4);
    let mut shutdown_rx = shutdown_tx.subscribe();

    let (pause_tx, pause_rx) = if cli.demo {
        let (pause_tx, pause_rx) = watch::channel(false);
        (Some(pause_tx), Some(pause_rx))
    } else {
        (None, None)
    };

    let demo_handle = if cli.demo {
        info!("demo mode enabled (generating local events)");
        let paused = pause_rx.expect("pause channel configured");
        Some(tokio::spawn(run_demo(shutdown_tx.subscribe(), paused, state.ingestor())))
    } else {
        None
    };

    let mut server_handle = tokio::spawn(run_server(
        config.clone(),
        state.clone(),
        shutdown_tx.subscribe(),
        shutdown_tx.clone(),
    ));

    let tui_handle = if config.tui_enabled {
        let palette = tui_palette_override(&env_map)?;
	        let tui_config = TuiConfig {
	            editor_command: config.editor.clone(),
	            ide_command: config.ide.clone(),
	            jq_command: config.jq.clone(),
	            palette,
	            show_archives_by_default: false,
	            archive_dir: Some(storage_root.join("data").join("archives")),
	            max_query_len: config.max_query_len,
	            jq_timeout_ms: config.jq_timeout_ms,
	        };
        Some(tokio::spawn(run_tui(
            tui_config,
            state.bus.clone(),
            initial_logs,
            shutdown_tx.subscribe(),
            shutdown_tx.clone(),
            pause_tx.clone(),
        )))
    } else {
        None
    };

    let mut server_result: Option<Result<(), DynError>> = None;

    if let Some(mut tui_handle) = tui_handle {
        let mut tui_result: Option<Result<(), DynError>> = None;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = shutdown_tx.send(());
            }
            _ = shutdown_rx.recv() => {}
            res = &mut server_handle => {
                server_result = Some(res?);
                let _ = shutdown_tx.send(());
            }
            res = &mut tui_handle => {
                tui_result = Some(res?);
                let _ = shutdown_tx.send(());
            }
        }

        // Ensure every component sees the shutdown signal (idempotent).
        let _ = shutdown_tx.send(());

        let tui_result = match tui_result {
            Some(result) => result,
            None => tui_handle.await?,
        };
        let server_result = match server_result {
            Some(result) => result,
            None => server_handle.await?,
        };

        if let Some(handle) = demo_handle {
            let _ = handle.await;
        }

        tui_result?;
        server_result?;
    } else {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let _ = shutdown_tx.send(());
            }
            _ = shutdown_rx.recv() => {}
            res = &mut server_handle => {
                server_result = Some(res?);
                let _ = shutdown_tx.send(());
            }
        }

        let _ = shutdown_tx.send(());

        let server_result = match server_result {
            Some(result) => result,
            None => server_handle.await?,
        };
        if let Some(handle) = demo_handle {
            let _ = handle.await;
        }
        server_result?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn cli_parses_flags() {
        let cli = Cli::parse_from([
            "raymon",
            "--host",
            "0.0.0.0",
            "--port",
            "9999",
            "--config",
            "config.json",
            "--ide",
            "zed",
            "--editor",
            "vim",
            "--jq",
            "jq",
            "--no-tui",
        ]);

        assert_eq!(cli.host.as_deref(), Some("0.0.0.0"));
        assert_eq!(cli.port, Some(9999));
        assert_eq!(cli.config.as_deref(), Some(Path::new("config.json")));
        assert_eq!(cli.ide.as_deref(), Some("zed"));
        assert_eq!(cli.editor.as_deref(), Some("vim"));
        assert_eq!(cli.jq.as_deref(), Some("jq"));
        assert!(!cli.tui);
        assert!(cli.no_tui);
        assert!(!cli.demo);
    }

    #[test]
    fn resolves_config_in_order() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let child = root.join("nested");
        fs::create_dir_all(&child).expect("create nested dir");

        let config_path = root.join("ray.json");
        fs::write(
            &config_path,
            r#"{
  "host": "10.0.0.1",
  "port": 1111,
  "ide": "zed",
  "tui": true
}"#,
        )
        .expect("write config");

        let mut env_map = BTreeMap::new();
        env_map.insert("RAYMON_PORT".to_string(), "2222".to_string());
        env_map.insert("RAYMON_EDITOR".to_string(), "vim".to_string());
        env_map.insert("RAYMON_NO_TUI".to_string(), "1".to_string());

        let cli = Cli {
            host: Some("0.0.0.0".to_string()),
            port: None,
            config: None,
            ide: None,
            editor: Some("nano".to_string()),
            jq: None,
            tui: false,
            no_tui: true,
            demo: false,
        };

        let (config, resolved_path) = resolve_config(&cli, &child, &env_map).unwrap();

        assert_eq!(resolved_path.as_deref(), Some(config_path.as_path()));
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 2222);
        assert_eq!(config.ide.as_deref(), Some("zed"));
        assert_eq!(config.editor.as_deref(), Some("nano"));
        assert!(!config.tui_enabled);
    }

    #[test]
    fn parse_bool_accepts_and_rejects_values() {
        assert!(parse_bool("FLAG", "true").unwrap());
        assert!(parse_bool("FLAG", "1").unwrap());
        assert!(!parse_bool("FLAG", "0").unwrap());
        assert!(!parse_bool("FLAG", "off").unwrap());

        let err = parse_bool("FLAG", "maybe").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnv { .. }));
    }

    #[test]
    fn parse_u16_rejects_invalid_value() {
        let err = parse_u16("PORT", "not-a-number").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnv { .. }));
    }

    #[test]
    fn tui_palette_override_parses_valid_csv() {
        let value = "#111111,#222222,#000000,#ff0000,#00ff00,#ffff00,#0000ff,#ff00ff,#00ffff,#cccccc,#555555,#ff5555,#55ff55,#ffff55,#5555ff,#ff55ff,#55ffff,#ffffff";
        let mut env_map = BTreeMap::new();
        env_map.insert("RAYMON_TUI_PALETTE".to_string(), value.to_string());

        let palette = tui_palette_override(&env_map).unwrap().expect("palette");
        assert_eq!(palette.fg, ratatui::style::Color::Rgb(0x11, 0x11, 0x11));
        assert_eq!(palette.bg, ratatui::style::Color::Rgb(0x22, 0x22, 0x22));
        assert_eq!(palette.ansi_color(0), ratatui::style::Color::Rgb(0, 0, 0));
        assert_eq!(palette.ansi_color(1), ratatui::style::Color::Rgb(0xff, 0, 0));
        assert_eq!(palette.ansi_color(2), ratatui::style::Color::Rgb(0, 0xff, 0));
        assert_eq!(palette.ansi_color(15), ratatui::style::Color::Rgb(0xff, 0xff, 0xff));
    }

    #[test]
    fn tui_palette_override_rejects_invalid_csv() {
        let mut env_map = BTreeMap::new();
        env_map.insert("RAYMON_TUI_PALETTE".to_string(), "#000000,#111111".to_string());
        let err = tui_palette_override(&env_map).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidEnv { .. }));
    }

    #[test]
    fn find_config_path_none_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        assert!(find_config_path(temp.path()).is_none());
    }

    #[test]
    fn load_config_file_invalid_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("ray.json");
        fs::write(&path, "{not valid json").expect("write");
        let err = load_config_file(&path).unwrap_err();
        assert!(matches!(err, ConfigError::ParseFile { .. }));
    }

    #[test]
    fn build_search_text_includes_type_and_color() {
        let screen = Screen::new("proj:host:default");
        let entry = CoreEntry {
            uuid: "entry-1".to_string(),
            received_at: 1,
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: screen.clone(),
            session_id: None,
            payloads: vec![crate::raymon_core::Payload {
                r#type: "log".to_string(),
                content: serde_json::json!({
                    "message": "hello",
                    "color": "red"
                }),
                origin: crate::raymon_core::Origin {
                    project: "proj".to_string(),
                    host: "host".to_string(),
                    screen: Some(screen.clone()),
                    session_id: None,
                    function_name: None,
                    file: None,
                    line_number: None,
                },
            }],
        };

        let search = build_search_text(&entry, "payload");
        assert!(search.search_text.contains("log"));
        assert!(search.search_text.contains("red"));
        assert_eq!(search.types, vec!["log".to_string()]);
        assert_eq!(search.colors, vec!["red".to_string()]);
    }

    #[test]
    fn build_state_restores_entries_from_storage() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let mut storage = RaymonStorage::new(root).expect("storage");

        let screen = Screen::new("proj:host:default");
        let entry = CoreEntry {
            uuid: "entry-restore-1".to_string(),
            received_at: 1,
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: screen.clone(),
            session_id: None,
            payloads: vec![crate::raymon_core::Payload {
                r#type: "log".to_string(),
                content: serde_json::json!({ "message": "hello" }),
                origin: crate::raymon_core::Origin {
                    project: "proj".to_string(),
                    host: "host".to_string(),
                    screen: Some(screen),
                    session_id: None,
                    function_name: None,
                    file: None,
                    line_number: None,
                },
            }],
        };

        let input = entry_to_storage_input(&entry).expect("storage input");
        storage.append_entry(input).expect("append");

        let (state, logs) = build_state(root, true).expect("build state");
        let restored = state.core.get(&entry.uuid).expect("get entry");
        assert!(restored.is_some());
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].message, "hello");
    }
}
