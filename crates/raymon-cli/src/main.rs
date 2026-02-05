use std::{
    collections::{BTreeMap, HashSet},
    env,
    hash::{Hash, Hasher},
    io,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use clap::Parser;
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use raymon_core::{
    Entry as CoreEntry, Event as CoreEvent, EventBus as CoreEventBusTrait, Filters, Screen,
    StateStore as CoreStateStoreTrait,
};
use raymon_ingest::Ingestor;
use raymon_mcp::{RaymonMcp, RaymonMcpService};
use raymon_storage::{EntryInput, EntryPayload as StoragePayload, Storage as RaymonStorage};
use raymon_tui::{Action, LogEntry, Tui, TuiConfig};
use serde::Deserialize;
use tokio::sync::broadcast;
use tracing::{info, warn};
use tower::ServiceExt;

const DEFAULT_HOST: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 7777;
const DEFAULT_TUI_ENABLED: bool = true;
const SUMMARY_LIMIT: usize = 160;
const TUI_TICK_MS: u64 = 50;

type DynError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
enum UiEvent {
    Log(LogEntry),
    ClearScreen(String),
    ClearAll,
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
    }
}

impl Config {
    fn from_partial(partial: PartialConfig) -> Self {
        Self {
            enabled: partial.enabled.unwrap_or(true),
            host: partial
                .host
                .unwrap_or_else(|| DEFAULT_HOST.to_string()),
            port: partial.port.unwrap_or(DEFAULT_PORT),
            ide: partial.ide,
            editor: partial.editor,
            jq: partial.jq,
            tui_enabled: partial.tui_enabled.unwrap_or(DEFAULT_TUI_ENABLED),
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
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    ParseFile {
        path: PathBuf,
        source: serde_json::Error,
    },
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
            IngestState {
                core: self.core.clone(),
            },
            self.storage.clone(),
            IngestBus {
                bus: self.bus.clone(),
            },
            raymon_ingest::now_millis,
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
        if let Some(existing) = inner
            .entries
            .iter_mut()
            .find(|existing| existing.uuid == entry.uuid)
        {
            *existing = entry;
        } else {
            inner.entries.push(entry);
        }
        Ok(())
    }

    fn get(&self, uuid: &str) -> Result<Option<CoreEntry>, StateError> {
        let inner = self.inner.read().map_err(|_| StateError::Poisoned)?;
        Ok(inner
            .entries
            .iter()
            .find(|entry| entry.uuid == uuid)
            .cloned())
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
        Self {
            inner: Arc::new(Mutex::new(storage)),
        }
    }

    fn append_ingest_entry(&self, entry: &CoreEntry) -> Result<(), String> {
        let input = entry_to_storage_input(entry)?;
        let mut storage = self
            .inner
            .lock()
            .map_err(|_| "storage lock poisoned".to_string())?;
        storage
            .append_entry(input)
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

impl raymon_ingest::Storage for StorageHandle {
    fn append_entry(&self, entry: &CoreEntry) -> Result<(), String> {
        self.append_ingest_entry(entry)
    }
}

#[derive(Clone)]
struct IngestState {
    core: CoreState,
}

impl raymon_ingest::StateStore for IngestState {
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

impl raymon_ingest::EventBus for IngestBus {
    fn emit(&self, event: CoreEvent) -> Result<(), String> {
        self.bus.emit(event).map_err(|error| error.to_string())
    }
}

fn build_state(storage_root: &Path) -> Result<AppState, DynError> {
    let storage = RaymonStorage::new(storage_root)?;
    Ok(AppState {
        core: CoreState::default(),
        storage: StorageHandle::new(storage),
        bus: CoreBus::new(),
    })
}

fn entry_to_storage_input(entry: &CoreEntry) -> Result<EntryInput, String> {
    let payload_text = serde_json::to_string(entry).map_err(|error| error.to_string())?;
    let summary = summarize_entry(entry, &payload_text);
    let search_text = build_search_text(entry, &payload_text);

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
        search_text,
        payload: StoragePayload::Text(payload_text),
    })
}

fn summarize_entry(entry: &CoreEntry, payload_text: &str) -> String {
    if let Some(payload) = entry.payloads.first() {
        if let Some(message) = payload
            .content
            .get("message")
            .and_then(|value| value.as_str())
        {
            return truncate(message, SUMMARY_LIMIT);
        }
    }
    truncate(payload_text, SUMMARY_LIMIT)
}

fn build_search_text(entry: &CoreEntry, payload_text: &str) -> String {
    let mut parts = Vec::new();
    parts.push(entry.project.clone());
    parts.push(entry.host.clone());
    parts.push(entry.screen.as_str().to_string());
    if let Some(session) = &entry.session_id {
        parts.push(session.as_str().to_string());
    }
    for payload in &entry.payloads {
        parts.push(payload.r#type.clone());
        if let Some(color) = payload
            .content
            .get("color")
            .and_then(|value| value.as_str())
        {
            parts.push(color.to_string());
        }
        if let Some(file) = payload.origin.file.as_deref() {
            parts.push(file.to_string());
        }
        if let Some(function_name) = payload.origin.function_name.as_deref() {
            parts.push(function_name.to_string());
        }
        if let Some(line) = payload.origin.line_number {
            parts.push(line.to_string());
        }
    }
    parts.push(payload_text.to_string());
    parts.join(" ")
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
    let fallback = entry
        .payloads
        .first()
        .map(|payload| payload.r#type.as_str())
        .unwrap_or("entry");
    let message = entry
        .payloads
        .first()
        .and_then(|payload| payload.content.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or(fallback);
    let detail = serde_json::to_string_pretty(entry).unwrap_or_else(|_| format!("{entry:?}"));
    let (origin_file, origin_line) = entry
        .payloads
        .first()
        .map(|payload| {
            (
                payload.origin.file.clone(),
                payload.origin.line_number,
            )
        })
        .unwrap_or((None, None));
    let origin = origin_file.as_deref().map(|file| {
        if let Some(line) = origin_line {
            format!("{file}:{line}")
        } else {
            file.to_string()
        }
    });

    let entry_type = entry.payloads.first().map(|payload| payload.r#type.clone());
    let color = entry
        .payloads
        .iter()
        .find_map(|payload| {
            payload
                .content
                .get("color")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string())
        });
    let screen = Some(entry.screen.as_str().to_string());

    LogEntry {
        id: log_id(&entry.uuid),
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
    }
}

fn env_overrides(env: &BTreeMap<String, String>) -> Result<PartialConfig, ConfigError> {
    let mut partial = PartialConfig::default();
    if let Some(enabled) = env.get("RAY_ENABLED") {
        partial.enabled = Some(parse_bool("RAY_ENABLED", enabled)?);
    }
    if let Some(host) = env.get("RAY_HOST") {
        partial.host = Some(host.clone());
    }
    if let Some(port) = env.get("RAY_PORT") {
        partial.port = Some(parse_u16("RAY_PORT", port)?);
    }
    if let Some(ide) = env.get("RAY_IDE") {
        partial.ide = Some(ide.clone());
    }
    if let Some(editor) = env.get("RAY_EDITOR") {
        partial.editor = Some(editor.clone());
    }
    if let Some(jq) = env.get("RAY_JQ") {
        partial.jq = Some(jq.clone());
    }
    if let Some(no_tui) = env.get("RAY_NO_TUI") {
        let disabled = parse_bool("RAY_NO_TUI", no_tui)?;
        partial.tui_enabled = Some(!disabled);
    }
    if partial.tui_enabled.is_none() {
        if let Some(tui) = env.get("RAY_TUI") {
            partial.tui_enabled = Some(parse_bool("RAY_TUI", tui)?);
        }
    }
    Ok(partial)
}

fn parse_u16(name: &str, value: &str) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidEnv {
            name: name.to_string(),
            value: value.to_string(),
        })
}

fn parse_bool(name: &str, value: &str) -> Result<bool, ConfigError> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(ConfigError::InvalidEnv {
            name: name.to_string(),
            value: value.to_string(),
        }),
    }
}

fn load_config_file(path: &Path) -> Result<PartialConfig, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed: FileConfig = serde_json::from_str(&contents).map_err(|source| {
        ConfigError::ParseFile {
            path: path.to_path_buf(),
            source,
        }
    })?;
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
            return Err(ConfigError::MissingConfig {
                path: path.clone(),
            });
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
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no bind addresses resolved",
        )
    })
}

fn storage_root(cwd: &Path, config_path: Option<&PathBuf>) -> PathBuf {
    config_path
        .and_then(|path| path.parent())
        .unwrap_or(cwd)
        .to_path_buf()
}

async fn run_server(
    config: Config,
    state: AppState,
    mut shutdown: broadcast::Receiver<()>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<(), DynError> {
    let addr = resolve_bind_addr(&config.host, config.port)?;
    let app = build_router(state, shutdown_tx)?;
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
    mut shutdown: broadcast::Receiver<()>,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<(), DynError> {
    let mut event_rx = bus
        .subscribe()
        .map_err(|error| format!("event bus subscribe failed: {error}"))?;
    let (log_tx, log_rx) = std::sync::mpsc::channel::<UiEvent>();
    let running = Arc::new(AtomicBool::new(true));
    let running_signal = running.clone();

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
                        if log_tx.send(ui_event).is_err() {
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
        running_signal.store(false, Ordering::SeqCst);
    });

    tokio::task::spawn_blocking(move || run_tui_loop(config, log_rx, running, shutdown_tx))
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
            }
        }

        terminal.draw(|frame| {
            tui.render(frame);
        })?;

        if event::poll(Duration::from_millis(TUI_TICK_MS))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let action = tui.handle_key(key);
                    if action == Action::Quit {
                        let _ = shutdown_tx.send(());
                        running.store(false, Ordering::SeqCst);
                        break;
                    }
                    if action != Action::None {
                        if let Err(error) = tui.perform_action(action) {
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
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

fn build_router(
    state: AppState,
    shutdown_tx: broadcast::Sender<()>,
) -> Result<Router, DynError> {
    let mcp_service = RaymonMcp::streamable_http_service_with_shutdown(
        state.core.clone(),
        state.bus.clone(),
        shutdown_tx.clone(),
    )?;
    let router_state = RouterState {
        app: state,
        mcp: mcp_service.clone(),
    };
    let router = Router::new()
        .route("/", post(ingest_or_mcp_handler))
        .route_service("/mcp", mcp_service)
        .with_state(router_state);
    Ok(router)
}

async fn ingest_or_mcp_handler(
    State(state): State<RouterState>,
    body: Bytes,
) -> impl IntoResponse {
    let ingestor = state.app.ingestor();
    let response = ingestor.handle(&body);
    let status =
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    if response.status == 422 && looks_like_mcp_request(&body) {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()));

        if let Ok(request) = request {
            let response = state
                .mcp
                .clone()
                .oneshot(request)
                .await
                .unwrap_or_else(|err| match err {});
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
                matches!(
                    object.get("jsonrpc").and_then(|value| value.as_str()),
                    Some("2.0")
                ) && object.get("method").is_some()
            })
        }),
        _ => false,
    }
}

#[tokio::main]
async fn main() -> Result<(), DynError> {
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

    let state = build_state(&storage_root)?;
    let (shutdown_tx, _) = broadcast::channel(4);

    let server_handle = tokio::spawn(run_server(
        config.clone(),
        state.clone(),
        shutdown_tx.subscribe(),
        shutdown_tx.clone(),
    ));

    let tui_handle = if config.tui_enabled {
        let tui_config = TuiConfig {
            editor_command: config.editor.clone(),
            ide_command: config.ide.clone(),
            jq_command: config.jq.clone(),
            show_archives_by_default: false,
        };
        Some(tokio::spawn(run_tui(
            tui_config,
            state.bus.clone(),
            shutdown_tx.subscribe(),
            shutdown_tx.clone(),
        )))
    } else {
        None
    };

    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(());

    if let Some(handle) = tui_handle {
        handle.await??;
    }

    server_handle.await??;
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
        env_map.insert("RAY_PORT".to_string(), "2222".to_string());
        env_map.insert("RAY_EDITOR".to_string(), "vim".to_string());
        env_map.insert("RAY_NO_TUI".to_string(), "1".to_string());

        let cli = Cli {
            host: Some("0.0.0.0".to_string()),
            port: None,
            config: None,
            ide: None,
            editor: Some("nano".to_string()),
            jq: None,
            tui: false,
            no_tui: true,
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
            payloads: vec![raymon_core::Payload {
                r#type: "log".to_string(),
                content: serde_json::json!({
                    "message": "hello",
                    "color": "red"
                }),
                origin: raymon_core::Origin {
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

        let text = build_search_text(&entry, "payload");
        assert!(text.contains("log"));
        assert!(text.contains("red"));
    }
}
