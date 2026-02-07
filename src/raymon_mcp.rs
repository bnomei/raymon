//! MCP handlers for Raymon using rmcp.

use std::any::Any;
use std::fmt::Display;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use crate::raymon_core::{Event, EventBus, Filters, Screen, StateStore};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CustomNotification, CustomRequest, CustomResult, InitializeRequestParams, InitializeResult,
        ServerCapabilities, ServerInfo, ServerNotification,
    },
    tool, tool_handler, tool_router,
    transport::{
        streamable_http_server::session::local::LocalSessionManager, StreamableHttpServerConfig,
        StreamableHttpService,
    },
    ErrorData as McpError, Json, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc, RwLock};

/// Streamable HTTP service type for mounting on `/mcp` with axum/tower.
pub type RaymonMcpService<S, B> = StreamableHttpService<RaymonMcp<S, B>, LocalSessionManager>;

const DEFAULT_LIST_LIMIT: usize = 100;
const MAX_LIST_LIMIT: usize = 500;
const DEFAULT_MAX_QUERY_LEN: usize = 265;
const MAX_MCP_PEERS: usize = 64;

trait PeerHealth {
    fn transport_closed(&self) -> bool;
}

impl PeerHealth for rmcp::Peer<rmcp::RoleServer> {
    fn transport_closed(&self) -> bool {
        self.is_transport_closed()
    }
}

fn prune_closed_peers<P: PeerHealth>(peers: &mut Vec<P>) {
    peers.retain(|peer| !peer.transport_closed());
}

fn enforce_peer_cap<P>(peers: &mut Vec<P>, cap: usize) {
    if cap == 0 {
        peers.clear();
        return;
    }

    if peers.len() <= cap {
        return;
    }

    let overflow = peers.len() - cap;
    peers.drain(0..overflow);
}

#[derive(Debug, thiserror::Error)]
pub enum McpInitError {
    #[error("event bus subscription failed: {0}")]
    EventBus(String),
    #[error("tokio runtime not available")]
    NoRuntime,
}

/// Trait for event subscriptions that can be awaited inside the MCP server.
pub trait EventStream: Send + 'static {
    fn recv<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Option<Event>> + Send + 'a>>;
}

impl EventStream for broadcast::Receiver<Event> {
    fn recv<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Option<Event>> + Send + 'a>> {
        Box::pin(async move {
            loop {
                match self.recv().await {
                    Ok(event) => return Some(event),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        })
    }
}

impl EventStream for mpsc::Receiver<Event> {
    fn recv<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Option<Event>> + Send + 'a>> {
        Box::pin(async move { self.recv().await })
    }
}

#[derive(Clone)]
pub struct RaymonMcp<S, B> {
    state: S,
    bus: B,
    shutdown: Option<broadcast::Sender<()>>,
    max_query_len: usize,
    peers: Arc<RwLock<Vec<rmcp::Peer<rmcp::RoleServer>>>>,
    forwarder_started: Arc<AtomicBool>,
    tool_router: ToolRouter<Self>,
}

impl<S, B> RaymonMcp<S, B>
where
    S: StateStore + Clone + Send + Sync + 'static,
    S::Error: Display + Send + Sync + 'static,
    B: EventBus + Clone + Send + Sync + 'static,
    B::Error: Display + Send + Sync + 'static,
    B::Subscription: EventStream + Send + 'static,
{
    pub fn new(state: S, bus: B) -> Self {
        Self {
            state,
            bus,
            shutdown: None,
            max_query_len: DEFAULT_MAX_QUERY_LEN,
            peers: Arc::new(RwLock::new(Vec::new())),
            forwarder_started: Arc::new(AtomicBool::new(false)),
            tool_router: Self::tool_router(),
        }
    }

    pub fn new_with_shutdown(state: S, bus: B, shutdown: broadcast::Sender<()>) -> Self {
        Self {
            state,
            bus,
            shutdown: Some(shutdown),
            max_query_len: DEFAULT_MAX_QUERY_LEN,
            peers: Arc::new(RwLock::new(Vec::new())),
            forwarder_started: Arc::new(AtomicBool::new(false)),
            tool_router: Self::tool_router(),
        }
    }

    pub fn new_with_shutdown_and_limits(
        state: S,
        bus: B,
        shutdown: broadcast::Sender<()>,
        max_query_len: usize,
    ) -> Self {
        Self {
            state,
            bus,
            shutdown: Some(shutdown),
            max_query_len: max_query_len.max(1),
            peers: Arc::new(RwLock::new(Vec::new())),
            forwarder_started: Arc::new(AtomicBool::new(false)),
            tool_router: Self::tool_router(),
        }
    }

    pub fn start_event_forwarder(&self) -> Result<(), McpInitError> {
        if self.forwarder_started.swap(true, Ordering::SeqCst) {
            return Ok(());
        }

        let mut subscription =
            self.bus.subscribe().map_err(|err| McpInitError::EventBus(err.to_string()))?;
        let peers = self.peers.clone();
        let handle = tokio::runtime::Handle::try_current().map_err(|_| McpInitError::NoRuntime)?;

        handle.spawn(async move {
            while let Some(event) = subscription.recv().await {
                let notification = event_to_notification(event);
                broadcast_notification(&peers, notification).await;
            }
        });

        Ok(())
    }

    pub fn streamable_http_service(
        state: S,
        bus: B,
    ) -> Result<RaymonMcpService<S, B>, McpInitError> {
        Self::streamable_http_service_with_config(state, bus, StreamableHttpServerConfig::default())
    }

    pub fn streamable_http_service_with_shutdown(
        state: S,
        bus: B,
        shutdown: broadcast::Sender<()>,
    ) -> Result<RaymonMcpService<S, B>, McpInitError> {
        let handler = RaymonMcp::new_with_shutdown(state, bus, shutdown);
        handler.start_event_forwarder()?;
        Ok(StreamableHttpService::new(
            move || Ok(handler.clone()),
            Default::default(),
            StreamableHttpServerConfig::default(),
        ))
    }

    pub fn streamable_http_service_with_shutdown_and_limits(
        state: S,
        bus: B,
        shutdown: broadcast::Sender<()>,
        max_query_len: usize,
    ) -> Result<RaymonMcpService<S, B>, McpInitError> {
        let handler = RaymonMcp::new_with_shutdown_and_limits(state, bus, shutdown, max_query_len);
        handler.start_event_forwarder()?;
        Ok(StreamableHttpService::new(
            move || Ok(handler.clone()),
            Default::default(),
            StreamableHttpServerConfig::default(),
        ))
    }

    pub fn streamable_http_service_with_config(
        state: S,
        bus: B,
        config: StreamableHttpServerConfig,
    ) -> Result<RaymonMcpService<S, B>, McpInitError> {
        let handler = RaymonMcp::new(state, bus);
        handler.start_event_forwarder()?;
        Ok(StreamableHttpService::new(move || Ok(handler.clone()), Default::default(), config))
    }

    async fn register_peer(&self, peer: rmcp::Peer<rmcp::RoleServer>) {
        let mut peers = self.peers.write().await;
        prune_closed_peers(&mut peers);
        peers.push(peer);
        enforce_peer_cap(&mut peers, MAX_MCP_PEERS);
    }

    fn map_filters(params: &ListEntriesParams) -> Filters {
        let mut filters = Filters::default();
        filters.query = params.query.clone();
        filters.types = params.types.clone();
        filters.colors = params.colors.clone();
        filters.screen = params.screen.as_ref().map(|value| Screen::new(value.clone()));
        filters.project = params.project.clone();
        filters.host = params.host.clone();
        filters
    }

    fn state_error(error: S::Error) -> McpError {
        if let Some(filter_error) =
            (&error as &dyn Any).downcast_ref::<crate::raymon_core::FilterError>()
        {
            match filter_error {
                crate::raymon_core::FilterError::InvalidRegex { pattern, message } => {
                    return McpError::invalid_params(
                        format!("invalid regex pattern `{pattern}`: {message}"),
                        None,
                    );
                }
            }
        }
        McpError::internal_error(format!("state store error: {error}"), None)
    }

    fn bus_error(error: B::Error) -> McpError {
        McpError::internal_error(format!("event bus error: {error}"), None)
    }

    async fn emit_notification(&self, notification: ServerNotification) {
        broadcast_notification(&self.peers, notification).await;
    }

    fn maybe_quit(&self, method: &str) {
        if !matches!(method, "ray/quit" | "ray/exit" | "raymon/quit" | "raymon/exit") {
            return;
        }
        if let Some(shutdown) = &self.shutdown {
            let _ = shutdown.send(());
        }
    }
}

#[tool_router]
impl<S, B> RaymonMcp<S, B>
where
    S: StateStore + Clone + Send + Sync + 'static,
    S::Error: Display + Send + Sync + 'static,
    B: EventBus + Clone + Send + Sync + 'static,
    B::Error: Display + Send + Sync + 'static,
    B::Subscription: EventStream + Send + 'static,
{
    #[tool(name = "ray.list_entries", description = "List entries using Raymon filters")]
    async fn list_entries(
        &self,
        Parameters(params): Parameters<ListEntriesParams>,
    ) -> Result<Json<ListEntriesResult>, McpError> {
        if let Some(query) = params.query.as_ref() {
            if query.len() > self.max_query_len {
                return Err(McpError::invalid_params(
                    format!("query too long ({} bytes > max {})", query.len(), self.max_query_len),
                    None,
                ));
            }
        }
        let (limit, offset) = normalize_pagination(params.limit, params.offset);
        let mut filters = Self::map_filters(&params);
        filters.limit = Some(limit);
        filters.offset = offset;
        let entries = self.state.list_entries(&filters).map_err(Self::state_error)?;
        let summaries = entries.into_iter().map(EntrySummary::from).collect::<Vec<_>>();
        Ok(Json(ListEntriesResult { entries: summaries, limit, offset }))
    }

    #[tool(name = "ray.get_entry", description = "Fetch a single entry by UUID")]
    async fn get_entry(
        &self,
        Parameters(params): Parameters<GetEntryParams>,
    ) -> Result<Json<GetEntryResult>, McpError> {
        let entry = self.state.get_entry(&params.uuid).map_err(Self::state_error)?;
        let entry = entry.map(McpEntry::from);
        Ok(Json(GetEntryResult { entry }))
    }

    #[tool(name = "ray.list_screens", description = "List screens available in state")]
    async fn list_screens(&self) -> Result<Json<ListScreensResult>, McpError> {
        let screens = self.state.list_screens().map_err(Self::state_error)?;
        Ok(Json(ListScreensResult {
            screens: screens.into_iter().map(|screen| screen.as_str().to_string()).collect(),
        }))
    }

    #[tool(name = "ray.emit", description = "Emit a local action into the MCP event stream")]
    async fn emit(
        &self,
        Parameters(params): Parameters<EmitParams>,
    ) -> Result<Json<EmitResult>, McpError> {
        if let Some(event) = map_emit_to_core_event(&params)? {
            self.bus.emit(event).map_err(Self::bus_error)?;
        }

        let notification = ServerNotification::CustomNotification(CustomNotification::new(
            "ray/emit",
            Some(json!({ "type": params.event_type, "data": params.data })),
        ));
        self.emit_notification(notification).await;

        Ok(Json(EmitResult { ok: true }))
    }

    #[tool(name = "ray.clear_screen", description = "Clear entries for a screen")]
    async fn clear_screen(
        &self,
        Parameters(params): Parameters<ClearScreenParams>,
    ) -> Result<Json<ClearResult>, McpError> {
        let screen = Screen::new(params.screen);
        let mut state = self.state.clone();
        state.clear_screen(&screen).map_err(Self::state_error)?;
        self.bus.emit(Event::ScreenCleared(screen)).map_err(Self::bus_error)?;
        Ok(Json(ClearResult { ok: true }))
    }

    #[tool(name = "ray.clear_all", description = "Clear all entries")]
    async fn clear_all(&self) -> Result<Json<ClearResult>, McpError> {
        let mut state = self.state.clone();
        state.clear_all().map_err(Self::state_error)?;
        self.bus.emit(Event::StateCleared).map_err(Self::bus_error)?;
        Ok(Json(ClearResult { ok: true }))
    }
}

#[tool_handler]
impl<S, B> ServerHandler for RaymonMcp<S, B>
where
    S: StateStore + Clone + Send + Sync + 'static,
    S::Error: Display + Send + Sync + 'static,
    B: EventBus + Clone + Send + Sync + 'static,
    B::Error: Display + Send + Sync + 'static,
    B::Subscription: EventStream + Send + 'static,
{
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Raymon MCP server".to_string()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        if context.peer.peer_info().is_none() {
            context.peer.set_peer_info(request);
        }
        self.register_peer(context.peer.clone()).await;
        Ok(self.get_info())
    }

    fn on_custom_notification(
        &self,
        notification: CustomNotification,
        _context: rmcp::service::NotificationContext<rmcp::RoleServer>,
    ) -> impl Future<Output = ()> + Send + '_ {
        let method = notification.method;
        async move {
            self.maybe_quit(&method);
        }
    }

    fn on_custom_request(
        &self,
        request: CustomRequest,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> impl Future<Output = Result<CustomResult, McpError>> + Send + '_ {
        let method = request.method;
        async move {
            self.maybe_quit(&method);
            Ok(CustomResult::new(json!({ "ok": true })))
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct ListEntriesParams {
    query: Option<String>,
    types: Vec<String>,
    colors: Vec<String>,
    screen: Option<String>,
    project: Option<String>,
    host: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetEntryParams {
    uuid: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct EmitParams {
    #[serde(rename = "type", alias = "event", alias = "name")]
    event_type: String,
    #[serde(default)]
    data: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ClearScreenParams {
    screen: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListEntriesResult {
    entries: Vec<EntrySummary>,
    limit: usize,
    offset: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GetEntryResult {
    entry: Option<McpEntry>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListScreensResult {
    screens: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EmitResult {
    ok: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ClearResult {
    ok: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EntrySummary {
    uuid: String,
    received_at: u64,
    project: String,
    host: String,
    screen: String,
    payload_count: usize,
    payload_types: Vec<String>,
}

impl From<crate::raymon_core::Entry> for EntrySummary {
    fn from(entry: crate::raymon_core::Entry) -> Self {
        let mut payload_types = Vec::new();
        for payload in &entry.payloads {
            if !payload_types.iter().any(|value| value == &payload.r#type) {
                payload_types.push(payload.r#type.clone());
            }
        }
        Self {
            uuid: entry.uuid,
            received_at: entry.received_at,
            project: entry.project,
            host: entry.host,
            screen: entry.screen.as_str().to_string(),
            payload_count: entry.payloads.len(),
            payload_types,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct McpEntry {
    uuid: String,
    received_at: u64,
    project: String,
    host: String,
    screen: String,
    session_id: Option<String>,
    payloads: Vec<McpPayload>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct McpPayload {
    r#type: String,
    content: Value,
    origin: McpOrigin,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct McpOrigin {
    project: String,
    host: String,
    screen: Option<String>,
    session_id: Option<String>,
    function_name: Option<String>,
    file: Option<String>,
    line_number: Option<u32>,
}

impl From<crate::raymon_core::Entry> for McpEntry {
    fn from(entry: crate::raymon_core::Entry) -> Self {
        Self {
            uuid: entry.uuid,
            received_at: entry.received_at,
            project: entry.project,
            host: entry.host,
            screen: entry.screen.as_str().to_string(),
            session_id: entry.session_id.map(|value| value.0),
            payloads: entry.payloads.into_iter().map(McpPayload::from).collect(),
        }
    }
}

impl From<crate::raymon_core::Payload> for McpPayload {
    fn from(payload: crate::raymon_core::Payload) -> Self {
        Self {
            r#type: payload.r#type,
            content: payload.content,
            origin: McpOrigin::from(payload.origin),
        }
    }
}

impl From<crate::raymon_core::Origin> for McpOrigin {
    fn from(origin: crate::raymon_core::Origin) -> Self {
        Self {
            project: origin.project,
            host: origin.host,
            screen: origin.screen.map(|screen| screen.as_str().to_string()),
            session_id: origin.session_id.map(|value| value.0),
            function_name: origin.function_name,
            file: origin.file,
            line_number: origin.line_number,
        }
    }
}

fn map_emit_to_core_event(params: &EmitParams) -> Result<Option<Event>, McpError> {
    match params.event_type.as_str() {
        "entry_inserted" => {
            let data = params.data.clone().ok_or_else(|| {
                McpError::invalid_params("missing entry_inserted data".to_string(), None)
            })?;
            let entry = serde_json::from_value(data).map_err(|err| {
                McpError::invalid_params(format!("invalid entry_inserted data: {err}"), None)
            })?;
            Ok(Some(Event::EntryInserted(entry)))
        }
        "entry_updated" => {
            let data = params.data.clone().ok_or_else(|| {
                McpError::invalid_params("missing entry_updated data".to_string(), None)
            })?;
            let entry = serde_json::from_value(data).map_err(|err| {
                McpError::invalid_params(format!("invalid entry_updated data: {err}"), None)
            })?;
            Ok(Some(Event::EntryUpdated(entry)))
        }
        "screen_cleared" => {
            let data = params.data.clone().ok_or_else(|| {
                McpError::invalid_params("missing screen_cleared data".to_string(), None)
            })?;
            let screen = match data {
                Value::String(value) => Screen::new(value),
                other => {
                    return Err(McpError::invalid_params(
                        format!("invalid screen_cleared data: {other}"),
                        None,
                    ))
                }
            };
            Ok(Some(Event::ScreenCleared(screen)))
        }
        "state_cleared" => Ok(Some(Event::StateCleared)),
        _ => Ok(None),
    }
}

fn normalize_pagination(limit: Option<usize>, offset: Option<usize>) -> (usize, usize) {
    let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);
    let offset = offset.unwrap_or(0);
    (limit, offset)
}

fn event_to_notification(event: Event) -> ServerNotification {
    let payload = match event {
        Event::EntryInserted(entry) => json!({ "type": "entry_inserted", "entry": entry }),
        Event::EntryUpdated(entry) => json!({ "type": "entry_updated", "entry": entry }),
        Event::ScreenCleared(screen) => json!({ "type": "screen_cleared", "screen": screen }),
        Event::StateCleared => json!({ "type": "state_cleared" }),
    };
    ServerNotification::CustomNotification(CustomNotification::new("ray/event", Some(payload)))
}

async fn broadcast_notification(
    peers: &Arc<RwLock<Vec<rmcp::Peer<rmcp::RoleServer>>>>,
    notification: ServerNotification,
) {
    let peers_snapshot = peers.read().await.clone();
    let mut had_error = false;

    for peer in peers_snapshot {
        if peer.send_notification(notification.clone()).await.is_err() {
            had_error = true;
        }
    }

    if had_error {
        let mut peers = peers.write().await;
        prune_closed_peers(&mut peers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raymon_core::{types::default_screen_name, Entry, Origin, Payload};
    use rmcp::handler::server::common::schema_for_type;
    use rmcp::model::ErrorCode;
    use serde_json::json;
    use std::sync::Mutex;

    #[derive(Clone, Debug)]
    struct MockPeer {
        closed: bool,
    }

    impl PeerHealth for MockPeer {
        fn transport_closed(&self) -> bool {
            self.closed
        }
    }

    #[derive(Debug, Clone)]
    struct TestError(String);

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for TestError {}

    #[test]
    fn prune_closed_peers_removes_closed_entries() {
        let mut peers = vec![
            MockPeer { closed: false },
            MockPeer { closed: true },
            MockPeer { closed: false },
        ];

        prune_closed_peers(&mut peers);

        assert_eq!(peers.len(), 2);
        assert!(peers.iter().all(|peer| !peer.closed));
    }

    #[test]
    fn enforce_peer_cap_evicts_oldest_entries() {
        let mut peers = vec![1, 2, 3, 4];
        enforce_peer_cap(&mut peers, 2);
        assert_eq!(peers, vec![3, 4]);
    }

    #[derive(Clone)]
    struct TestStore {
        entries: Vec<Entry>,
        screens: Vec<Screen>,
        last_filters: Arc<Mutex<Option<Filters>>>,
    }

    impl StateStore for TestStore {
        type Error = TestError;

        fn insert_entry(&mut self, _entry: Entry) -> Result<(), Self::Error> {
            Ok(())
        }

        fn update_entry(&mut self, _entry: Entry) -> Result<(), Self::Error> {
            Ok(())
        }

        fn get_entry(&self, uuid: &str) -> Result<Option<Entry>, Self::Error> {
            Ok(self.entries.iter().find(|entry| entry.uuid == uuid).cloned())
        }

        fn list_entries(&self, filters: &Filters) -> Result<Vec<Entry>, Self::Error> {
            *self.last_filters.lock().unwrap() = Some(filters.clone());
            let filtered =
                filters.apply(self.entries.iter()).map_err(|err| TestError(err.to_string()))?;
            Ok(filtered.into_iter().cloned().collect())
        }

        fn list_screens(&self) -> Result<Vec<Screen>, Self::Error> {
            Ok(self.screens.clone())
        }

        fn clear_screen(&mut self, _screen: &Screen) -> Result<(), Self::Error> {
            Ok(())
        }

        fn clear_all(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestBus {
        sender: broadcast::Sender<Event>,
        emitted: Arc<Mutex<Vec<Event>>>,
    }

    impl TestBus {
        fn new() -> Self {
            let (sender, _) = broadcast::channel(16);
            Self { sender, emitted: Arc::new(Mutex::new(Vec::new())) }
        }

        fn emitted(&self) -> Vec<Event> {
            self.emitted.lock().unwrap().clone()
        }
    }

    impl EventBus for TestBus {
        type Error = TestError;
        type Subscription = broadcast::Receiver<Event>;

        fn emit(&self, event: Event) -> Result<(), Self::Error> {
            self.emitted.lock().unwrap().push(event.clone());
            let _ = self.sender.send(event);
            Ok(())
        }

        fn subscribe(&self) -> Result<Self::Subscription, Self::Error> {
            Ok(self.sender.subscribe())
        }
    }

    fn sample_entry(uuid: &str) -> Entry {
        let origin = Origin {
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: None,
            session_id: None,
            function_name: None,
            file: None,
            line_number: None,
        };
        let payload =
            Payload { r#type: "note".to_string(), content: json!({"message": "alpha"}), origin };
        Entry {
            uuid: uuid.to_string(),
            received_at: 1,
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: default_screen_name("proj", "host"),
            session_id: None,
            payloads: vec![payload],
        }
    }

    #[tokio::test]
    async fn list_entries_maps_filters() {
        let store = TestStore {
            entries: vec![sample_entry("one")],
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store.clone(), bus);

        let params = ListEntriesParams {
            query: Some("alpha".to_string()),
            screen: Some("main".to_string()),
            limit: Some(10),
            offset: Some(2),
            ..Default::default()
        };

        handler.list_entries(Parameters(params)).await.expect("list_entries should succeed");

        let filters = store.last_filters.lock().unwrap().clone().expect("filters captured");
        assert_eq!(filters.query, Some("alpha".to_string()));
        assert_eq!(filters.screen, Some(Screen::new("main")));
        assert_eq!(filters.limit, Some(10));
        assert_eq!(filters.offset, 2);
    }

    #[tokio::test]
    async fn emit_maps_core_event_when_known() {
        let store = TestStore {
            entries: vec![sample_entry("one")],
            screens: Vec::new(),
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store, bus.clone());

        let entry = sample_entry("emit");
        let params = EmitParams {
            event_type: "entry_inserted".to_string(),
            data: Some(serde_json::to_value(&entry).unwrap()),
        };

        handler.emit(Parameters(params)).await.unwrap();
        assert_eq!(bus.emitted().len(), 1);
    }

    #[tokio::test]
    async fn list_entries_enforces_default_limit_and_summary() {
        let entries = (0..120)
            .map(|idx| {
                let uuid = format!("entry-{idx}");
                let origin = Origin {
                    project: "proj".to_string(),
                    host: "host".to_string(),
                    screen: None,
                    session_id: None,
                    function_name: None,
                    file: None,
                    line_number: None,
                };
                let payload_a = Payload {
                    r#type: "note".to_string(),
                    content: json!({"message": "alpha"}),
                    origin: origin.clone(),
                };
                let payload_b = Payload {
                    r#type: "log".to_string(),
                    content: json!({"message": "beta"}),
                    origin,
                };
                Entry {
                    uuid,
                    received_at: idx as u64,
                    project: "proj".to_string(),
                    host: "host".to_string(),
                    screen: default_screen_name("proj", "host"),
                    session_id: None,
                    payloads: vec![payload_a, payload_b],
                }
            })
            .collect::<Vec<_>>();

        let store = TestStore {
            entries,
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store, bus);

        let params = ListEntriesParams::default();
        let result = handler.list_entries(Parameters(params)).await.unwrap();
        assert_eq!(result.0.entries.len(), DEFAULT_LIST_LIMIT);
        let first = result.0.entries.first().expect("first entry");
        assert!(first.payload_count > 0);
        assert!(!first.payload_types.is_empty());
    }

    #[tokio::test]
    async fn invalid_regex_maps_to_invalid_params() {
        #[derive(Clone)]
        struct RegexStore;

        impl StateStore for RegexStore {
            type Error = crate::raymon_core::FilterError;

            fn insert_entry(&mut self, _entry: Entry) -> Result<(), Self::Error> {
                Ok(())
            }

            fn update_entry(&mut self, _entry: Entry) -> Result<(), Self::Error> {
                Ok(())
            }

            fn get_entry(&self, _uuid: &str) -> Result<Option<Entry>, Self::Error> {
                Ok(None)
            }

            fn list_entries(&self, _filters: &Filters) -> Result<Vec<Entry>, Self::Error> {
                Err(crate::raymon_core::FilterError::InvalidRegex {
                    pattern: "(".to_string(),
                    message: "unclosed group".to_string(),
                })
            }

            fn list_screens(&self) -> Result<Vec<Screen>, Self::Error> {
                Ok(Vec::new())
            }

            fn clear_screen(&mut self, _screen: &Screen) -> Result<(), Self::Error> {
                Ok(())
            }

            fn clear_all(&mut self) -> Result<(), Self::Error> {
                Ok(())
            }
        }

        let store = RegexStore;
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store, bus);

        let params = ListEntriesParams { query: Some("(/".to_string()), ..Default::default() };
        let result = handler.list_entries(Parameters(params)).await;

        let error = match result {
            Ok(_) => panic!("expected invalid params error"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn schemas_are_generated_for_tools() {
        let _ = schema_for_type::<ListEntriesParams>();
        let _ = schema_for_type::<GetEntryParams>();
        let _ = schema_for_type::<EmitParams>();
        let _ = schema_for_type::<ClearScreenParams>();
        let _ = schema_for_type::<ListEntriesResult>();
        let _ = schema_for_type::<GetEntryResult>();
        let _ = schema_for_type::<ListScreensResult>();
        let _ = schema_for_type::<EmitResult>();
        let _ = schema_for_type::<ClearResult>();
    }
}
