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
    handler::server::wrapper::Parameters,
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
const MAX_SEARCH_SCAN_ENTRIES: usize = 5_000;
const MAX_GET_ENTRIES_UUIDS: usize = 100;
const MAX_GET_ENTRIES_UUID_BYTES: usize = 265;
const MAX_GET_ENTRIES_RESPONSE_BYTES: usize = 1024 * 1024;
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
/// Errors that can occur while initializing the MCP server.
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

/// Raymon MCP server handler.
///
/// This type wires together a [`StateStore`] and [`EventBus`] to expose Raymon tools over MCP and
/// forwards internal [`Event`]s as MCP notifications to connected peers.
#[derive(Clone)]
pub struct RaymonMcp<S, B> {
    state: S,
    bus: B,
    shutdown: Option<broadcast::Sender<()>>,
    allow_shutdown_methods: bool,
    max_query_len: usize,
    peers: Arc<RwLock<Vec<rmcp::Peer<rmcp::RoleServer>>>>,
    forwarder_started: Arc<AtomicBool>,
}

impl<S, B> RaymonMcp<S, B>
where
    S: StateStore + Clone + Send + Sync + 'static,
    S::Error: Display + Send + Sync + 'static,
    B: EventBus + Clone + Send + Sync + 'static,
    B::Error: Display + Send + Sync + 'static,
    B::Subscription: EventStream + Send + 'static,
{
    /// Create a handler with default limits and without a shutdown channel.
    pub fn new(state: S, bus: B) -> Self {
        Self {
            state,
            bus,
            shutdown: None,
            allow_shutdown_methods: false,
            max_query_len: DEFAULT_MAX_QUERY_LEN,
            peers: Arc::new(RwLock::new(Vec::new())),
            forwarder_started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a handler that will also listen to a shutdown broadcast channel.
    pub fn new_with_shutdown(state: S, bus: B, shutdown: broadcast::Sender<()>) -> Self {
        Self {
            state,
            bus,
            shutdown: Some(shutdown),
            allow_shutdown_methods: false,
            max_query_len: DEFAULT_MAX_QUERY_LEN,
            peers: Arc::new(RwLock::new(Vec::new())),
            forwarder_started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Create a handler with a shutdown channel and an explicit maximum query length.
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
            allow_shutdown_methods: false,
            max_query_len: max_query_len.max(1),
            peers: Arc::new(RwLock::new(Vec::new())),
            forwarder_started: Arc::new(AtomicBool::new(false)),
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

    pub fn streamable_http_service_with_shutdown_and_limits_and_shutdown_methods(
        state: S,
        bus: B,
        shutdown: broadcast::Sender<()>,
        max_query_len: usize,
        allow_shutdown_methods: bool,
    ) -> Result<RaymonMcpService<S, B>, McpInitError> {
        let handler = RaymonMcp::new_with_shutdown_and_limits(state, bus, shutdown, max_query_len)
            .with_shutdown_methods(allow_shutdown_methods);
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

    pub fn with_shutdown_methods(mut self, allow_shutdown_methods: bool) -> Self {
        self.allow_shutdown_methods = allow_shutdown_methods;
        self
    }

    fn map_filters(params: &ListEntriesParams) -> Filters {
        Filters {
            query: params.query.clone(),
            types: params.types.to_vec(),
            colors: params.colors.to_vec(),
            screen: params.screen.as_ref().map(|value| Screen::new(value.clone())),
            project: params.project.clone(),
            host: params.host.clone(),
            ..Default::default()
        }
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

    fn is_shutdown_method(method: &str) -> bool {
        matches!(method, "ray/quit" | "ray/exit" | "raymon/quit" | "raymon/exit")
    }

    fn maybe_quit(&self, method: &str) -> bool {
        if !Self::is_shutdown_method(method) || !self.allow_shutdown_methods {
            return false;
        }
        if let Some(shutdown) = &self.shutdown {
            let _ = shutdown.send(());
        }
        true
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
    #[tool(
        name = "raymon.search",
        description = "Search entries using Raymon filters",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn search(
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
        filters.scan_limit = Some(MAX_SEARCH_SCAN_ENTRIES);
        let (entries, count) =
            self.state.list_entries_with_count(&filters).map_err(Self::state_error)?;
        let summaries = entries.into_iter().map(EntrySummary::from).collect::<Vec<_>>();
        Ok(Json(ListEntriesResult {
            entries: summaries,
            count,
            limit,
            offset,
            scan_limit: MAX_SEARCH_SCAN_ENTRIES,
        }))
    }

    #[tool(
        name = "raymon.get_entries",
        description = "Fetch entries by UUID",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn get_entries(
        &self,
        Parameters(params): Parameters<GetEntriesParams>,
    ) -> Result<Json<GetEntriesResult>, McpError> {
        let uuids = normalize_get_entry_uuids(params.uuids)?;

        let mut entries = Vec::new();
        for uuid in uuids {
            let entry = self.state.get_entry(&uuid).map_err(Self::state_error)?;
            if let Some(entry) = entry {
                entries.push(McpEntry::from(entry));
                let result = GetEntriesResult { entries: entries.clone() };
                let response_bytes = get_entries_tool_result_bytes(&result)?;
                if response_bytes > MAX_GET_ENTRIES_RESPONSE_BYTES {
                    return Err(McpError::invalid_params(
                        format!(
                            "get_entries response too large ({} bytes > max {})",
                            response_bytes, MAX_GET_ENTRIES_RESPONSE_BYTES
                        ),
                        None,
                    ));
                }
            }
        }

        Ok(Json(GetEntriesResult { entries }))
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
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Raymon MCP server")
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
            if RaymonMcp::<S, B>::is_shutdown_method(&method) && !self.allow_shutdown_methods {
                return Err(McpError::invalid_request("mcp shutdown methods are disabled", None));
            }
            self.maybe_quit(&method);
            Ok(CustomResult::new(json!({ "ok": true })))
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct ListEntriesParams {
    query: Option<String>,
    types: StringListSelector,
    colors: StringListSelector,
    screen: Option<String>,
    project: Option<String>,
    host: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum StringListSelector {
    One(String),
    Many(Vec<String>),
}

impl Default for StringListSelector {
    fn default() -> Self {
        Self::Many(Vec::new())
    }
}

impl StringListSelector {
    fn to_vec(&self) -> Vec<String> {
        match self {
            Self::One(value) => comma_separated_values(value),
            Self::Many(values) => values.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(untagged)]
pub enum UuidSelector {
    One(String),
    Many(Vec<String>),
}

impl UuidSelector {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(uuid) if uuid.contains(',') => {
                uuid.split(',').map(compact_uuid_segment).collect()
            }
            Self::One(uuid) => vec![uuid.trim().to_string()],
            Self::Many(uuids) => uuids,
        }
    }
}

fn comma_separated_values(value: &str) -> Vec<String> {
    value.split(',').map(|segment| segment.trim().to_string()).collect()
}

fn compact_uuid_segment(uuid: &str) -> String {
    uuid.chars().filter(|ch| !ch.is_whitespace()).collect()
}

fn normalize_get_entry_uuids(selector: UuidSelector) -> Result<Vec<String>, McpError> {
    let uuids = selector.into_vec();
    if uuids.is_empty() {
        return Err(McpError::invalid_params("uuids must not be empty".to_string(), None));
    }
    if uuids.len() > MAX_GET_ENTRIES_UUIDS {
        return Err(McpError::invalid_params(
            format!("too many uuids ({} > max {})", uuids.len(), MAX_GET_ENTRIES_UUIDS),
            None,
        ));
    }

    let mut normalized = Vec::with_capacity(uuids.len());
    for uuid in uuids {
        let uuid = uuid.trim().to_string();
        if uuid.is_empty() {
            return Err(McpError::invalid_params("uuid must not be empty".to_string(), None));
        }
        if uuid.len() > MAX_GET_ENTRIES_UUID_BYTES {
            return Err(McpError::invalid_params(
                format!(
                    "uuid too long ({} bytes > max {})",
                    uuid.len(),
                    MAX_GET_ENTRIES_UUID_BYTES
                ),
                None,
            ));
        }
        normalized.push(uuid);
    }

    Ok(normalized)
}

fn get_entries_tool_result_bytes(result: &GetEntriesResult) -> Result<usize, McpError> {
    let value = serde_json::to_value(result).map_err(|error| {
        McpError::internal_error(format!("failed to serialize get_entries result: {error}"), None)
    })?;
    let tool_result = rmcp::model::CallToolResult::structured(value);
    serde_json::to_vec(&tool_result).map(|bytes| bytes.len()).map_err(|error| {
        McpError::internal_error(
            format!("failed to serialize get_entries tool result: {error}"),
            None,
        )
    })
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetEntriesParams {
    #[serde(alias = "uuid")]
    uuids: UuidSelector,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListEntriesResult {
    entries: Vec<EntrySummary>,
    count: usize,
    limit: usize,
    offset: usize,
    scan_limit: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct GetEntriesResult {
    entries: Vec<McpEntry>,
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

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct McpEntry {
    uuid: String,
    received_at: u64,
    project: String,
    host: String,
    screen: String,
    session_id: Option<String>,
    payloads: Vec<McpPayload>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct McpPayload {
    r#type: String,
    content: Value,
    origin: McpOrigin,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
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

fn normalize_pagination(limit: Option<usize>, offset: Option<usize>) -> (usize, usize) {
    let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT).min(MAX_LIST_LIMIT);
    let offset = offset.unwrap_or(0).min(MAX_SEARCH_SCAN_ENTRIES);
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
    use rmcp::model::{ErrorCode, Tool};
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
        let mut peers =
            vec![MockPeer { closed: false }, MockPeer { closed: true }, MockPeer { closed: false }];

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

    #[test]
    fn shutdown_methods_are_disabled_by_default() {
        let store = TestStore {
            entries: Vec::new(),
            screens: Vec::new(),
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);
        let handler = RaymonMcp::new_with_shutdown(store, bus, shutdown_tx);

        assert!(!handler.maybe_quit("ray/quit"));
        assert!(shutdown_rx.try_recv().is_err());
    }

    #[test]
    fn shutdown_methods_require_explicit_enablement() {
        let store = TestStore {
            entries: Vec::new(),
            screens: Vec::new(),
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel(1);
        let handler =
            RaymonMcp::new_with_shutdown(store, bus, shutdown_tx).with_shutdown_methods(true);

        assert!(handler.maybe_quit("raymon/exit"));
        assert!(shutdown_rx.try_recv().is_ok());
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
    async fn search_maps_filters() {
        let store = TestStore {
            entries: vec![sample_entry("one")],
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let bus_handle = bus.clone();
        let handler = RaymonMcp::new(store.clone(), bus);

        let params: ListEntriesParams = serde_json::from_value(json!({
            "query": "alpha",
            "types": ["note"],
            "colors": "red, blue",
            "screen": "main",
            "limit": 10,
            "offset": 2
        }))
        .expect("search params should deserialize");

        handler.search(Parameters(params)).await.expect("search should succeed");

        let filters = store.last_filters.lock().unwrap().clone().expect("filters captured");
        assert_eq!(filters.query, Some("alpha".to_string()));
        assert_eq!(filters.types, vec!["note"]);
        assert_eq!(filters.colors, vec!["red", "blue"]);
        assert_eq!(filters.screen, Some(Screen::new("main")));
        assert_eq!(filters.limit, Some(10));
        assert_eq!(filters.offset, 2);
        assert_eq!(filters.scan_limit, Some(MAX_SEARCH_SCAN_ENTRIES));
        assert!(bus_handle.emitted().is_empty());
    }

    #[tokio::test]
    async fn search_enforces_default_limit_and_summary() {
        let total_entries = 120usize;
        let entries = (0..total_entries)
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
        let result = handler.search(Parameters(params)).await.unwrap();
        assert_eq!(result.0.count, total_entries);
        assert_eq!(result.0.entries.len(), DEFAULT_LIST_LIMIT);
        let first = result.0.entries.first().expect("first entry");
        assert!(first.payload_count > 0);
        assert!(!first.payload_types.is_empty());
    }

    #[tokio::test]
    async fn search_bounds_count_scan_work() {
        let total_entries = MAX_SEARCH_SCAN_ENTRIES + 25;
        let entries =
            (0..total_entries).map(|idx| sample_entry(&format!("entry-{idx}"))).collect::<Vec<_>>();
        let store = TestStore {
            entries,
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store.clone(), bus);

        let result = handler.search(Parameters(ListEntriesParams::default())).await.unwrap();

        assert_eq!(result.0.count, MAX_SEARCH_SCAN_ENTRIES);
        assert_eq!(result.0.entries.len(), DEFAULT_LIST_LIMIT);
        assert_eq!(result.0.scan_limit, MAX_SEARCH_SCAN_ENTRIES);

        let filters = store.last_filters.lock().unwrap().clone().expect("filters captured");
        assert_eq!(filters.scan_limit, Some(MAX_SEARCH_SCAN_ENTRIES));
    }

    #[tokio::test]
    async fn get_entries_accepts_comma_separated_uuid_string() {
        let store = TestStore {
            entries: vec![
                sample_entry("entry-1"),
                sample_entry("entry-2"),
                sample_entry("entry-3"),
            ],
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store, bus);

        let params: GetEntriesParams = serde_json::from_value(json!({
            "uuids": "entry-1, entry-\n 3"
        }))
        .expect("get entries params should deserialize");

        let result = handler.get_entries(Parameters(params)).await.unwrap();
        let uuids = result.0.entries.into_iter().map(|entry| entry.uuid).collect::<Vec<_>>();

        assert_eq!(uuids, vec!["entry-1", "entry-3"]);
    }

    #[tokio::test]
    async fn get_entries_rejects_too_many_uuids() {
        let store = TestStore {
            entries: Vec::new(),
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store, bus);
        let params = GetEntriesParams {
            uuids: UuidSelector::Many(
                (0..=MAX_GET_ENTRIES_UUIDS).map(|idx| format!("entry-{idx}")).collect(),
            ),
        };

        let error = match handler.get_entries(Parameters(params)).await {
            Ok(_) => panic!("expected invalid params error"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn get_entries_rejects_oversized_uuid() {
        let store = TestStore {
            entries: Vec::new(),
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store, bus);
        let params = GetEntriesParams {
            uuids: UuidSelector::Many(vec!["x".repeat(MAX_GET_ENTRIES_UUID_BYTES + 1)]),
        };

        let error = match handler.get_entries(Parameters(params)).await {
            Ok(_) => panic!("expected invalid params error"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[tokio::test]
    async fn get_entries_rejects_oversized_response() {
        let mut entry = sample_entry("entry-large");
        entry.payloads[0].content = json!({
            "message": "x".repeat(MAX_GET_ENTRIES_RESPONSE_BYTES)
        });
        let store = TestStore {
            entries: vec![entry],
            screens: vec![Screen::new("main")],
            last_filters: Arc::new(Mutex::new(None)),
        };
        let bus = TestBus::new();
        let handler = RaymonMcp::new(store, bus);
        let params =
            GetEntriesParams { uuids: UuidSelector::Many(vec!["entry-large".to_string()]) };

        let error = match handler.get_entries(Parameters(params)).await {
            Ok(_) => panic!("expected invalid params error"),
            Err(error) => error,
        };

        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
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
        let result = handler.search(Parameters(params)).await;

        let error = match result {
            Ok(_) => panic!("expected invalid params error"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn schemas_are_generated_for_tools() {
        let _ = schema_for_type::<ListEntriesParams>();
        let _ = schema_for_type::<GetEntriesParams>();
        let _ = schema_for_type::<ListEntriesResult>();
        let _ = schema_for_type::<GetEntriesResult>();
    }

    #[test]
    fn tools_are_marked_read_only() {
        assert_read_only_tool(RaymonMcp::<TestStore, TestBus>::search_tool_attr());
        assert_read_only_tool(RaymonMcp::<TestStore, TestBus>::get_entries_tool_attr());
    }

    fn assert_read_only_tool(tool: Tool) {
        let annotations = tool.annotations.expect("tool should expose annotations");
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(true));
        assert_eq!(annotations.open_world_hint, Some(false));
    }
}
