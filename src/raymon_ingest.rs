//! HTTP ingest handlers for Raymon.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::raymon_core::{Entry, Event, RayEnvelope};

/// Response returned by [`Ingestor::handle`].
///
/// `status` is an HTTP status code. `error` is a human-readable message (when present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestResponse {
    /// HTTP status code (e.g. `200`, `400`, `422`, `500`).
    pub status: u16,
    /// Human-readable error message (present for non-2xx responses).
    pub error: Option<String>,
}

impl IngestResponse {
    /// Successful ingest response.
    pub fn ok() -> Self {
        Self { status: 200, error: None }
    }

    /// Convert an [`IngestError`] into an HTTP-friendly status and message.
    pub fn from_error(error: IngestError) -> Self {
        let status = error.status_code();
        Self { status, error: Some(error.to_string()) }
    }
}

/// Errors that can occur while parsing and persisting an inbound Ray envelope.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("invalid json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("state store error: {0}")]
    StateStore(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("event bus error: {0}")]
    EventBus(String),
    #[error("entry exceeds size limit: {len} bytes > {max} bytes")]
    EntryTooLarge { len: usize, max: usize },
}

impl IngestError {
    /// Map the ingest error to an HTTP status code.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidJson(_) => 400,
            Self::EntryTooLarge { .. } => 413,
            Self::InvalidEnvelope(_) | Self::MissingField(_) => 422,
            Self::StateStore(_) | Self::Storage(_) | Self::EventBus(_) => 500,
        }
    }
}

/// Serialization guard held across the read-modify-write merge of a single UUID.
///
/// Holding the guard for the duration of the `get_entry` → merge → commit critical
/// section ensures concurrent ingests of the same UUID cannot each read pre-merge state
/// and lose payloads via last-writer-wins. The default [`StateStore::ingest_guard`] is a
/// no-op for single-writer test stores.
pub enum IngestGuard<'a> {
    Noop,
    Locked(std::sync::MutexGuard<'a, ()>),
}

/// Minimal state-store API needed by [`Ingestor`].
///
/// This trait exists to keep the ingest pipeline decoupled from concrete storage/state
/// implementations and to make testing easier.
pub trait StateStore {
    fn insert_entry(&self, entry: Entry) -> Result<(), String>;
    fn update_entry(&self, entry: Entry) -> Result<(), String>;
    fn get_entry(&self, uuid: &str) -> Result<Option<Entry>, String>;

    /// Acquire a serialization guard for the read-modify-write merge of `uuid`.
    ///
    /// Implementations that can be written from multiple threads must return a guard that
    /// serializes per UUID; the default is a no-op for single-writer stores.
    fn ingest_guard(&self, uuid: &str) -> IngestGuard<'_> {
        let _ = uuid;
        IngestGuard::Noop
    }
}

impl<T> StateStore for &T
where
    T: StateStore + ?Sized,
{
    fn insert_entry(&self, entry: Entry) -> Result<(), String> {
        (*self).insert_entry(entry)
    }

    fn update_entry(&self, entry: Entry) -> Result<(), String> {
        (*self).update_entry(entry)
    }

    fn get_entry(&self, uuid: &str) -> Result<Option<Entry>, String> {
        (*self).get_entry(uuid)
    }

    fn ingest_guard(&self, uuid: &str) -> IngestGuard<'_> {
        (*self).ingest_guard(uuid)
    }
}

/// Append-only storage API needed by [`Ingestor`].
pub trait Storage {
    fn append_entry(&self, entry: &Entry) -> Result<(), String>;
}

impl<T> Storage for &T
where
    T: Storage + ?Sized,
{
    fn append_entry(&self, entry: &Entry) -> Result<(), String> {
        (*self).append_entry(entry)
    }
}

/// Event bus API used by [`Ingestor`] to notify subscribers of state changes.
pub trait EventBus {
    fn emit(&self, event: Event) -> Result<(), String>;
}

impl<T> EventBus for &T
where
    T: EventBus + ?Sized,
{
    fn emit(&self, event: Event) -> Result<(), String> {
        (*self).emit(event)
    }
}

/// Ingest pipeline for Ray-compatible JSON envelopes.
///
/// The ingestor:
/// - Parses the request body into a [`RayEnvelope`].
/// - Validates required fields.
/// - Sanitizes payload content.
/// - Inserts or updates the entry in the [`StateStore`] and [`Storage`].
/// - Emits an [`Event`] on the [`EventBus`].
pub struct Ingestor<S, T, B, C> {
    state: S,
    storage: T,
    bus: B,
    clock: C,
    max_entry_bytes: Option<usize>,
}

impl<S, T, B, C> Ingestor<S, T, B, C>
where
    S: StateStore,
    T: Storage,
    B: EventBus,
    C: Fn() -> u64,
{
    /// Create a new ingestor.
    ///
    /// `clock` returns a `u64` timestamp in milliseconds since the UNIX epoch.
    pub fn new(state: S, storage: T, bus: B, clock: C) -> Self {
        Self { state, storage, bus, clock, max_entry_bytes: None }
    }

    /// Cap the serialized size of each stored entry.
    pub fn with_max_entry_bytes(mut self, max_entry_bytes: usize) -> Self {
        self.max_entry_bytes = Some(max_entry_bytes);
        self
    }

    /// Handle a raw HTTP request body and return an [`IngestResponse`].
    pub fn handle(&self, body: &[u8]) -> IngestResponse {
        match self.handle_inner(body) {
            Ok(_) => IngestResponse::ok(),
            Err(error) => IngestResponse::from_error(error),
        }
    }

    /// Parse and process the request body and return the resulting [`Entry`].
    pub fn handle_inner(&self, body: &[u8]) -> Result<Entry, IngestError> {
        let envelope: RayEnvelope = serde_json::from_slice(body).map_err(|err| {
            use serde_json::error::Category;

            match err.classify() {
                Category::Syntax | Category::Eof => IngestError::InvalidJson(err),
                Category::Data | Category::Io => IngestError::InvalidEnvelope(err.to_string()),
            }
        })?;
        validate_envelope(&envelope)?;

        let mut entry = envelope.into_entry((self.clock)());

        // Serialize the read-modify-write merge for this UUID so concurrent ingests of the
        // same UUID cannot each read pre-merge state and drop each other's payloads. Held
        // until the end of the function, covering get_entry through the state/storage/bus
        // commit. Distinct UUIDs (different shards) still ingest concurrently.
        let _ingest_guard = self.state.ingest_guard(&entry.uuid);

        let existing = self.state.get_entry(&entry.uuid).map_err(IngestError::StateStore)?;

        let update = if let Some(existing) = existing {
            entry = merge_entry_update(existing, entry);
            true
        } else {
            false
        };

        crate::sanitize::sanitize_entry(&mut entry);
        self.validate_entry_size(&entry)?;

        // Update core state before appending to durable storage. If the state update
        // fails (e.g. a poisoned lock), no JSONL line is written, so storage never holds
        // an entry that is invisible to live MCP/TUI queries until the next restart.
        if update {
            self.state.update_entry(entry.clone()).map_err(IngestError::StateStore)?;
            self.storage.append_entry(&entry).map_err(IngestError::Storage)?;
            self.bus.emit(Event::EntryUpdated(entry.clone())).map_err(IngestError::EventBus)?;
        } else {
            self.state.insert_entry(entry.clone()).map_err(IngestError::StateStore)?;
            self.storage.append_entry(&entry).map_err(IngestError::Storage)?;
            self.bus.emit(Event::EntryInserted(entry.clone())).map_err(IngestError::EventBus)?;
        }

        Ok(entry)
    }

    fn validate_entry_size(&self, entry: &Entry) -> Result<(), IngestError> {
        let Some(max) = self.max_entry_bytes else {
            return Ok(());
        };

        let len = serde_json::to_vec(entry)
            .map_err(|error| IngestError::InvalidEnvelope(error.to_string()))?
            .len();
        if len > max {
            return Err(IngestError::EntryTooLarge { len, max });
        }

        Ok(())
    }
}

fn merge_entry_update(existing: Entry, update: Entry) -> Entry {
    let mut payloads = existing.payloads;
    payloads.extend(update.payloads);

    let project = if existing.project.trim().is_empty() || existing.project == "unknown" {
        update.project
    } else {
        existing.project
    };
    let host = if existing.host.trim().is_empty() || existing.host == "unknown" {
        update.host
    } else {
        existing.host
    };

    Entry {
        uuid: existing.uuid,
        received_at: existing.received_at,
        project,
        host,
        screen: existing.screen,
        session_id: existing.session_id.or(update.session_id),
        payloads,
    }
}

fn validate_envelope(envelope: &RayEnvelope) -> Result<(), IngestError> {
    if envelope.uuid.trim().is_empty() {
        return Err(IngestError::MissingField("uuid"));
    }
    if envelope.payloads.is_empty() {
        return Err(IngestError::MissingField("payloads"));
    }
    for payload in &envelope.payloads {
        if payload.r#type.trim().is_empty() {
            return Err(IngestError::MissingField("payloads.type"));
        }
        if payload.origin.hostname.trim().is_empty() {
            return Err(IngestError::MissingField("payloads.origin.hostname"));
        }
    }
    Ok(())
}

/// Current time as milliseconds since the UNIX epoch.
///
/// Returns `0` if the system clock is before the UNIX epoch or otherwise fails.
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::{fixture, rstest};
    use serde_json::json;
    use serde_json::Value;
    use std::sync::Mutex;

    #[derive(Default)]
    struct TestState {
        entries: Mutex<Vec<Entry>>,
    }

    impl StateStore for TestState {
        fn insert_entry(&self, entry: Entry) -> Result<(), String> {
            self.entries.lock().map_err(|_| "state poisoned".to_string())?.push(entry);
            Ok(())
        }

        fn update_entry(&self, entry: Entry) -> Result<(), String> {
            let mut guard = self.entries.lock().map_err(|_| "state poisoned".to_string())?;
            if let Some(existing) = guard.iter_mut().find(|item| item.uuid == entry.uuid) {
                *existing = entry;
            } else {
                guard.push(entry);
            }
            Ok(())
        }

        fn get_entry(&self, uuid: &str) -> Result<Option<Entry>, String> {
            let guard = self.entries.lock().map_err(|_| "state poisoned".to_string())?;
            Ok(guard.iter().find(|entry| entry.uuid == uuid).cloned())
        }
    }

    #[derive(Default)]
    struct TestStorage {
        entries: Mutex<Vec<Entry>>,
    }

    impl Storage for TestStorage {
        fn append_entry(&self, entry: &Entry) -> Result<(), String> {
            self.entries.lock().map_err(|_| "storage poisoned".to_string())?.push(entry.clone());
            Ok(())
        }
    }

    /// A state store whose writes always fail, simulating a poisoned lock.
    #[derive(Default)]
    struct FailingState;

    impl StateStore for FailingState {
        fn insert_entry(&self, _entry: Entry) -> Result<(), String> {
            Err("state poisoned".to_string())
        }

        fn update_entry(&self, _entry: Entry) -> Result<(), String> {
            Err("state poisoned".to_string())
        }

        fn get_entry(&self, _uuid: &str) -> Result<Option<Entry>, String> {
            Ok(None)
        }
    }

    /// A shared, thread-safe state store that serializes per-UUID merges via `ingest_guard`
    /// and sleeps inside `get_entry` to widen the read-modify-write race window. Without the
    /// guard this would drop payloads under concurrent same-UUID ingest.
    struct SharedConcurrentState {
        entries: std::sync::Mutex<Vec<Entry>>,
        locks: [std::sync::Mutex<()>; 16],
        get_delay: std::time::Duration,
    }

    impl SharedConcurrentState {
        fn new(get_delay: std::time::Duration) -> Self {
            Self {
                entries: std::sync::Mutex::new(Vec::new()),
                locks: std::array::from_fn(|_| std::sync::Mutex::new(())),
                get_delay,
            }
        }
    }

    impl StateStore for SharedConcurrentState {
        fn insert_entry(&self, entry: Entry) -> Result<(), String> {
            self.entries.lock().map_err(|_| "poisoned".to_string())?.push(entry);
            Ok(())
        }

        fn update_entry(&self, entry: Entry) -> Result<(), String> {
            let mut guard = self.entries.lock().map_err(|_| "poisoned".to_string())?;
            if let Some(existing) = guard.iter_mut().find(|item| item.uuid == entry.uuid) {
                *existing = entry;
            } else {
                guard.push(entry);
            }
            Ok(())
        }

        fn get_entry(&self, uuid: &str) -> Result<Option<Entry>, String> {
            std::thread::sleep(self.get_delay);
            let guard = self.entries.lock().map_err(|_| "poisoned".to_string())?;
            Ok(guard.iter().find(|entry| entry.uuid == uuid).cloned())
        }

        fn ingest_guard(&self, uuid: &str) -> IngestGuard<'_> {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::hash::Hash::hash(uuid, &mut hasher);
            let shard = (std::hash::Hasher::finish(&hasher) as usize) % self.locks.len();
            IngestGuard::Locked(
                self.locks[shard].lock().unwrap_or_else(|poisoned| poisoned.into_inner()),
            )
        }
    }

    #[derive(Default)]
    struct TestBus {
        events: Mutex<Vec<Event>>,
    }

    impl EventBus for TestBus {
        fn emit(&self, event: Event) -> Result<(), String> {
            self.events.lock().map_err(|_| "bus poisoned".to_string())?.push(event);
            Ok(())
        }
    }

    fn ingestor<'a>(
        state: &'a TestState,
        storage: &'a TestStorage,
        bus: &'a TestBus,
    ) -> Ingestor<&'a TestState, &'a TestStorage, &'a TestBus, impl Fn() -> u64> {
        Ingestor::new(state, storage, bus, || 42_000)
    }

    #[fixture]
    fn state() -> TestState {
        TestState::default()
    }

    #[fixture]
    fn storage() -> TestStorage {
        TestStorage::default()
    }

    #[fixture]
    fn bus() -> TestBus {
        TestBus::default()
    }

    #[fixture]
    fn payload() -> Value {
        json!({
            "type": "mystery",
            "content": { "message": "hi" },
            "origin": {
                "function_name": "demo",
                "file": "main.rs",
                "line_number": 12,
                "hostname": "laptop"
            },
            "extra": "field"
        })
    }

    #[fixture]
    fn envelope(payload: Value) -> Value {
        json!({
            "uuid": "123e4567-e89b-12d3-a456-426614174000",
            "payloads": [payload],
            "meta": {
                "project": "ray",
                "host": "laptop",
                "screen": "screen-1",
                "session_id": "session-9",
                "unknown": "value"
            }
        })
    }

    #[fixture]
    fn envelope_missing_screen() -> Value {
        json!({
            "uuid": "123e4567-e89b-12d3-a456-426614174111",
            "payloads": [{
                "type": "log",
                "content": { "message": "hi" },
                "origin": { "hostname": "device" }
            }],
            "meta": {
                "project": "ray",
                "host": "device"
            }
        })
    }

    #[fixture]
    fn envelope_missing_uuid() -> Value {
        json!({
            "payloads": [{
                "type": "log",
                "content": { "message": "hi" },
                "origin": { "hostname": "device" }
            }]
        })
    }

    #[rstest]
    fn ingest_valid_envelope_updates_state_and_storage(
        state: TestState,
        storage: TestStorage,
        bus: TestBus,
        envelope: Value,
    ) {
        let ingestor = ingestor(&state, &storage, &bus);

        let response = ingestor.handle(&serde_json::to_vec(&envelope).unwrap());
        assert_eq!(response.status, 200);

        let stored = storage.entries.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].screen.as_str(), "screen-1");
        assert_eq!(stored[0].payloads[0].r#type, "mystery");

        let state_entries = state.entries.lock().unwrap();
        assert_eq!(state_entries.len(), 1);

        let events = bus.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        match &events[0] {
            Event::EntryInserted(entry) => {
                assert_eq!(entry.uuid, "123e4567-e89b-12d3-a456-426614174000");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[rstest]
    fn ingest_state_failure_does_not_orphan_storage(
        storage: TestStorage,
        bus: TestBus,
        envelope: Value,
    ) {
        let state = FailingState;
        let ingestor = Ingestor::new(&state, &storage, &bus, || 42_000);

        let response = ingestor.handle(&serde_json::to_vec(&envelope).unwrap());
        assert_eq!(response.status, 500);

        // Core state is updated before storage, so a state failure must leave no JSONL
        // line behind (which would be invisible to live MCP/TUI until a restart) and
        // emit no bus event.
        assert!(
            storage.entries.lock().unwrap().is_empty(),
            "state failure must not append an orphaned storage entry"
        );
        assert!(bus.events.lock().unwrap().is_empty(), "no event should be emitted on failure");
    }

    #[rstest]
    fn ingest_duplicate_uuid_updates_state(
        state: TestState,
        storage: TestStorage,
        bus: TestBus,
        envelope: Value,
    ) {
        let ingestor = ingestor(&state, &storage, &bus);
        let body = serde_json::to_vec(&envelope).unwrap();
        let uuid = envelope["uuid"].as_str().unwrap();

        assert_eq!(ingestor.handle(&body).status, 200);
        assert_eq!(ingestor.handle(&body).status, 200);

        let stored = storage.entries.lock().unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].payloads.len(), 1);
        assert_eq!(stored[1].payloads.len(), 2);

        let state_entries = state.entries.lock().unwrap();
        assert_eq!(state_entries.len(), 1);
        assert_eq!(state_entries[0].uuid, uuid);
        assert_eq!(state_entries[0].payloads.len(), 2);

        let events = bus.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::EntryInserted(_)));
        assert!(matches!(events[1], Event::EntryUpdated(_)));
    }

    #[test]
    fn concurrent_same_uuid_ingest_preserves_all_payloads() {
        const N: usize = 8;
        let state = SharedConcurrentState::new(std::time::Duration::from_millis(5));
        let storage = TestStorage::default();
        let bus = TestBus::default();

        std::thread::scope(|scope| {
            for i in 0..N {
                let state = &state;
                let storage = &storage;
                let bus = &bus;
                scope.spawn(move || {
                    let ingestor = Ingestor::new(state, storage, bus, || 42_000);
                    let envelope = json!({
                        "uuid": "shared-uuid",
                        "payloads": [{
                            "type": "log",
                            "content": { "message": format!("payload-{i}") },
                            "origin": { "hostname": "device" }
                        }],
                        "meta": { "project": "ray", "host": "device" }
                    });
                    let response = ingestor.handle(&serde_json::to_vec(&envelope).unwrap());
                    assert_eq!(response.status, 200);
                });
            }
        });

        let entries = state.entries.lock().unwrap();
        assert_eq!(entries.len(), 1, "all ingests target the same UUID");
        assert_eq!(
            entries[0].payloads.len(),
            N,
            "concurrent same-UUID merges must not drop payloads"
        );
    }

    #[rstest]
    fn ingest_duplicate_uuid_rejects_oversized_merged_entry(
        state: TestState,
        storage: TestStorage,
        bus: TestBus,
        envelope: Value,
    ) {
        let first_entry = serde_json::from_value::<RayEnvelope>(envelope.clone())
            .expect("envelope")
            .into_entry(42_000);
        let max_entry_bytes = serde_json::to_vec(&first_entry).expect("serialize").len();
        let ingestor = ingestor(&state, &storage, &bus).with_max_entry_bytes(max_entry_bytes);
        let body = serde_json::to_vec(&envelope).unwrap();

        assert_eq!(ingestor.handle(&body).status, 200);
        assert_eq!(ingestor.handle(&body).status, 413);

        let stored = storage.entries.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].payloads.len(), 1);

        let state_entries = state.entries.lock().unwrap();
        assert_eq!(state_entries.len(), 1);
        assert_eq!(state_entries[0].payloads.len(), 1);

        let events = bus.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::EntryInserted(_)));
    }

    #[rstest]
    fn ingest_default_screen_when_missing(
        state: TestState,
        storage: TestStorage,
        bus: TestBus,
        envelope_missing_screen: Value,
    ) {
        let ingestor = ingestor(&state, &storage, &bus);

        let response = ingestor.handle(&serde_json::to_vec(&envelope_missing_screen).unwrap());
        assert_eq!(response.status, 200);

        let stored = storage.entries.lock().unwrap();
        assert_eq!(stored[0].screen.as_str(), "ray:device:default");
    }

    #[rstest]
    fn ingest_invalid_json_returns_400(state: TestState, storage: TestStorage, bus: TestBus) {
        let ingestor = ingestor(&state, &storage, &bus);

        let response = ingestor.handle(br#"{not valid json"#);
        assert_eq!(response.status, 400);
        assert!(state.entries.lock().unwrap().is_empty());
        assert!(storage.entries.lock().unwrap().is_empty());
        assert!(bus.events.lock().unwrap().is_empty());
    }

    #[rstest]
    fn ingest_missing_required_fields_returns_422(
        state: TestState,
        storage: TestStorage,
        bus: TestBus,
        envelope_missing_uuid: Value,
    ) {
        let ingestor = ingestor(&state, &storage, &bus);

        let response = ingestor.handle(&serde_json::to_vec(&envelope_missing_uuid).unwrap());
        assert_eq!(response.status, 422);
        assert!(state.entries.lock().unwrap().is_empty());
        assert!(storage.entries.lock().unwrap().is_empty());
        assert!(bus.events.lock().unwrap().is_empty());
    }
}
