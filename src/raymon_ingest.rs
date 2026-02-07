//! HTTP ingest handlers for Raymon.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::raymon_core::{Entry, Event, RayEnvelope};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestResponse {
    pub status: u16,
    pub error: Option<String>,
}

impl IngestResponse {
    pub fn ok() -> Self {
        Self { status: 200, error: None }
    }

    pub fn from_error(error: IngestError) -> Self {
        let status = error.status_code();
        Self { status, error: Some(error.to_string()) }
    }
}

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
}

impl IngestError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidJson(_) => 400,
            Self::InvalidEnvelope(_) | Self::MissingField(_) => 422,
            Self::StateStore(_) | Self::Storage(_) | Self::EventBus(_) => 500,
        }
    }
}

pub trait StateStore {
    fn insert_entry(&self, entry: Entry) -> Result<(), String>;
    fn update_entry(&self, entry: Entry) -> Result<(), String>;
    fn get_entry(&self, uuid: &str) -> Result<Option<Entry>, String>;
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
}

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

pub struct Ingestor<S, T, B, C> {
    state: S,
    storage: T,
    bus: B,
    clock: C,
}

impl<S, T, B, C> Ingestor<S, T, B, C>
where
    S: StateStore,
    T: Storage,
    B: EventBus,
    C: Fn() -> u64,
{
    pub fn new(state: S, storage: T, bus: B, clock: C) -> Self {
        Self { state, storage, bus, clock }
    }

    pub fn handle(&self, body: &[u8]) -> IngestResponse {
        match self.handle_inner(body) {
            Ok(_) => IngestResponse::ok(),
            Err(error) => IngestResponse::from_error(error),
        }
    }

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

        let existing = self.state.get_entry(&entry.uuid).map_err(IngestError::StateStore)?;

        let update = if let Some(existing) = existing {
            entry = merge_entry_update(existing, entry);
            true
        } else {
            false
        };

        crate::sanitize::sanitize_entry(&mut entry);

        if update {
            self.storage.append_entry(&entry).map_err(IngestError::Storage)?;
            self.state.update_entry(entry.clone()).map_err(IngestError::StateStore)?;
            self.bus.emit(Event::EntryUpdated(entry.clone())).map_err(IngestError::EventBus)?;
        } else {
            self.storage.append_entry(&entry).map_err(IngestError::Storage)?;
            self.state.insert_entry(entry.clone()).map_err(IngestError::StateStore)?;
            self.bus.emit(Event::EntryInserted(entry.clone())).map_err(IngestError::EventBus)?;
        }

        Ok(entry)
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

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub fn router<S, T, B, C>(ingestor: Arc<Ingestor<S, T, B, C>>) -> Router
where
    S: StateStore + Send + Sync + 'static,
    T: Storage + Send + Sync + 'static,
    B: EventBus + Send + Sync + 'static,
    C: Fn() -> u64 + Send + Sync + 'static,
{
    Router::new().route("/", post(ingest_handler::<S, T, B, C>)).with_state(ingestor)
}

async fn ingest_handler<S, T, B, C>(
    State(ingestor): State<Arc<Ingestor<S, T, B, C>>>,
    bytes: Bytes,
) -> Response
where
    S: StateStore + Send + Sync + 'static,
    T: Storage + Send + Sync + 'static,
    B: EventBus + Send + Sync + 'static,
    C: Fn() -> u64 + Send + Sync + 'static,
{
    let response = ingestor.handle(&bytes);
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    match response.error {
        Some(error) => (status, error).into_response(),
        None => status.into_response(),
    }
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
