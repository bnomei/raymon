//! Core domain types and traits for Raymon.

pub mod types {
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    pub type Timestamp = u64;

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct Screen(pub String);

    impl Screen {
        pub fn new(name: impl Into<String>) -> Self {
            Self(name.into())
        }

        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct SessionId(pub String);

    impl SessionId {
        pub fn new(value: impl Into<String>) -> Self {
            Self(value.into())
        }

        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct Origin {
        pub project: String,
        pub host: String,
        pub screen: Option<Screen>,
        pub session_id: Option<SessionId>,
        #[serde(default, skip_serializing_if = "Option::is_none", alias = "functionName")]
        pub function_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", alias = "fileName")]
        pub file: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none", alias = "lineNumber")]
        pub line_number: Option<u32>,
    }

    impl Origin {
        pub fn screen_or_default(&self) -> Screen {
            self.screen
                .clone()
                .unwrap_or_else(|| default_screen_name(&self.project, &self.host))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct EntryMeta {
        pub project: String,
        pub host: String,
        pub screen: Screen,
        pub session_id: Option<SessionId>,
        pub received_at: Timestamp,
    }

    impl EntryMeta {
        pub fn new(
            project: impl Into<String>,
            host: impl Into<String>,
            screen: Screen,
            session_id: Option<SessionId>,
            received_at: Timestamp,
        ) -> Self {
            Self {
                project: project.into(),
                host: host.into(),
                screen,
                session_id,
                received_at,
            }
        }

        pub fn from_origin(origin: &Origin, received_at: Timestamp) -> Self {
            Self {
                project: origin.project.clone(),
                host: origin.host.clone(),
                screen: origin.screen_or_default(),
                session_id: origin.session_id.clone(),
                received_at,
            }
        }

        pub fn from_payloads(payloads: &[Payload], received_at: Timestamp) -> Self {
            if let Some(origin) = payloads.first().map(|payload| &payload.origin) {
                return Self::from_origin(origin, received_at);
            }

            let project = "unknown";
            let host = "unknown";
            let screen = default_screen_name(project, host);
            Self {
                project: project.to_string(),
                host: host.to_string(),
                screen,
                session_id: None,
                received_at,
            }
        }

        pub fn from_ray(
            meta: Option<&RayMeta>,
            payloads: &[RayPayload],
            received_at: Timestamp,
        ) -> Self {
            let project = normalize_component(
                meta.and_then(|meta| meta.project.as_deref()),
                "unknown",
            );
            let host = normalize_component(
                meta.and_then(|meta| meta.host.as_deref())
                    .or_else(|| payloads.first().map(|payload| payload.origin.hostname.as_str())),
                "unknown",
            );
            let default_screen = default_screen_name(&project, &host);
            let screen = normalize_component(
                meta.and_then(|meta| meta.screen.as_deref()),
                default_screen.as_str(),
            );

            Self {
                project,
                host,
                screen: Screen::new(screen),
                session_id: meta.and_then(|meta| meta.session_id.clone()),
                received_at,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct RayOrigin {
        #[serde(default, alias = "functionName")]
        pub function_name: Option<String>,
        #[serde(default, alias = "fileName")]
        pub file: Option<String>,
        #[serde(default, alias = "lineNumber")]
        pub line_number: Option<u32>,
        #[serde(alias = "hostname", alias = "host", alias = "host_name")]
        pub hostname: String,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct RayPayload {
        #[serde(rename = "type")]
        pub r#type: String,
        pub content: Value,
        pub origin: RayOrigin,
    }

    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    pub struct RayMeta {
        #[serde(default, alias = "projectName", alias = "project_name")]
        pub project: Option<String>,
        #[serde(default, alias = "hostname", alias = "host", alias = "host_name")]
        pub host: Option<String>,
        #[serde(default, alias = "screenName", alias = "screen_name")]
        pub screen: Option<String>,
        #[serde(default, alias = "sessionId", alias = "session")]
        pub session_id: Option<SessionId>,
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct RayEnvelope {
        pub uuid: String,
        pub payloads: Vec<RayPayload>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub meta: Option<RayMeta>,
    }

    impl RayEnvelope {
        pub fn entry_meta(&self, received_at: Timestamp) -> EntryMeta {
            EntryMeta::from_ray(self.meta.as_ref(), &self.payloads, received_at)
        }

        pub fn into_entry(self, received_at: Timestamp) -> Entry {
            let meta = EntryMeta::from_ray(self.meta.as_ref(), &self.payloads, received_at);
            let payloads = self
                .payloads
                .into_iter()
                .map(|payload| Payload {
                    r#type: payload.r#type,
                    content: payload.content,
                    origin: Origin {
                        project: meta.project.clone(),
                        host: meta.host.clone(),
                        screen: Some(meta.screen.clone()),
                        session_id: meta.session_id.clone(),
                        function_name: payload.origin.function_name.clone(),
                        file: payload.origin.file.clone(),
                        line_number: payload.origin.line_number,
                    },
                })
                .collect();

            Entry {
                uuid: self.uuid,
                received_at: meta.received_at,
                project: meta.project,
                host: meta.host,
                screen: meta.screen,
                session_id: meta.session_id,
                payloads,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Payload {
        #[serde(rename = "type")]
        pub r#type: String,
        pub content: Value,
        pub origin: Origin,
    }

    impl Payload {
        pub fn screen_or_default(&self) -> Screen {
            self.origin.screen_or_default()
        }
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Envelope {
        pub uuid: String,
        pub payloads: Vec<Payload>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub meta: Option<EntryMeta>,
    }

    impl Envelope {
        pub fn entry_meta(&self, received_at: Timestamp) -> EntryMeta {
            if let Some(meta) = &self.meta {
                return meta.clone();
            }
            EntryMeta::from_payloads(&self.payloads, received_at)
        }

        pub fn into_entry(self, received_at: Timestamp) -> Entry {
            let meta = EntryMeta::from_payloads(&self.payloads, received_at);
            Entry {
                uuid: self.uuid,
                received_at: meta.received_at,
                project: meta.project,
                host: meta.host,
                screen: meta.screen,
                session_id: meta.session_id,
                payloads: self.payloads,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub struct Entry {
        pub uuid: String,
        pub received_at: Timestamp,
        pub project: String,
        pub host: String,
        pub screen: Screen,
        pub session_id: Option<SessionId>,
        pub payloads: Vec<Payload>,
    }

    impl Entry {
        pub fn meta(&self) -> EntryMeta {
            EntryMeta {
                project: self.project.clone(),
                host: self.host.clone(),
                screen: self.screen.clone(),
                session_id: self.session_id.clone(),
                received_at: self.received_at,
            }
        }

        pub fn from_envelope(envelope: Envelope, received_at: Timestamp) -> Self {
            let meta = envelope.entry_meta(received_at);
            Self {
                uuid: envelope.uuid,
                received_at: meta.received_at,
                project: meta.project,
                host: meta.host,
                screen: meta.screen,
                session_id: meta.session_id,
                payloads: envelope.payloads,
            }
        }
    }

    pub fn default_screen_name(project: &str, host: &str) -> Screen {
        Screen::new(format!("{project}:{host}:default"))
    }

    pub fn timestamp_from_system_time(time: SystemTime) -> Timestamp {
        let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
        let millis = duration.as_millis();
        u64::try_from(millis).unwrap_or(u64::MAX)
    }

    pub fn system_time_from_timestamp(timestamp: Timestamp) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(timestamp)
    }

    fn normalize_component(value: Option<&str>, fallback: &str) -> String {
        value
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(fallback)
            .to_string()
    }
}

pub mod filters {
    use crate::types::{Entry, Payload, Screen};
    use rayon::prelude::*;
    use regex::{Regex, RegexBuilder};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use thiserror::Error;

    #[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
    pub struct Filters {
        pub query: Option<String>,
        #[serde(default)]
        pub query_is_regex: bool,
        pub types: Vec<String>,
        pub colors: Vec<String>,
        pub screen: Option<Screen>,
        pub project: Option<String>,
        pub host: Option<String>,
        pub limit: Option<usize>,
        pub offset: usize,
    }

    impl Filters {
        pub fn matches_entry(&self, entry: &Entry) -> Result<bool, FilterError> {
            let query = self.compile_query()?;
            Ok(self.matches_entry_with_query(entry, query.as_ref()))
        }

        pub fn apply<'a>(
            &self,
            entries: impl IntoIterator<Item = &'a Entry>,
        ) -> Result<Vec<&'a Entry>, FilterError> {
            let query = self.compile_query()?;
            let mut matched = Vec::new();
            let mut skipped = 0usize;

            for entry in entries {
                if !self.matches_entry_with_query(entry, query.as_ref()) {
                    continue;
                }

                if skipped < self.offset {
                    skipped += 1;
                    continue;
                }

                matched.push(entry);

                if let Some(limit) = self.limit {
                    if matched.len() >= limit {
                        break;
                    }
                }
            }

            Ok(matched)
        }

        pub fn apply_parallel<'a>(
            &self,
            entries: &'a [Entry],
        ) -> Result<Vec<&'a Entry>, FilterError> {
            let query = self.compile_query()?;
            let matches: Vec<bool> = entries
                .par_iter()
                .map(|entry| self.matches_entry_with_query(entry, query.as_ref()))
                .collect();

            let mut matched = Vec::new();
            let mut skipped = 0usize;

            for (entry, is_match) in entries.iter().zip(matches.into_iter()) {
                if !is_match {
                    continue;
                }

                if skipped < self.offset {
                    skipped += 1;
                    continue;
                }

                matched.push(entry);

                if let Some(limit) = self.limit {
                    if matched.len() >= limit {
                        break;
                    }
                }
            }

            Ok(matched)
        }

        fn matches_entry_with_query(&self, entry: &Entry, query: Option<&QueryMatcher>) -> bool {
            if let Some(project) = &self.project {
                if &entry.project != project {
                    return false;
                }
            }

            if let Some(host) = &self.host {
                if &entry.host != host {
                    return false;
                }
            }

            if let Some(screen) = &self.screen {
                if &entry.screen != screen {
                    return false;
                }
            }

            if !self.has_payload_filters(query) {
                return true;
            }

            entry
                .payloads
                .iter()
                .any(|payload| self.matches_payload(payload, query))
        }

        fn has_payload_filters(&self, query: Option<&QueryMatcher>) -> bool {
            query.is_some() || !self.types.is_empty() || !self.colors.is_empty()
        }

        fn matches_payload(&self, payload: &Payload, query: Option<&QueryMatcher>) -> bool {
            if !self.types.is_empty() && !self.types.iter().any(|t| t == &payload.r#type) {
                return false;
            }

            if !self.colors.is_empty() {
                let payload_color = payload_color(payload);
                match payload_color {
                    Some(color) => {
                        if !self.colors.iter().any(|candidate| candidate == color) {
                            return false;
                        }
                    }
                    None => return false,
                }
            }

            if let Some(query) = query {
                if !payload_matches_query(payload, query) {
                    return false;
                }
            }

            true
        }

        fn compile_query(&self) -> Result<Option<QueryMatcher>, FilterError> {
            let query = match self.query.as_ref().map(|q| q.trim()).filter(|q| !q.is_empty()) {
                Some(query) => query,
                None => return Ok(None),
            };

            if self.query_is_regex {
                let pattern = strip_regex_delimiters(query).unwrap_or(query);
                return Ok(Some(QueryMatcher::Regex(compile_regex(pattern)?)));
            }

            if let Some(pattern) = strip_regex_delimiters(query) {
                return Ok(Some(QueryMatcher::Regex(compile_regex(pattern)?)));
            }

            Ok(Some(QueryMatcher::Substring(query.to_lowercase())))
        }
    }

    fn payload_color(payload: &Payload) -> Option<&str> {
        match payload.content.get("color") {
            Some(Value::String(value)) => Some(value.as_str()),
            _ => None,
        }
    }

    fn payload_matches_query(payload: &Payload, query: &QueryMatcher) -> bool {
        let content_string = match &payload.content {
            Value::String(value) => value.clone(),
            _ => payload.content.to_string(),
        };

        match query {
            QueryMatcher::Substring(query) => {
                payload.r#type.to_lowercase().contains(query)
                    || content_string.to_lowercase().contains(query)
            }
            QueryMatcher::Regex(regex) => regex.is_match(&payload.r#type) || regex.is_match(&content_string),
        }
    }

    fn strip_regex_delimiters(query: &str) -> Option<&str> {
        query.strip_prefix('/').and_then(|q| q.strip_suffix('/'))
    }

    fn compile_regex(pattern: &str) -> Result<Regex, FilterError> {
        RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .map_err(|error| FilterError::InvalidRegex {
                pattern: pattern.to_string(),
                message: error.to_string(),
            })
    }

    #[derive(Clone, Debug)]
    enum QueryMatcher {
        Substring(String),
        Regex(Regex),
    }

    #[derive(Debug, Error)]
    pub enum FilterError {
        #[error("invalid regex pattern `{pattern}`: {message}")]
        InvalidRegex { pattern: String, message: String },
    }
}

pub mod state {
    use crate::filters::Filters;
    use crate::types::{Entry, Screen};

    pub trait StateStore {
        type Error;

        fn insert_entry(&mut self, entry: Entry) -> Result<(), Self::Error>;
        fn update_entry(&mut self, entry: Entry) -> Result<(), Self::Error>;
        fn get_entry(&self, uuid: &str) -> Result<Option<Entry>, Self::Error>;
        fn list_entries(&self, filters: &Filters) -> Result<Vec<Entry>, Self::Error>;
        fn list_screens(&self) -> Result<Vec<Screen>, Self::Error>;
        fn clear_screen(&mut self, screen: &Screen) -> Result<(), Self::Error>;
        fn clear_all(&mut self) -> Result<(), Self::Error>;
    }
}

pub mod events {
    use crate::types::{Entry, Screen};
    use serde::{Deserialize, Serialize};

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    pub enum Event {
        EntryInserted(Entry),
        EntryUpdated(Entry),
        ScreenCleared(Screen),
        StateCleared,
    }

    pub trait EventBus {
        type Error;
        type Subscription;

        fn emit(&self, event: Event) -> Result<(), Self::Error>;
        fn subscribe(&self) -> Result<Self::Subscription, Self::Error>;
    }
}

pub use events::{Event, EventBus};
pub use filters::{FilterError, Filters};
pub use state::StateStore;
pub use types::{
    default_screen_name, system_time_from_timestamp, timestamp_from_system_time, Entry, EntryMeta,
    Envelope, Origin, Payload, RayEnvelope, RayMeta, RayOrigin, RayPayload, Screen, SessionId,
    Timestamp,
};

#[cfg(test)]
mod tests {
    use super::filters::{FilterError, Filters};
    use super::types::{
        default_screen_name, Entry, Envelope, Origin, Payload, RayEnvelope, RayMeta, RayOrigin,
        RayPayload, Screen, SessionId,
    };
    use rstest::{fixture, rstest};
    use serde_json::json;

    #[test]
    fn default_screen_name_uses_project_and_host() {
        let screen = default_screen_name("project-a", "host-1");
        assert_eq!(screen.as_str(), "project-a:host-1:default");
    }

    #[fixture]
    fn origin_default() -> Origin {
        Origin {
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: None,
            session_id: None,
            function_name: None,
            file: None,
            line_number: None,
        }
    }

    #[fixture]
    fn payload_note(origin_default: Origin) -> Payload {
        Payload {
            r#type: "note".to_string(),
            content: json!({"message": "Hello there", "color": "red"}),
            origin: origin_default,
        }
    }

    #[fixture]
    fn payload_log() -> Payload {
        Payload {
            r#type: "log".to_string(),
            content: json!({"message": "World", "color": "blue"}),
            origin: Origin {
                project: "proj".to_string(),
                host: "host".to_string(),
                screen: Some(Screen::new("custom")),
                session_id: None,
                function_name: None,
                file: None,
                line_number: None,
            },
        }
    }

    #[fixture]
    fn entry_with_payloads(payload_note: Payload, payload_log: Payload) -> Entry {
        Entry {
            uuid: "entry-1".to_string(),
            received_at: 42,
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: default_screen_name("proj", "host"),
            session_id: None,
            payloads: vec![payload_note, payload_log],
        }
    }

    #[rstest]
    fn filters_match_payload_constraints(entry_with_payloads: Entry) {
        let mut filters = Filters::default();
        filters.query = Some("hello".to_string());
        filters.types = vec!["note".to_string()];
        filters.colors = vec!["red".to_string()];
        assert!(filters.matches_entry(&entry_with_payloads).unwrap());

        filters.types = vec!["log".to_string()];
        filters.colors = vec!["red".to_string()];
        assert!(!filters.matches_entry(&entry_with_payloads).unwrap());

        filters.types.clear();
        filters.colors.clear();
        filters.screen = Some(Screen::new("missing"));
        assert!(!filters.matches_entry(&entry_with_payloads).unwrap());
    }

    #[rstest]
    #[case("/Hello.*there/", false)]
    #[case("/hello.*there/", false)]
    #[case("Hello.*there", true)]
    fn filters_support_regex_queries(entry_with_payloads: Entry, #[case] query: &str, #[case] is_regex: bool) {
        let mut filters = Filters::default();
        filters.query = Some(query.to_string());
        filters.query_is_regex = is_regex;
        assert!(filters.matches_entry(&entry_with_payloads).unwrap());
    }

    #[rstest]
    fn invalid_regex_returns_error(entry_with_payloads: Entry) {
        let mut filters = Filters::default();
        filters.query = Some("/[a-/".to_string());

        let result = filters.apply(std::iter::once(&entry_with_payloads));
        assert!(matches!(result, Err(FilterError::InvalidRegex { .. })));
    }

    #[rstest]
    fn parallel_apply_matches_sequential(entry_with_payloads: Entry) {
        let mut filters = Filters::default();
        filters.query = Some("hello".to_string());
        filters.types = vec!["note".to_string()];

        let entries = vec![entry_with_payloads.clone(), entry_with_payloads];
        let sequential = filters.apply(entries.iter()).unwrap();
        let parallel = filters.apply_parallel(&entries).unwrap();

        assert_eq!(sequential.len(), parallel.len());
        for (left, right) in sequential.iter().zip(parallel.iter()) {
            assert_eq!(left.uuid, right.uuid);
        }
    }

    #[rstest]
    fn envelope_without_meta_derives_from_payloads(entry_with_payloads: Entry) {
        let envelope = Envelope {
            uuid: "env-1".to_string(),
            payloads: entry_with_payloads.payloads.clone(),
            meta: None,
        };

        let entry = Entry::from_envelope(envelope, 77);
        assert_eq!(entry.project, "proj");
        assert_eq!(entry.host, "host");
        assert_eq!(entry.screen.as_str(), "proj:host:default");
        assert_eq!(entry.received_at, 77);
    }

    #[test]
    fn ray_envelope_with_meta_derives_entry() {
        let envelope = RayEnvelope {
            uuid: "ray-1".to_string(),
            payloads: vec![RayPayload {
                r#type: "note".to_string(),
                content: json!({"message": "hello"}),
                origin: RayOrigin {
                    function_name: Some("handler".to_string()),
                    file: Some("main.rs".to_string()),
                    line_number: Some(12),
                    hostname: "payload-host".to_string(),
                },
            }],
            meta: Some(RayMeta {
                project: Some("ray".to_string()),
                host: Some("meta-host".to_string()),
                screen: Some("screen-1".to_string()),
                session_id: Some(SessionId::new("sess-1")),
            }),
        };

        let entry = envelope.into_entry(5_000);
        assert_eq!(entry.project, "ray");
        assert_eq!(entry.host, "meta-host");
        assert_eq!(entry.screen.as_str(), "screen-1");
        assert_eq!(entry.session_id.unwrap().as_str(), "sess-1");
        assert_eq!(entry.received_at, 5_000);
        assert_eq!(entry.payloads.len(), 1);
        assert_eq!(entry.payloads[0].origin.project, "ray");
        assert_eq!(entry.payloads[0].origin.host, "meta-host");
    }

    #[test]
    fn ray_envelope_without_meta_uses_payload_origin() {
        let envelope = RayEnvelope {
            uuid: "ray-2".to_string(),
            payloads: vec![RayPayload {
                r#type: "note".to_string(),
                content: json!({"message": "hello"}),
                origin: RayOrigin {
                    function_name: None,
                    file: None,
                    line_number: None,
                    hostname: "payload-host".to_string(),
                },
            }],
            meta: None,
        };

        let entry = envelope.into_entry(10);
        assert_eq!(entry.project, "unknown");
        assert_eq!(entry.host, "payload-host");
        assert_eq!(entry.screen.as_str(), "unknown:payload-host:default");
        assert_eq!(entry.payloads.len(), 1);
        assert_eq!(entry.payloads[0].origin.host, "payload-host");
    }
}
