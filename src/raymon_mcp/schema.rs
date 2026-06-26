use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct ListEntriesParams {
    pub(super) query: Option<String>,
    pub(super) types: StringListSelector,
    pub(super) colors: StringListSelector,
    pub(super) screen: Option<String>,
    pub(super) project: Option<String>,
    pub(super) host: Option<String>,
    pub(super) limit: Option<usize>,
    pub(super) offset: Option<usize>,
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
    pub(super) fn to_vec(&self) -> Vec<String> {
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
    pub(super) fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(uuid) if uuid.contains(',') => {
                // Drop empty segments from stray separators (leading/trailing/double commas)
                // so the convenience form tolerates them, consistent with unknown UUIDs being
                // silently skipped rather than failing the whole batch.
                uuid.split(',')
                    .map(compact_uuid_segment)
                    .filter(|segment| !segment.is_empty())
                    .collect()
            }
            Self::One(uuid) => vec![uuid.trim().to_string()],
            Self::Many(uuids) => uuids,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct GetEntriesParams {
    #[serde(alias = "uuid")]
    pub(super) uuids: UuidSelector,
    #[serde(default, alias = "redacted", alias = "redact_payloads")]
    pub(super) redact: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ListEntriesResult {
    pub(super) entries: Vec<EntrySummary>,
    pub(super) count: usize,
    pub(super) limit: usize,
    pub(super) offset: usize,
    pub(super) scan_limit: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct GetEntriesResult {
    pub(super) entries: Vec<McpEntry>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct EntrySummary {
    pub(super) uuid: String,
    pub(super) received_at: u64,
    pub(super) project: String,
    pub(super) host: String,
    pub(super) screen: String,
    pub(super) payload_count: usize,
    pub(super) payload_types: Vec<String>,
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
    pub(super) uuid: String,
    pub(super) received_at: u64,
    pub(super) project: String,
    pub(super) host: String,
    pub(super) screen: String,
    pub(super) session_id: Option<String>,
    pub(super) payloads: Vec<McpPayload>,
}

impl From<crate::raymon_core::Entry> for McpEntry {
    fn from(entry: crate::raymon_core::Entry) -> Self {
        Self::from_entry(entry, false)
    }
}

impl McpEntry {
    pub(super) fn from_entry(entry: crate::raymon_core::Entry, redact_payloads: bool) -> Self {
        Self {
            uuid: entry.uuid,
            received_at: entry.received_at,
            project: entry.project,
            host: entry.host,
            screen: entry.screen.as_str().to_string(),
            session_id: entry.session_id.map(|value| value.0),
            payloads: entry
                .payloads
                .into_iter()
                .map(|payload| McpPayload::from_payload(payload, redact_payloads))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct McpPayload {
    pub(super) r#type: String,
    pub(super) content: Value,
    pub(super) origin: McpOrigin,
}

impl From<crate::raymon_core::Payload> for McpPayload {
    fn from(payload: crate::raymon_core::Payload) -> Self {
        Self::from_payload(payload, false)
    }
}

impl McpPayload {
    fn from_payload(payload: crate::raymon_core::Payload, redact_payloads: bool) -> Self {
        let mut content = payload.content;
        if redact_payloads {
            crate::sanitize::redact_sensitive_payload_value(&mut content);
        }

        Self { r#type: payload.r#type, content, origin: McpOrigin::from(payload.origin) }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct McpOrigin {
    pub(super) project: String,
    pub(super) host: String,
    pub(super) screen: Option<String>,
    pub(super) session_id: Option<String>,
    pub(super) function_name: Option<String>,
    pub(super) file: Option<String>,
    pub(super) line_number: Option<u32>,
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

fn comma_separated_values(value: &str) -> Vec<String> {
    value.split(',').map(|segment| segment.trim().to_string()).collect()
}

fn compact_uuid_segment(uuid: &str) -> String {
    uuid.chars().filter(|ch| !ch.is_whitespace()).collect()
}
