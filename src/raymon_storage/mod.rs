//! Storage layer for Raymon.
//!
//! Entries are persisted as newline-delimited JSON (`.jsonl`) on disk and indexed in-memory for
//! fast listing and random access by id/offset.

use std::collections::VecDeque;
use std::fs;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::raymon_core::{FilterError as CoreFilterError, Filters as CoreFilters};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use tracing::info;

mod index;
mod jsonl;

/// Default directory under the storage root where Raymon keeps persisted data.
pub const DEFAULT_DATA_DIR: &str = "data";
/// Default file name for the JSONL entries log inside [`DEFAULT_DATA_DIR`].
pub const ENTRIES_FILE: &str = "entries.jsonl";
const RETENTION_BAK_FILE: &str = "entries.jsonl.bak";
const RETENTION_TMP_FILE: &str = "entries.jsonl.tmp";

/// Errors returned by [`Storage`] operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid offset {offset} len {len}")]
    InvalidOffset { offset: u64, len: u64 },
}

/// In-memory representation of an entry that is about to be appended to storage.
#[derive(Debug, Clone)]
pub struct EntryInput {
    pub id: String,
    pub project: String,
    pub host: String,
    pub screen: String,
    pub session: String,
    pub summary: String,
    pub search_text: String,
    pub types: Vec<String>,
    pub colors: Vec<String>,
    pub payload: EntryPayload,
}

/// Payload variants supported by the storage layer.
#[derive(Debug, Clone)]
pub enum EntryPayload {
    Text(String),
}

/// Summary of entries kept/dropped after a retention pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionOutcome {
    pub dropped: usize,
    pub kept: usize,
}

/// Serialized representation of an entry as written to the JSONL file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEntry {
    pub id: String,
    pub project: String,
    pub host: String,
    pub screen: String,
    pub session: String,
    pub summary: String,
    pub search_text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub colors: Vec<String>,
    pub payload: StoredPayload,
}

/// Serialized payload variants as written to the JSONL file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoredPayload {
    Text { text: String },
}

/// Index metadata for a stored entry.
///
/// This is designed for fast listing/filtering without loading the full JSON payload.
#[derive(Debug, Clone)]
pub struct OffsetMeta {
    pub id: SmolStr,
    pub project: SmolStr,
    pub host: SmolStr,
    pub screen: SmolStr,
    pub session: SmolStr,
    pub summary: SmolStr,
    pub search_text: SmolStr,
    pub summary_lower: SmolStr,
    pub search_text_lower: SmolStr,
    pub offset: u64,
    pub len: u64,
}

/// Lightweight filter used for listing entries from the index.
#[derive(Debug, Default, Clone)]
pub struct EntryFilter {
    pub id: Option<String>,
    pub screen: Option<String>,
    pub session: Option<String>,
    pub query: Option<String>,
    pub offset: usize,
    pub limit: Option<usize>,
}

impl EntryFilter {
    fn matches(&self, meta: &OffsetMeta, query_lower: Option<&str>) -> bool {
        if let Some(id) = &self.id {
            if meta.id.as_str() != id.as_str() {
                return false;
            }
        }
        if let Some(screen) = &self.screen {
            if meta.screen.as_str() != screen.as_str() {
                return false;
            }
        }
        if let Some(session) = &self.session {
            if meta.session.as_str() != session.as_str() {
                return false;
            }
        }
        if let Some(query) = query_lower {
            if !meta.summary_lower.contains(query) && !meta.search_text_lower.contains(query) {
                return false;
            }
        }
        true
    }
}

pub struct Storage {
    root: PathBuf,
    data_dir: PathBuf,
    entries_path: PathBuf,
    index: index::Index,
    retention_max_entries: usize,
}

impl Storage {
    /// Create a new storage instance.
    ///
    /// This uses the default data directory (`data/`) and disables retention pruning.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, StorageError> {
        Self::new_with_retention(root, 0)
    }

    /// Create a new storage instance with a retention cap.
    ///
    /// When `retention_max_entries` is non-zero, Raymon keeps the newest `N` entries and may
    /// rewrite the JSONL file to drop older data.
    pub fn new_with_retention(
        root: impl AsRef<Path>,
        retention_max_entries: usize,
    ) -> Result<Self, StorageError> {
        let root = root.as_ref().to_path_buf();
        let data_dir = root.join(DEFAULT_DATA_DIR);
        let entries_path = data_dir.join(ENTRIES_FILE);

        fs::create_dir_all(&data_dir)?;

        if let Some(outcome) = enforce_retention(&entries_path, retention_max_entries)? {
            info!(
                dropped = outcome.dropped,
                kept = outcome.kept,
                path = %entries_path.display(),
                "storage retention pruned entries"
            );
        }

        let index = index::rebuild(&entries_path)?;

        Ok(Self { root, data_dir, entries_path, index, retention_max_entries })
    }

    /// Append an entry to the JSONL file and update the in-memory index.
    ///
    /// Returns the indexed metadata (including byte offset and length) for the stored entry.
    pub fn append_entry(&mut self, entry: EntryInput) -> Result<OffsetMeta, StorageError> {
        let payload = match entry.payload {
            EntryPayload::Text(text) => StoredPayload::Text { text },
        };

        let stored = StoredEntry {
            id: entry.id,
            project: entry.project,
            host: entry.host,
            screen: entry.screen,
            session: entry.session,
            summary: entry.summary,
            search_text: entry.search_text,
            types: entry.types,
            colors: entry.colors,
            payload,
        };

        let entry_id = stored.id.clone();
        let (offset, len) = jsonl::append_entry(&self.entries_path, &stored)?;
        let record = index::record_from_entry(&stored, offset, len);
        let meta = record.meta.clone();
        self.index.insert(record);

        if let Some(outcome) = self.maybe_enforce_retention()? {
            info!(
                dropped = outcome.dropped,
                kept = outcome.kept,
                path = %self.entries_path.display(),
                "storage retention pruned entries"
            );
        }

        Ok(self.index.get_by_id(&entry_id).cloned().unwrap_or(meta))
    }

    /// Storage root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolved data directory (`{root}/data` by default).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Read an entry from the JSONL file by byte offset and length.
    pub fn get_entry_by_offset(&self, offset: u64, len: u64) -> Result<StoredEntry, StorageError> {
        jsonl::read_entry_at(&self.entries_path, offset, len)
    }

    /// Read an entry by id, if it exists in the index.
    pub fn get_entry_by_id(&self, id: &str) -> Result<Option<StoredEntry>, StorageError> {
        let meta = match self.index.get_by_id(id) {
            Some(meta) => meta,
            None => return Ok(None),
        };
        self.get_entry_by_offset(meta.offset, meta.len).map(Some)
    }

    /// List entry metadata from the index with an optional [`EntryFilter`].
    pub fn list_entries(&self, filter: Option<&EntryFilter>) -> Vec<OffsetMeta> {
        self.index.list(filter)
    }

    /// List entry metadata using the shared core [`Filters`](crate::raymon_core::Filters).
    pub fn list_entries_core(
        &self,
        filters: &CoreFilters,
    ) -> Result<Vec<OffsetMeta>, CoreFilterError> {
        self.index.list_core(filters)
    }

    /// Rebuild the in-memory index by scanning the JSONL file.
    pub fn rebuild_index(&mut self) -> Result<(), StorageError> {
        self.index = index::rebuild(&self.entries_path)?;
        Ok(())
    }

    fn maybe_enforce_retention(&mut self) -> Result<Option<RetentionOutcome>, StorageError> {
        let max_entries = self.retention_max_entries;
        if max_entries == 0 {
            return Ok(None);
        }
        let slack = retention_slack(max_entries);
        let total = self.index.len();
        if total <= max_entries.saturating_add(slack) {
            return Ok(None);
        }

        let offsets = self.index.tail_offsets(max_entries);
        rewrite_retained_offsets(&self.entries_path, &offsets)?;
        self.rebuild_index()?;

        Ok(Some(RetentionOutcome { dropped: total.saturating_sub(max_entries), kept: max_entries }))
    }
}

fn retention_slack(max_entries: usize) -> usize {
    (max_entries / 10).clamp(1, 10_000)
}

fn enforce_retention(
    entries_path: &Path,
    retention_max_entries: usize,
) -> Result<Option<RetentionOutcome>, StorageError> {
    if retention_max_entries == 0 {
        return Ok(None);
    }

    let mut offsets: VecDeque<(u64, u64)> = VecDeque::new();
    let mut total = 0usize;
    jsonl::scan_entries(entries_path, |offset, len, _entry| {
        total = total.saturating_add(1);
        offsets.push_back((offset, len));
        if offsets.len() > retention_max_entries {
            offsets.pop_front();
        }
    })?;

    if total <= retention_max_entries {
        return Ok(None);
    }

    let offsets: Vec<(u64, u64)> = offsets.into_iter().collect();
    rewrite_retained_offsets(entries_path, &offsets)?;

    Ok(Some(RetentionOutcome {
        dropped: total.saturating_sub(retention_max_entries),
        kept: retention_max_entries,
    }))
}

fn rewrite_retained_offsets(
    entries_path: &Path,
    offsets: &[(u64, u64)],
) -> Result<(), StorageError> {
    let Some(parent) = entries_path.parent() else {
        return Ok(());
    };

    let tmp_path = parent.join(RETENTION_TMP_FILE);
    let bak_path = parent.join(RETENTION_BAK_FILE);

    {
        let mut source = File::open(entries_path)?;
        let tmp_file = File::create(&tmp_path)?;
        let mut writer = BufWriter::new(tmp_file);
        let mut buf = Vec::new();

        for (offset, len) in offsets {
            source.seek(SeekFrom::Start(*offset))?;
            buf.resize(*len as usize, 0u8);
            source.read_exact(&mut buf)?;
            writer.write_all(&buf)?;
            writer.write_all(b"\n")?;
        }

        writer.flush()?;
    }

    if bak_path.exists() {
        let _ = fs::remove_file(&bak_path);
    }
    if entries_path.exists() {
        fs::rename(entries_path, &bak_path)?;
    }
    fs::rename(&tmp_path, entries_path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raymon_core::{
        Entry as CoreEntry, Filters as CoreFilters, Origin, Payload as CorePayload, Screen,
    };
    use rstest::fixture;
    use rstest::rstest;
    use serde_json::json;
    use tempfile::TempDir;

    struct TempStorage {
        _dir: TempDir,
        storage: Storage,
    }

    impl TempStorage {
        fn new() -> Self {
            let dir = TempDir::new().expect("temp dir");
            let storage = Storage::new(dir.path()).expect("storage");
            Self { _dir: dir, storage }
        }
    }

    #[fixture]
    fn temp_storage() -> TempStorage {
        TempStorage::new()
    }

    #[test]
    fn append_and_read_text_entry() {
        let dir = TempDir::new().expect("temp dir");
        let mut storage = Storage::new(dir.path()).expect("storage");

        let input = EntryInput {
            id: "entry-1".to_string(),
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: "home".to_string(),
            session: "sess-a".to_string(),
            summary: "hello".to_string(),
            search_text: "hello world".to_string(),
            types: Vec::new(),
            colors: Vec::new(),
            payload: EntryPayload::Text("payload".to_string()),
        };

        let meta = storage.append_entry(input).expect("append entry");
        assert!(meta.len > 0);

        let entry = storage.get_entry_by_offset(meta.offset, meta.len).expect("read entry");
        assert_eq!(entry.id, "entry-1");
        match entry.payload {
            StoredPayload::Text { text } => assert_eq!(text, "payload"),
        }

        let filter = EntryFilter { screen: Some("home".to_string()), ..EntryFilter::default() };
        let listed = storage.list_entries(Some(&filter));
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn rebuild_index_reads_existing_entries() {
        let dir = TempDir::new().expect("temp dir");
        {
            let mut storage = Storage::new(dir.path()).expect("storage");
            let first = EntryInput {
                id: "entry-1".to_string(),
                project: "proj".to_string(),
                host: "host".to_string(),
                screen: "home".to_string(),
                session: "sess-a".to_string(),
                summary: "first".to_string(),
                search_text: "alpha".to_string(),
                types: Vec::new(),
                colors: Vec::new(),
                payload: EntryPayload::Text("payload".to_string()),
            };
            let second = EntryInput {
                id: "entry-2".to_string(),
                project: "proj".to_string(),
                host: "host".to_string(),
                screen: "work".to_string(),
                session: "sess-b".to_string(),
                summary: "second".to_string(),
                search_text: "beta".to_string(),
                types: Vec::new(),
                colors: Vec::new(),
                payload: EntryPayload::Text("payload".to_string()),
            };
            storage.append_entry(first).expect("append first");
            storage.append_entry(second).expect("append second");
        }

        let storage = Storage::new(dir.path()).expect("storage reload");
        let listed = storage.list_entries(None);
        assert_eq!(listed.len(), 2);

        let entry = storage.get_entry_by_id("entry-2").expect("get entry").expect("missing entry");
        assert_eq!(entry.summary, "second");
    }

    #[test]
    fn retention_prunes_old_entries_on_reload() {
        let dir = TempDir::new().expect("temp dir");
        {
            let mut storage = Storage::new(dir.path()).expect("storage");
            for idx in 1..=5 {
                let input = EntryInput {
                    id: format!("entry-{idx}"),
                    project: "proj".to_string(),
                    host: "host".to_string(),
                    screen: "home".to_string(),
                    session: "sess-a".to_string(),
                    summary: format!("entry-{idx}"),
                    search_text: format!("entry-{idx}"),
                    types: Vec::new(),
                    colors: Vec::new(),
                    payload: EntryPayload::Text("payload".to_string()),
                };
                storage.append_entry(input).expect("append entry");
            }
        }

        let storage = Storage::new_with_retention(dir.path(), 3).expect("storage reload");
        let listed = storage.list_entries(None);
        let ids: Vec<String> = listed.into_iter().map(|meta| meta.id.to_string()).collect();
        assert_eq!(ids, vec!["entry-3".to_string(), "entry-4".to_string(), "entry-5".to_string()]);

        let entry = storage.get_entry_by_id("entry-1").expect("get entry");
        assert!(entry.is_none());
    }

    #[rstest]
    #[case("home", "sess-a", "hello", "hello world")]
    #[case("work", "sess-b", "status", "status update")]
    fn list_entries_filters_match(
        mut temp_storage: TempStorage,
        #[case] screen: &str,
        #[case] session: &str,
        #[case] summary: &str,
        #[case] search_text: &str,
    ) {
        let input = EntryInput {
            id: format!("entry-{}", screen),
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: screen.to_string(),
            session: session.to_string(),
            summary: summary.to_string(),
            search_text: search_text.to_string(),
            types: Vec::new(),
            colors: Vec::new(),
            payload: EntryPayload::Text("payload".to_string()),
        };
        temp_storage.storage.append_entry(input).expect("append entry");

        let filter = EntryFilter {
            screen: Some(screen.to_string()),
            session: Some(session.to_string()),
            query: Some(summary.split_whitespace().next().unwrap().to_string()),
            ..EntryFilter::default()
        };
        let listed = temp_storage.storage.list_entries(Some(&filter));
        assert_eq!(listed.len(), 1);
    }

    #[rstest]
    fn list_entries_filter_no_match(mut temp_storage: TempStorage) {
        let input = EntryInput {
            id: "entry-nope".to_string(),
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: "home".to_string(),
            session: "sess-a".to_string(),
            summary: "hello".to_string(),
            search_text: "hello world".to_string(),
            types: Vec::new(),
            colors: Vec::new(),
            payload: EntryPayload::Text("payload".to_string()),
        };
        temp_storage.storage.append_entry(input).expect("append entry");

        let filter = EntryFilter { screen: Some("work".to_string()), ..EntryFilter::default() };
        let listed = temp_storage.storage.list_entries(Some(&filter));
        assert_eq!(listed.len(), 0);
    }

    #[test]
    fn list_entries_preserves_insertion_order() {
        let dir = TempDir::new().expect("temp dir");
        let mut storage = Storage::new(dir.path()).expect("storage");

        for id in ["entry-1", "entry-2", "entry-3"] {
            let input = EntryInput {
                id: id.to_string(),
                project: "proj".to_string(),
                host: "host".to_string(),
                screen: "home".to_string(),
                session: "sess-a".to_string(),
                summary: id.to_string(),
                search_text: id.to_string(),
                types: Vec::new(),
                colors: Vec::new(),
                payload: EntryPayload::Text("payload".to_string()),
            };
            storage.append_entry(input).expect("append entry");
        }

        let listed = storage.list_entries(None);
        let ids: Vec<String> = listed.into_iter().map(|meta| meta.id.to_string()).collect();
        assert_eq!(ids, vec!["entry-1".to_string(), "entry-2".to_string(), "entry-3".to_string()]);
    }

    #[test]
    fn list_entries_applies_offset_and_limit() {
        let dir = TempDir::new().expect("temp dir");
        let mut storage = Storage::new(dir.path()).expect("storage");

        for id in ["entry-1", "entry-2", "entry-3", "entry-4"] {
            let input = EntryInput {
                id: id.to_string(),
                project: "proj".to_string(),
                host: "host".to_string(),
                screen: "home".to_string(),
                session: "sess-a".to_string(),
                summary: id.to_string(),
                search_text: id.to_string(),
                types: Vec::new(),
                colors: Vec::new(),
                payload: EntryPayload::Text("payload".to_string()),
            };
            storage.append_entry(input).expect("append entry");
        }

        let filter = EntryFilter { offset: 1, limit: Some(2), ..EntryFilter::default() };
        let listed = storage.list_entries(Some(&filter));
        let ids: Vec<String> = listed.into_iter().map(|meta| meta.id.to_string()).collect();
        assert_eq!(ids, vec!["entry-2".to_string(), "entry-3".to_string()]);
    }

    fn core_entry_payload(color: &str) -> CoreEntry {
        let screen = Screen::new("project-a:host-1:default");
        let origin = Origin {
            project: "project-a".to_string(),
            host: "host-1".to_string(),
            screen: Some(screen.clone()),
            session_id: None,
            function_name: None,
            file: None,
            line_number: None,
        };
        let payload = CorePayload {
            r#type: "log".to_string(),
            content: json!({
                "message": "hello core",
                "color": color,
            }),
            origin,
        };

        CoreEntry {
            uuid: "entry-core".to_string(),
            received_at: 0,
            project: "project-a".to_string(),
            host: "host-1".to_string(),
            screen,
            session_id: None,
            payloads: vec![payload],
        }
    }

    #[test]
    fn list_entries_core_filters_match() {
        let dir = TempDir::new().expect("temp dir");
        let mut storage = Storage::new(dir.path()).expect("storage");

        let core_entry = core_entry_payload("blue");
        let payload_text = serde_json::to_string(&core_entry).expect("serialize core entry");
        let input = EntryInput {
            id: core_entry.uuid.clone(),
            project: core_entry.project.clone(),
            host: core_entry.host.clone(),
            screen: core_entry.screen.as_str().to_string(),
            session: "unknown".to_string(),
            summary: "hello core".to_string(),
            search_text: "hello core log".to_string(),
            types: vec!["log".to_string()],
            colors: vec!["blue".to_string()],
            payload: EntryPayload::Text(payload_text),
        };
        storage.append_entry(input).expect("append entry");

        let filters = CoreFilters {
            query: Some("hello".to_string()),
            types: vec!["log".to_string()],
            colors: vec!["blue".to_string()],
            screen: Some(core_entry.screen.clone()),
            project: Some("project-a".to_string()),
            host: Some("host-1".to_string()),
            limit: Some(1),
            ..Default::default()
        };

        let listed = storage.list_entries_core(&filters).expect("list core entries");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id.as_str(), "entry-core");
    }

    #[test]
    fn list_entries_core_invalid_regex_returns_error() {
        let dir = TempDir::new().expect("temp dir");
        let storage = Storage::new(dir.path()).expect("storage");

        let filters = CoreFilters {
            query: Some("[invalid".to_string()),
            query_is_regex: true,
            ..Default::default()
        };

        let result = storage.list_entries_core(&filters);
        assert!(result.is_err());
    }

    #[test]
    fn list_entries_core_regex_is_case_insensitive() {
        let dir = TempDir::new().expect("temp dir");
        let mut storage = Storage::new(dir.path()).expect("storage");

        let input = EntryInput {
            id: "entry-case".to_string(),
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: "home".to_string(),
            session: "sess-a".to_string(),
            summary: "Hello Core".to_string(),
            search_text: "Hello Core log".to_string(),
            types: Vec::new(),
            colors: Vec::new(),
            payload: EntryPayload::Text("{}".to_string()),
        };
        storage.append_entry(input).expect("append entry");

        let filters = CoreFilters {
            query: Some("hello".to_string()),
            query_is_regex: true,
            ..Default::default()
        };

        let listed = storage.list_entries_core(&filters).expect("list core entries");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id.as_str(), "entry-case");
    }

    #[test]
    fn list_entries_core_types_without_metadata_do_not_match() {
        let dir = TempDir::new().expect("temp dir");
        let mut storage = Storage::new(dir.path()).expect("storage");

        let input = EntryInput {
            id: "entry-no-meta".to_string(),
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: "home".to_string(),
            session: "sess-a".to_string(),
            summary: "no meta".to_string(),
            search_text: "no meta".to_string(),
            types: Vec::new(),
            colors: Vec::new(),
            payload: EntryPayload::Text("not-json".to_string()),
        };
        storage.append_entry(input).expect("append entry");

        let filters = CoreFilters { types: vec!["log".to_string()], ..Default::default() };

        let listed = storage.list_entries_core(&filters).expect("list core entries");
        assert!(listed.is_empty());
    }
}
