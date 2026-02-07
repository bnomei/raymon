use std::collections::{HashMap, HashSet};
use std::path::Path;

use rayon::prelude::*;
use regex::Regex;
use serde_json::Value;

use raymon_core::{Entry as CoreEntry, FilterError as CoreFilterError, Filters as CoreFilters};

use crate::{jsonl, EntryFilter, OffsetMeta, StorageError, StoredEntry, StoredPayload};

#[derive(Debug, Clone)]
pub(crate) struct IndexRecord {
    pub(crate) meta: OffsetMeta,
    project: Option<String>,
    host: Option<String>,
    types: Vec<String>,
    colors: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct Index {
    order: Vec<String>,
    by_id: HashMap<String, IndexRecord>,
    by_screen_session: HashMap<(String, String), Vec<String>>,
}

impl Index {
    pub(crate) fn insert(&mut self, record: IndexRecord) {
        let id = record.meta.id.clone();
        let key = (record.meta.screen.clone(), record.meta.session.clone());
        self.by_screen_session.entry(key).or_default().push(id.clone());
        if !self.by_id.contains_key(&id) {
            self.order.push(id.clone());
        }
        self.by_id.insert(id, record);
    }

    pub(crate) fn get_by_id(&self, id: &str) -> Option<&OffsetMeta> {
        self.by_id.get(id).map(|record| &record.meta)
    }

    pub(crate) fn list(&self, filter: Option<&EntryFilter>) -> Vec<OffsetMeta> {
        const PAR_FILTER_THRESHOLD: usize = 2048;
        let (offset, limit) = filter
            .map(|filter| (filter.offset, filter.limit))
            .unwrap_or((0, None));

        let mut items: Vec<OffsetMeta> = match filter {
            None => self
                .order
                .iter()
                .filter_map(|id| self.by_id.get(id).map(|record| record.meta.clone()))
                .collect(),
            Some(filter) => {
                if self.order.len() >= PAR_FILTER_THRESHOLD {
                    let mut hits: Vec<(usize, OffsetMeta)> = self
                        .order
                        .par_iter()
                        .enumerate()
                        .filter_map(|(idx, id)| {
                            let meta = self.by_id.get(id)?;
                            if filter.matches(&meta.meta) {
                                Some((idx, meta.meta.clone()))
                            } else {
                                None
                            }
                        })
                        .collect();
                    hits.sort_unstable_by_key(|(idx, _)| *idx);
                    hits.into_iter().map(|(_, meta)| meta).collect()
                } else {
                    self.order
                        .iter()
                        .filter_map(|id| self.by_id.get(id))
                        .filter(|record| filter.matches(&record.meta))
                        .map(|record| record.meta.clone())
                        .collect()
                }
            }
        };

        if offset > 0 || limit.is_some() {
            let start = offset.min(items.len());
            let end = limit
                .map(|limit| start.saturating_add(limit).min(items.len()))
                .unwrap_or(items.len());
            items = items[start..end].to_vec();
        }

        items
    }

    pub(crate) fn list_core(
        &self,
        filters: &CoreFilters,
    ) -> Result<Vec<OffsetMeta>, CoreFilterError> {
        const PAR_FILTER_THRESHOLD: usize = 2048;
        let matcher = compile_query(filters)?;

        if self.order.len() >= PAR_FILTER_THRESHOLD {
            let matches: Vec<bool> = self
                .order
                .par_iter()
                .map(|id| {
                    self.by_id
                        .get(id)
                        .map(|record| record.matches_core(filters, matcher.as_ref()))
                        .unwrap_or(false)
                })
                .collect();
            Ok(apply_offset_limit(
                &self.order,
                &self.by_id,
                &matches,
                filters.offset,
                filters.limit,
            ))
        } else {
            Ok(apply_offset_limit_sequential(
                &self.order,
                &self.by_id,
                filters,
                matcher.as_ref(),
            ))
        }
    }
}

pub(crate) fn rebuild(entries_path: &Path) -> Result<Index, StorageError> {
    let mut index = Index::default();
    jsonl::scan_entries(entries_path, |offset, len, entry| {
        index.insert(record_from_entry(entry, offset, len));
    })?;
    Ok(index)
}

pub(crate) fn record_from_entry(entry: &StoredEntry, offset: u64, len: u64) -> IndexRecord {
    let core_meta = derive_core_metadata(entry);
    let summary_lower = entry.summary.to_lowercase();
    let search_text_lower = entry.search_text.to_lowercase();
    let meta = OffsetMeta {
        id: entry.id.clone(),
        project: entry.project.clone(),
        host: entry.host.clone(),
        screen: entry.screen.clone(),
        session: entry.session.clone(),
        summary: entry.summary.clone(),
        search_text: entry.search_text.clone(),
        summary_lower,
        search_text_lower,
        offset,
        len,
    };

    IndexRecord {
        meta,
        project: core_meta.project,
        host: core_meta.host,
        types: core_meta.types,
        colors: core_meta.colors,
    }
}

#[derive(Debug, Default)]
struct CoreMetadata {
    project: Option<String>,
    host: Option<String>,
    types: Vec<String>,
    colors: Vec<String>,
}

fn derive_core_metadata(entry: &StoredEntry) -> CoreMetadata {
    let text = match &entry.payload {
        StoredPayload::Text { text } => text,
        _ => {
            return CoreMetadata {
                project: Some(entry.project.clone()),
                host: Some(entry.host.clone()),
                types: Vec::new(),
                colors: Vec::new(),
            }
        }
    };
    let Ok(core_entry) = serde_json::from_str::<CoreEntry>(text) else {
        return CoreMetadata {
            project: Some(entry.project.clone()),
            host: Some(entry.host.clone()),
            types: Vec::new(),
            colors: Vec::new(),
        };
    };

    let mut types = Vec::new();
    let mut colors = Vec::new();
    let mut seen_types = HashSet::new();
    let mut seen_colors = HashSet::new();

    for payload in &core_entry.payloads {
        if seen_types.insert(payload.r#type.as_str()) {
            types.push(payload.r#type.clone());
        }
        if let Some(color) = payload_color(&payload.content) {
            if seen_colors.insert(color) {
                colors.push(color.to_string());
            }
        }
    }

    CoreMetadata {
        project: Some(entry.project.clone()),
        host: Some(entry.host.clone()),
        types,
        colors,
    }
}

fn payload_color(value: &Value) -> Option<&str> {
    match value.get("color") {
        Some(Value::String(color)) => Some(color.as_str()),
        _ => None,
    }
}

impl IndexRecord {
    fn matches_core(&self, filters: &CoreFilters, query: Option<&QueryMatcher>) -> bool {
        if let Some(project) = &filters.project {
            if self.project.as_deref() != Some(project.as_str()) {
                return false;
            }
        }

        if let Some(host) = &filters.host {
            if self.host.as_deref() != Some(host.as_str()) {
                return false;
            }
        }

        if let Some(screen) = &filters.screen {
            if self.meta.screen != screen.as_str() {
                return false;
            }
        }

        if !filters.types.is_empty() {
            if self.types.is_empty()
                || !filters
                    .types
                    .iter()
                    .any(|filter_type| self.types.iter().any(|value| value == filter_type))
            {
                return false;
            }
        }

        if !filters.colors.is_empty() {
            if self.colors.is_empty()
                || !filters
                    .colors
                    .iter()
                    .any(|filter_color| self.colors.iter().any(|value| value == filter_color))
            {
                return false;
            }
        }

        if let Some(query) = query {
            if !query.matches(
                &self.meta.summary,
                &self.meta.search_text,
                &self.meta.summary_lower,
                &self.meta.search_text_lower,
            ) {
                return false;
            }
        }

        true
    }
}

#[derive(Clone, Debug)]
enum QueryMatcher {
    Substring(String),
    Regex(Regex),
}

impl QueryMatcher {
    fn matches(
        &self,
        summary: &str,
        search_text: &str,
        summary_lower: &str,
        search_text_lower: &str,
    ) -> bool {
        match self {
            QueryMatcher::Substring(query) => {
                summary_lower.contains(query) || search_text_lower.contains(query)
            }
            QueryMatcher::Regex(regex) => regex.is_match(summary) || regex.is_match(search_text),
        }
    }
}

fn compile_query(filters: &CoreFilters) -> Result<Option<QueryMatcher>, CoreFilterError> {
    let query = match filters.query.as_ref().map(|q| q.trim()).filter(|q| !q.is_empty()) {
        Some(query) => query,
        None => return Ok(None),
    };

    if filters.query_is_regex {
        let pattern = strip_regex_delimiters(query).unwrap_or(query);
        return Ok(Some(QueryMatcher::Regex(compile_regex(pattern)?)));
    }

    if let Some(pattern) = strip_regex_delimiters(query) {
        return Ok(Some(QueryMatcher::Regex(compile_regex(pattern)?)));
    }

    Ok(Some(QueryMatcher::Substring(query.to_lowercase())))
}

fn strip_regex_delimiters(query: &str) -> Option<&str> {
    query.strip_prefix('/').and_then(|q| q.strip_suffix('/'))
}

fn compile_regex(pattern: &str) -> Result<Regex, CoreFilterError> {
    Regex::new(pattern).map_err(|error| CoreFilterError::InvalidRegex {
        pattern: pattern.to_string(),
        message: error.to_string(),
    })
}

fn apply_offset_limit(
    order: &[String],
    records: &HashMap<String, IndexRecord>,
    matches: &[bool],
    offset: usize,
    limit: Option<usize>,
) -> Vec<OffsetMeta> {
    let mut matched = Vec::new();
    let mut skipped = 0usize;

    for (id, is_match) in order.iter().zip(matches.iter().copied()) {
        if !is_match {
            continue;
        }

        if skipped < offset {
            skipped += 1;
            continue;
        }

        if let Some(record) = records.get(id) {
            matched.push(record.meta.clone());
        }

        if let Some(limit) = limit {
            if matched.len() >= limit {
                break;
            }
        }
    }

    matched
}

fn apply_offset_limit_sequential(
    order: &[String],
    records: &HashMap<String, IndexRecord>,
    filters: &CoreFilters,
    matcher: Option<&QueryMatcher>,
) -> Vec<OffsetMeta> {
    let mut matched = Vec::new();
    let mut skipped = 0usize;

    for id in order {
        let Some(record) = records.get(id) else {
            continue;
        };

        if !record.matches_core(filters, matcher) {
            continue;
        }

        if skipped < filters.offset {
            skipped += 1;
            continue;
        }

        matched.push(record.meta.clone());

        if let Some(limit) = filters.limit {
            if matched.len() >= limit {
                break;
            }
        }
    }

    matched
}
