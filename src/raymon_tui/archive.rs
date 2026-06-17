use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::Instant;

use chrono::{DateTime, Utc};

/// File-backed archive entry.
#[derive(Debug, Clone)]
pub struct ArchiveFile {
    pub name: String,
    pub count: usize,
    pub path: PathBuf,
    pub live: bool,
}

pub(super) const LIVE_ARCHIVE_FLUSH_EVERY_ENTRIES: usize = 64;
pub(super) const LIVE_ARCHIVE_FLUSH_EVERY_MS: u64 = 1_000;

pub(super) struct LiveArchive {
    pub path: PathBuf,
    pub writer: BufWriter<File>,
    pub writes_since_flush: usize,
    pub last_flush_at: Instant,
}

pub(super) fn archive_stamp(now: DateTime<Utc>) -> String {
    let millis = now.timestamp_subsec_millis();
    format!("{}-{:03}Z", now.format("%Y%m%dT%H%M%S"), millis)
}

pub(super) fn archive_display_name(path: &Path) -> String {
    path.file_stem().and_then(|value| value.to_str()).unwrap_or("archive").to_string()
}

pub(super) fn create_unique_jsonl_file(
    dir: &Path,
    base_name: &str,
) -> Result<(PathBuf, File), std::io::Error> {
    for attempt in 0..=999u16 {
        let filename = if attempt == 0 {
            format!("{base_name}.jsonl")
        } else {
            format!("{base_name}-{attempt}.jsonl")
        };
        let path = dir.join(filename);
        match OpenOptions::new().create_new(true).append(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "archive file already exists"))
}

pub(super) fn scan_archives(
    dir: &Path,
    live_path: Option<&Path>,
) -> Result<Vec<ArchiveFile>, std::io::Error> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };

    let mut archives = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("jsonl") {
            continue;
        }

        let name = archive_display_name(&path);
        let count = count_jsonl_lines(&path)?;
        let live = live_path.is_some_and(|live| live == path.as_path());
        archives.push(ArchiveFile { name, count, path, live });
    }

    Ok(archives)
}

fn count_jsonl_lines(path: &Path) -> Result<usize, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0usize;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        count += 1;
    }
    Ok(count)
}
