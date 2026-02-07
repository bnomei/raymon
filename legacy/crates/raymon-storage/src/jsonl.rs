use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use tracing::warn;

use crate::{StorageError, StoredEntry};

pub(crate) fn append_entry(path: &Path, entry: &StoredEntry) -> Result<(u64, u64), StorageError> {
    let line = serde_json::to_vec(entry)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .open(path)?;
    let offset = file.metadata()?.len();
    file.write_all(&line)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok((offset, line.len() as u64))
}

pub(crate) fn read_entry_at(
    path: &Path,
    offset: u64,
    len: u64,
) -> Result<StoredEntry, StorageError> {
    if len == 0 {
        return Err(StorageError::InvalidOffset { offset, len });
    }
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len as usize];
    file.read_exact(&mut buf)?;
    Ok(serde_json::from_slice(&buf)?)
}

pub(crate) fn scan_entries<F>(path: &Path, mut on_entry: F) -> Result<(), StorageError>
where
    F: FnMut(u64, u64, &StoredEntry),
{
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    let mut reader = BufReader::new(file);
    let mut offset = 0u64;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let bytes = reader.read_until(b'\n', &mut buf)?;
        if bytes == 0 {
            break;
        }
        let mut line_bytes = buf.as_slice();
        if line_bytes.ends_with(b"\n") {
            line_bytes = &line_bytes[..line_bytes.len() - 1];
        }
        if line_bytes.ends_with(b"\r") {
            line_bytes = &line_bytes[..line_bytes.len() - 1];
        }
        if line_bytes.is_empty() {
            offset += bytes as u64;
            continue;
        }
        match serde_json::from_slice::<StoredEntry>(line_bytes) {
            Ok(entry) => on_entry(offset, line_bytes.len() as u64, &entry),
            Err(err) => {
                warn!(?err, offset, "Skipping corrupt JSONL entry");
            }
        }
        offset += bytes as u64;
    }
    Ok(())
}
