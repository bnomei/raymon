use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{BLOBS_DIR, StorageError};

static BLOB_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn store_blob(blobs_dir: &Path, bytes: &[u8]) -> Result<(String, u64), StorageError> {
    fs::create_dir_all(blobs_dir)?;
    let name = generate_blob_name();
    let path = blobs_dir.join(&name);
    let mut file = File::create(&path)?;
    file.write_all(bytes)?;
    file.flush()?;
    let relative = format!("{}/{}", BLOBS_DIR, name);
    Ok((relative, bytes.len() as u64))
}

fn generate_blob_name() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = BLOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("blob-{}-{}", now, counter)
}
