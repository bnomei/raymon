use std::fs::{self, File};
use std::io::{self, BufRead};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
struct StoredEntry {
    id: String,
    #[serde(default)]
    types: Vec<String>,
    #[serde(default)]
    colors: Vec<String>,
    payload: StoredPayload,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredPayload {
    Text { text: String },
    Blob { path: String, size: u64 },
}

impl StoredEntry {
    fn payload_text(&self) -> Option<&str> {
        match &self.payload {
            StoredPayload::Text { text } => Some(text),
            StoredPayload::Blob { .. } => None,
        }
    }
}

struct RaymonGuard {
    child: Child,
}

impl Drop for RaymonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn entries_path(storage_root: &Path) -> PathBuf {
    storage_root.join("data").join("entries.jsonl")
}

fn wait_for_port(host: &str, port: u16, timeout: Duration) -> io::Result<()> {
    let addr = format!("{host}:{port}");
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(&addr) {
            Ok(_) => return Ok(()),
            Err(err) if Instant::now() < deadline => {
                // Keep the retry tight; these tests are local-only.
                let _ = err;
                thread::sleep(Duration::from_millis(30));
            }
            Err(err) => return Err(err),
        }
    }
}

fn read_stored_entries(path: &Path) -> io::Result<Vec<StoredEntry>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<StoredEntry>(&line) {
            Ok(entry) => entries.push(entry),
            Err(_) => {
                // Ignore partial lines while the server is writing.
            }
        }
    }
    Ok(entries)
}

fn wait_for_marker_entry(path: &Path, marker: &str, timeout: Duration) -> io::Result<Option<StoredEntry>> {
    let deadline = Instant::now() + timeout;
    loop {
        let entries = read_stored_entries(path)?;
        let mut found = None;
        for entry in entries {
            if entry.payload_text().is_some_and(|text| text.contains(marker)) {
                found = Some(entry);
            }
        }
        if found.is_some() {
            return Ok(found);
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(40));
    }
}

#[test]
#[ignore]
fn ray_php_local_integration() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("CI").is_some() {
        // Explicit local-only test (even if someone runs ignored tests in CI).
        return Ok(());
    }

    let host = std::env::var("RAYMON_IT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = match std::env::var("RAYMON_IT_PORT").ok().and_then(|value| value.parse::<u16>().ok()) {
        Some(port) => port,
        None => {
            let listener = TcpListener::bind((host.as_str(), 0))
                .map_err(|err| format!("cannot bind {host}:0 to pick a free port: {err}"))?;
            let port = listener
                .local_addr()
                .map_err(|err| format!("cannot read selected port for {host}: {err}"))?
                .port();
            drop(listener);
            port
        }
    };

    let storage_root = tempfile::tempdir()?;
    let stderr_path = storage_root.path().join("raymon-stderr.log");
    let stderr_file = File::create(&stderr_path)?;

    let child = Command::new(env!("CARGO_BIN_EXE_raymon"))
        .env("RAYMON_HOST", &host)
        .env("RAYMON_PORT", port.to_string())
        .env("RAYMON_NO_TUI", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file))
        .current_dir(storage_root.path())
        .spawn()
        .map_err(|err| format!("failed to spawn raymon: {err}"))?;
    let raymon = RaymonGuard { child };

    wait_for_port(&host, port, Duration::from_secs(3)).map_err(|err| {
        let stderr = fs::read_to_string(&stderr_path).unwrap_or_else(|_| "<unable to read raymon stderr log>".to_string());
        format!(
            "raymon did not start listening on {host}:{port}: {err}\n\nraymon stderr log ({path}):\n{stderr}",
            path = stderr_path.display()
        )
    })?;

    let php_script = repo_root().join("tests").join("ray.php");
    let entries = entries_path(storage_root.path());

    let cases = [
        "log",
        "table",
        "json",
        "custom_html",
        "custom_text",
        "color_named",
        "color_method",
        "label",
        "xml",
        "file",
        "image_url",
        "phpinfo",
        "trace",
        "count",
        "measure",
        "limit",
        "once",
        "showif_true",
        "showif_false",
        "if_true",
        "exception",
        "send",
    ];

    for case in cases {
        let token = uuid::Uuid::new_v4().simple().to_string();
        let marker = format!("raymon-it:{token}:{case}");

        let output = Command::new("php")
            .arg(&php_script)
            .arg("--case")
            .arg(case)
            .arg("--token")
            .arg(&token)
            // Best-effort: help Ray PHP talk to this Raymon instance.
            .arg("--ray-host")
            .arg(&host)
            .arg("--ray-port")
            .arg(port.to_string())
            .env("RAY_HOST", &host)
            .env("RAY_PORT", port.to_string())
            .output()
            .map_err(|err| format!("failed to run php for case `{case}`: {err}"))?;

        if !output.status.success() {
            return Err(format!(
                "php case `{case}` failed (exit {:?})\nstdout:\n{}\nstderr:\n{}\n\nraymon stderr log: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
                stderr_path.display(),
            )
            .into());
        }

        let stored = wait_for_marker_entry(&entries, &marker, Duration::from_secs(2))?.ok_or_else(|| {
            format!(
                "case `{case}`: no entry found for marker `{marker}` within timeout.\nraymon stderr log: {}",
                stderr_path.display(),
            )
        })?;

        match case {
            "log" => assert!(
                stored.types.iter().any(|t| t == "log"),
                "case `{case}`: expected types to include `log`, got: {:?}",
                stored.types
            ),
            "table" => assert!(
                stored.types.iter().any(|t| t == "table"),
                "case `{case}`: expected types to include `table`, got: {:?}",
                stored.types
            ),
            "json" => assert!(
                stored.types.iter().any(|t| t == "json_string"),
                "case `{case}`: expected types to include `json_string`, got: {:?}",
                stored.types
            ),
            "custom_html" | "custom_text" => assert!(
                stored.types.iter().any(|t| t == "custom"),
                "case `{case}`: expected types to include `custom`, got: {:?}",
                stored.types
            ),
            "color_named" => assert!(
                stored.colors.iter().any(|c| c == "red"),
                "case `{case}`: expected colors to include `red`, got: {:?}",
                stored.colors
            ),
            "color_method" => assert!(
                stored.colors.iter().any(|c| c == "green"),
                "case `{case}`: expected colors to include `green`, got: {:?}",
                stored.colors
            ),
            "showif_false" => assert!(
                stored.types.iter().any(|t| t == "remove"),
                "case `{case}`: expected types to include `remove`, got: {:?}",
                stored.types
            ),
            "exception" => assert!(
                stored.types.iter().any(|t| t == "exception"),
                "case `{case}`: expected types to include `exception`, got: {:?}",
                stored.types
            ),
            _ => assert!(
                !stored.types.is_empty(),
                "case `{case}`: expected at least one payload type, got: {:?}",
                stored.types
            ),
        }
    }

    drop(raymon);
    Ok(())
}
