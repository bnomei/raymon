use std::sync::atomic::{AtomicUsize, Ordering};

use raymon::raymon_core::{Entry, Event, RayEnvelope};
use raymon::raymon_ingest::{EventBus, Ingestor, StateStore, Storage};
use serde_json::{json, Value};

fn main() {
    divan::main();
}

fn fixed_clock() -> u64 {
    1_700_000_000_000
}

fn make_body(payload_count: usize, content: Value) -> Vec<u8> {
    let payloads: Vec<Value> = (0..payload_count)
        .map(|idx| {
            json!({
                "type": "log",
                "content": content.clone(),
                "origin": {
                    "hostname": "host-1",
                    "fileName": "main.rs",
                    "lineNumber": 123 + idx,
                    "functionName": "bench_ingest",
                }
            })
        })
        .collect();

    serde_json::to_vec(&json!({
        "uuid": "bench-uuid-1",
        "payloads": payloads,
        "meta": {
            "projectName": "project-a",
            "host": "host-1",
            "screenName": "project-a:host-1:default",
        }
    }))
    .expect("serialize body")
}

#[derive(Default)]
struct NoopState;

impl StateStore for NoopState {
    fn insert_entry(&self, _entry: Entry) -> Result<(), String> {
        Ok(())
    }

    fn update_entry(&self, _entry: Entry) -> Result<(), String> {
        Ok(())
    }

    fn get_entry(&self, _uuid: &str) -> Result<Option<Entry>, String> {
        Ok(None)
    }
}

struct FixedState {
    entry: Entry,
}

impl StateStore for FixedState {
    fn insert_entry(&self, _entry: Entry) -> Result<(), String> {
        Ok(())
    }

    fn update_entry(&self, _entry: Entry) -> Result<(), String> {
        Ok(())
    }

    fn get_entry(&self, _uuid: &str) -> Result<Option<Entry>, String> {
        Ok(Some(self.entry.clone()))
    }
}

#[derive(Default)]
struct NoopStorage {
    appended: AtomicUsize,
}

impl Storage for NoopStorage {
    fn append_entry(&self, _entry: &Entry) -> Result<(), String> {
        self.appended.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[derive(Default)]
struct NoopBus;

impl EventBus for NoopBus {
    fn emit(&self, _event: Event) -> Result<(), String> {
        Ok(())
    }
}

#[divan::bench(args = [1usize, 8usize])]
fn ingest_new_object(bencher: divan::Bencher, payload_count: usize) {
    let body = make_body(
        payload_count,
        json!({
            "message": "Hello there",
            "color": "red",
            "nested": { "a": "b", "c": [1, 2, 3] },
            "extra": "field"
        }),
    );

    let state = NoopState;
    let storage = NoopStorage::default();
    let bus = NoopBus;
    let ingestor = Ingestor::new(&state, &storage, &bus, fixed_clock);

    bencher.bench(|| {
        let entry = ingestor.handle_inner(&body).expect("ingest");
        divan::black_box(entry);
    });
}

#[divan::bench]
fn ingest_new_blob_redaction(bencher: divan::Bencher) {
    let blob = format!("data:text/plain;base64,{}", "A".repeat(32 * 1024));
    let body = make_body(1, Value::String(blob));

    let state = NoopState;
    let storage = NoopStorage::default();
    let bus = NoopBus;
    let ingestor = Ingestor::new(&state, &storage, &bus, fixed_clock);

    bencher.bench(|| {
        let entry = ingestor.handle_inner(&body).expect("ingest");
        divan::black_box(entry);
    });
}

#[divan::bench]
fn ingest_new_symfony_html_strip(bencher: divan::Bencher) {
    let dump = r#"<script> Sfdump = window.Sfdump || (function () {})</script>
<pre class=sf-dump id=sf-dump-1 data-indent-pad="  ">
<span class=sf-dump-note>array:2</span> [<samp>
  <span class=sf-dump-index>0</span> => <span class=sf-dump-num>12</span>
  <span class=sf-dump-index>1</span> => <span class=sf-dump-num>3</span> <span>&#9654;</span>
</samp>]
</pre><script>Sfdump(\"sf-dump-1\")</script>"#;
    let body = make_body(1, Value::String(dump.to_string()));

    let state = NoopState;
    let storage = NoopStorage::default();
    let bus = NoopBus;
    let ingestor = Ingestor::new(&state, &storage, &bus, fixed_clock);

    bencher.bench(|| {
        let entry = ingestor.handle_inner(&body).expect("ingest");
        divan::black_box(entry);
    });
}

#[divan::bench]
fn ingest_update_merge_payloads(bencher: divan::Bencher) {
    let body = make_body(
        1,
        json!({
            "message": "Hello there",
            "color": "red",
            "nested": { "a": "b", "c": [1, 2, 3] },
            "extra": "field"
        }),
    );

    let envelope: RayEnvelope = serde_json::from_slice(&body).expect("parse envelope");
    let existing = envelope.clone().into_entry(fixed_clock());
    let state = FixedState { entry: existing };
    let storage = NoopStorage::default();
    let bus = NoopBus;
    let ingestor = Ingestor::new(&state, &storage, &bus, fixed_clock);

    bencher.bench(|| {
        let entry = ingestor.handle_inner(&body).expect("ingest");
        divan::black_box(entry);
    });
}
