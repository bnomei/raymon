use raymon::raymon_core::{Entry, Filters, Origin, Payload, Screen};
use serde_json::{json, Map, Value};

fn main() {
    divan::main();
}

fn make_entries(len: usize, content: Value) -> Vec<Entry> {
    let project = "project-a".to_string();
    let host = "host-1".to_string();
    let screen = Screen::new("project-a:host-1:default");

    let origin = Origin {
        project: project.clone(),
        host: host.clone(),
        screen: Some(screen.clone()),
        session_id: None,
        function_name: None,
        file: None,
        line_number: Some(123),
    };

    (0..len)
        .map(|idx| Entry {
            uuid: format!("entry-{idx}"),
            received_at: idx as u64,
            project: project.clone(),
            host: host.clone(),
            screen: screen.clone(),
            session_id: None,
            payloads: vec![Payload {
                r#type: "log".to_string(),
                content: content.clone(),
                origin: origin.clone(),
            }],
        })
        .collect()
}

fn make_entries_realistic_string(len: usize) -> Vec<Entry> {
    let project = "project-a".to_string();
    let host = "host-1".to_string();
    let screen = Screen::new("project-a:host-1:default");

    let origin = Origin {
        project: project.clone(),
        host: host.clone(),
        screen: Some(screen.clone()),
        session_id: None,
        function_name: None,
        file: None,
        line_number: Some(123),
    };

    (0..len)
        .map(|idx| {
            let level = match idx % 4 {
                0 => "INFO",
                1 => "WARN",
                2 => "DEBUG",
                _ => "ERROR",
            };

            let request_id = format!("{idx:08x}");
            let mut message = String::new();
            message.push_str(level);
            message.push_str(" request_id=");
            message.push_str(&request_id);
            message.push_str(" path=/api/v1/items duration_ms=");
            message.push_str(&(idx % 100).to_string());
            message.push_str(" msg=The quick brown fox jumps over the lazy dog");

            Entry {
                uuid: format!("entry-{idx}"),
                received_at: idx as u64,
                project: project.clone(),
                host: host.clone(),
                screen: screen.clone(),
                session_id: None,
                payloads: vec![Payload {
                    r#type: "log".to_string(),
                    content: Value::String(message),
                    origin: origin.clone(),
                }],
            }
        })
        .collect()
}

fn make_entries_realistic_object(len: usize) -> Vec<Entry> {
    let project = "project-a".to_string();
    let host = "host-1".to_string();
    let screen = Screen::new("project-a:host-1:default");

    let origin = Origin {
        project: project.clone(),
        host: host.clone(),
        screen: Some(screen.clone()),
        session_id: None,
        function_name: None,
        file: None,
        line_number: Some(123),
    };

    (0..len)
        .map(|idx| {
            let level = match idx % 4 {
                0 => "info",
                1 => "warn",
                2 => "debug",
                _ => "error",
            };
            let color = match idx % 3 {
                0 => "red",
                1 => "green",
                _ => "blue",
            };

            let content = json!({
                "message": format!("Processed request for entry {idx}"),
                "level": level,
                "color": color,
                "context": {
                    "file": "main.rs",
                    "line": idx,
                    "tags": ["alpha", "beta", "gamma", format!("id-{idx}")]
                },
                "nested": {
                    "a": "b",
                    "c": [1, 2, 3, idx],
                    "extra": {
                        "note": "The quick brown fox jumps over the lazy dog",
                        "ok": true
                    }
                },
                "metrics": {
                    "duration_ms": idx % 100,
                    "ratio": 0.123
                }
            });

            Entry {
                uuid: format!("entry-{idx}"),
                received_at: idx as u64,
                project: project.clone(),
                host: host.clone(),
                screen: screen.clone(),
                session_id: None,
                payloads: vec![Payload {
                    r#type: "log".to_string(),
                    content,
                    origin: origin.clone(),
                }],
            }
        })
        .collect()
}

fn make_object_with_strings(count: usize) -> Value {
    let mut map = Map::new();
    for idx in 0..count {
        map.insert(
            format!("key_{idx:02}"),
            Value::String("The quick brown fox jumps over the lazy dog".to_string()),
        );
    }
    Value::Object(map)
}

#[divan::bench(args = [256usize, 2048usize, 8192usize])]
fn filters_substring_string_miss(bencher: divan::Bencher, len: usize) {
    let entries = make_entries(len, Value::String("Hello there".to_string()));
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply(entries.iter()).expect("filters apply");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [256usize, 2048usize, 8192usize])]
fn filters_substring_string_miss_parallel(bencher: divan::Bencher, len: usize) {
    let entries = make_entries(len, Value::String("Hello there".to_string()));
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply_parallel(&entries).expect("filters apply_parallel");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [2048usize, 8192usize])]
fn filters_substring_string_miss_realistic(bencher: divan::Bencher, len: usize) {
    let entries = make_entries_realistic_string(len);
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply(entries.iter()).expect("filters apply");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [2048usize, 8192usize])]
fn filters_substring_string_miss_realistic_parallel(bencher: divan::Bencher, len: usize) {
    let entries = make_entries_realistic_string(len);
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply_parallel(&entries).expect("filters apply_parallel");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [256usize, 2048usize, 8192usize])]
fn filters_substring_object_miss(bencher: divan::Bencher, len: usize) {
    let content = json!({
        "message": "Hello there",
        "color": "red",
        "nested": {"a": "b", "c": [1, 2, 3]},
        "extra": "field"
    });
    let entries = make_entries(len, content);
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply(entries.iter()).expect("filters apply");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [256usize, 2048usize, 8192usize])]
fn filters_substring_object_miss_parallel(bencher: divan::Bencher, len: usize) {
    let content = json!({
        "message": "Hello there",
        "color": "red",
        "nested": {"a": "b", "c": [1, 2, 3]},
        "extra": "field"
    });
    let entries = make_entries(len, content);
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply_parallel(&entries).expect("filters apply_parallel");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [2048usize, 8192usize])]
fn filters_substring_object_miss_many_string_fields(bencher: divan::Bencher, len: usize) {
    let entries = make_entries(len, make_object_with_strings(30));
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply(entries.iter()).expect("filters apply");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [2048usize, 8192usize])]
fn filters_substring_object_miss_many_string_fields_parallel(bencher: divan::Bencher, len: usize) {
    let entries = make_entries(len, make_object_with_strings(30));
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply_parallel(&entries).expect("filters apply_parallel");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [2048usize, 8192usize])]
fn filters_substring_object_miss_realistic(bencher: divan::Bencher, len: usize) {
    let entries = make_entries_realistic_object(len);
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply(entries.iter()).expect("filters apply");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [2048usize, 8192usize])]
fn filters_substring_object_miss_realistic_parallel(bencher: divan::Bencher, len: usize) {
    let entries = make_entries_realistic_object(len);
    let filters = Filters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply_parallel(&entries).expect("filters apply_parallel");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [256usize, 2048usize])]
fn filters_substring_object_hit_limit_1(bencher: divan::Bencher, len: usize) {
    let content = json!({
        "message": "Hello there",
        "color": "red",
        "nested": {"a": "b", "c": [1, 2, 3]},
        "extra": "field"
    });
    let entries = make_entries(len, content);
    let filters =
        Filters { query: Some("hello".to_string()), limit: Some(1), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply(entries.iter()).expect("filters apply");
        divan::black_box(matched.len());
    });
}

#[divan::bench(args = [256usize, 2048usize])]
fn filters_substring_object_hit_limit_1_parallel(bencher: divan::Bencher, len: usize) {
    let content = json!({
        "message": "Hello there",
        "color": "red",
        "nested": {"a": "b", "c": [1, 2, 3]},
        "extra": "field"
    });
    let entries = make_entries(len, content);
    let filters =
        Filters { query: Some("hello".to_string()), limit: Some(1), ..Default::default() };

    bencher.counter(len).bench(|| {
        let matched = filters.apply_parallel(&entries).expect("filters apply_parallel");
        divan::black_box(matched.len());
    });
}
