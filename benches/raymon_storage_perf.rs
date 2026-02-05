#[path = "../src/colors.rs"]
mod colors;

#[path = "../src/raymon_core.rs"]
mod raymon_core;

#[path = "../src/raymon_storage/mod.rs"]
mod raymon_storage;

use raymon_core::Filters as CoreFilters;
use raymon_storage::{EntryFilter, EntryInput, EntryPayload, Storage};
use tempfile::TempDir;

fn main() {
    divan::main();
}

struct BenchStorage {
    _dir: TempDir,
    storage: Storage,
}

fn make_storage(len: usize) -> BenchStorage {
    let dir = TempDir::new().expect("temp dir");
    let mut storage = Storage::new(dir.path()).expect("storage");

    for idx in 0..len {
        let summary = if idx == 0 { "needle".to_string() } else { "entry".to_string() };
        let search_text =
            if idx == 0 { "needle haystack".to_string() } else { format!("entry-{idx}") };

        let input = EntryInput {
            id: format!("entry-{idx}"),
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: "home".to_string(),
            session: "sess-a".to_string(),
            summary,
            search_text,
            types: vec!["log".to_string()],
            colors: vec!["red".to_string()],
            payload: EntryPayload::Text("payload".to_string()),
        };

        storage.append_entry(input).expect("append entry");
    }

    BenchStorage { _dir: dir, storage }
}

fn make_storage_long_text(len: usize) -> BenchStorage {
    let dir = TempDir::new().expect("temp dir");
    let mut storage = Storage::new(dir.path()).expect("storage");

    let shared = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";

    for idx in 0..len {
        let summary =
            if idx == 0 { format!("needle {shared}") } else { format!("entry {idx} {shared}") };

        let search_text = if idx == 0 {
            format!("needle haystack {shared} {shared}")
        } else {
            format!("entry-{idx} {shared} {shared}")
        };

        let input = EntryInput {
            id: format!("entry-{idx}"),
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: "home".to_string(),
            session: "sess-a".to_string(),
            summary,
            search_text,
            types: vec!["log".to_string()],
            colors: vec!["red".to_string()],
            payload: EntryPayload::Text("payload".to_string()),
        };

        storage.append_entry(input).expect("append entry");
    }

    BenchStorage { _dir: dir, storage }
}

#[divan::bench(args = [1024usize, 4096usize, 8192usize])]
fn storage_list_entries_no_filter(bencher: divan::Bencher, len: usize) {
    let storage = make_storage(len);
    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries(None);
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_no_filter_long_text(bencher: divan::Bencher, len: usize) {
    let storage = make_storage_long_text(len);
    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries(None);
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_core_no_filter_long_text(bencher: divan::Bencher, len: usize) {
    let storage = make_storage_long_text(len);
    let filters = CoreFilters::default();

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries_core(&filters).expect("list_entries_core");
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize, 8192usize])]
fn storage_list_entries_filter_query_miss(bencher: divan::Bencher, len: usize) {
    let storage = make_storage(len);
    let filter =
        EntryFilter { query: Some("does-not-exist".to_string()), ..EntryFilter::default() };

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries(Some(&filter));
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_filter_query_miss_long_text(bencher: divan::Bencher, len: usize) {
    let storage = make_storage_long_text(len);
    let filter =
        EntryFilter { query: Some("does-not-exist".to_string()), ..EntryFilter::default() };

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries(Some(&filter));
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_filter_query_hit_limit_1(bencher: divan::Bencher, len: usize) {
    let storage = make_storage(len);
    let filter =
        EntryFilter { query: Some("needle".to_string()), limit: Some(1), ..EntryFilter::default() };

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries(Some(&filter));
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize, 8192usize])]
fn storage_list_entries_core_query_miss(bencher: divan::Bencher, len: usize) {
    let storage = make_storage(len);
    let mut filters = CoreFilters::default();
    filters.query = Some("does-not-exist".to_string());

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries_core(&filters).expect("list_entries_core");
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_core_query_miss_long_text(bencher: divan::Bencher, len: usize) {
    let storage = make_storage_long_text(len);
    let mut filters = CoreFilters::default();
    filters.query = Some("does-not-exist".to_string());

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries_core(&filters).expect("list_entries_core");
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_core_query_hit_limit_1(bencher: divan::Bencher, len: usize) {
    let storage = make_storage(len);
    let mut filters = CoreFilters::default();
    filters.query = Some("needle".to_string());
    filters.limit = Some(1);

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries_core(&filters).expect("list_entries_core");
        divan::black_box(listed.len());
    });
}
