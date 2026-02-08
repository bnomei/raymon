use raymon::raymon_core::Filters as CoreFilters;
use raymon::raymon_storage::{EntryFilter, EntryInput, EntryPayload, Storage};
use tempfile::TempDir;

fn main() {
    divan::main();
}

struct BenchStorage {
    _dir: TempDir,
    storage: Storage,
}

const LONG_SHARED: &str = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua";

fn make_entry_input(idx: usize) -> EntryInput {
    let summary = if idx == 0 { "needle".to_string() } else { "entry".to_string() };
    let search_text = if idx == 0 { "needle haystack".to_string() } else { format!("entry-{idx}") };

    EntryInput {
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
    }
}

fn make_entry_input_long_text(idx: usize) -> EntryInput {
    let summary = if idx == 0 {
        format!("needle {LONG_SHARED}")
    } else {
        format!("entry {idx} {LONG_SHARED}")
    };

    let search_text = if idx == 0 {
        format!("needle haystack {LONG_SHARED} {LONG_SHARED}")
    } else {
        format!("entry-{idx} {LONG_SHARED} {LONG_SHARED}")
    };

    EntryInput {
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
    }
}

fn make_storage(len: usize) -> BenchStorage {
    let dir = TempDir::new().expect("temp dir");
    let mut storage = Storage::new(dir.path()).expect("storage");

    for idx in 0..len {
        storage.append_entry(make_entry_input(idx)).expect("append entry");
    }

    BenchStorage { _dir: dir, storage }
}

fn make_storage_long_text(len: usize) -> BenchStorage {
    let dir = TempDir::new().expect("temp dir");
    let mut storage = Storage::new(dir.path()).expect("storage");

    for idx in 0..len {
        storage.append_entry(make_entry_input_long_text(idx)).expect("append entry");
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
    let filters = CoreFilters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries_core(&filters).expect("list_entries_core");
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_core_query_miss_long_text(bencher: divan::Bencher, len: usize) {
    let storage = make_storage_long_text(len);
    let filters = CoreFilters { query: Some("does-not-exist".to_string()), ..Default::default() };

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries_core(&filters).expect("list_entries_core");
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [1024usize, 4096usize])]
fn storage_list_entries_core_query_hit_limit_1(bencher: divan::Bencher, len: usize) {
    let storage = make_storage(len);
    let filters =
        CoreFilters { query: Some("needle".to_string()), limit: Some(1), ..Default::default() };

    bencher.counter(len).bench_local(|| {
        let listed = storage.storage.list_entries_core(&filters).expect("list_entries_core");
        divan::black_box(listed.len());
    });
}

#[divan::bench(args = [0usize, 1024usize, 8192usize])]
fn storage_append_entry(bencher: divan::Bencher, prefill: usize) {
    let mut storage = make_storage(prefill);
    let mut next = prefill;

    bencher.bench_local(|| {
        next += 1;
        storage.storage.append_entry(make_entry_input(next)).expect("append entry");
    });
}

#[divan::bench(args = [0usize, 1024usize])]
fn storage_append_entry_long_text(bencher: divan::Bencher, prefill: usize) {
    let mut storage = make_storage_long_text(prefill);
    let mut next = prefill;

    bencher.bench_local(|| {
        next += 1;
        storage.storage.append_entry(make_entry_input_long_text(next)).expect("append entry");
    });
}

#[divan::bench(args = [1024usize, 8192usize])]
fn storage_rebuild_index(bencher: divan::Bencher, len: usize) {
    let mut storage = make_storage(len);

    bencher.counter(len).bench_local(|| {
        storage.storage.rebuild_index().expect("rebuild_index");
        divan::black_box(storage.storage.list_entries(None).len());
    });
}

fn retention_slack(max_entries: usize) -> usize {
    (max_entries / 10).clamp(1, 10_000)
}

#[divan::bench(args = [1024usize])]
fn storage_append_entry_retention_rewrite(bencher: divan::Bencher, max_entries: usize) {
    let slack = retention_slack(max_entries);
    let dir = TempDir::new().expect("temp dir");
    let mut storage = Storage::new_with_retention(dir.path(), max_entries).expect("storage");

    // Seed to a steady state so each iteration triggers exactly one retention rewrite.
    for idx in 0..max_entries {
        storage.append_entry(make_entry_input(idx)).expect("append entry");
    }

    let mut next = max_entries;

    bencher.counter(slack + 1).bench_local(|| {
        for _ in 0..(slack + 1) {
            next += 1;
            storage.append_entry(make_entry_input(next)).expect("append entry");
        }
    });
}
