use raymon::raymon_tui::{fuzzy_rank_items, LogEntry, PickerItem, PickerItemId, Tui, TuiConfig};

fn main() {
    divan::main();
}

fn make_items(len: usize) -> Vec<PickerItem> {
    (0..len)
        .map(|idx| PickerItem {
            label: format!("alpha-item-{idx:05}"),
            meta: None,
            id: PickerItemId::Screen(format!("bench-{idx}")),
            active: false,
        })
        .collect()
}

#[divan::bench(args = [50usize, 200usize, 1000usize, 5000usize])]
fn tui_fuzzy_rank_contains(bencher: divan::Bencher, len: usize) {
    let items = make_items(len);
    bencher.counter(len).bench(|| {
        let ranked = fuzzy_rank_items(&items, "alpha");
        divan::black_box(ranked.len());
    });
}

#[divan::bench(args = [50usize, 200usize, 1000usize, 5000usize])]
fn tui_fuzzy_rank_fuzz_miss(bencher: divan::Bencher, len: usize) {
    let items = make_items(len);
    bencher.counter(len).bench(|| {
        let ranked = fuzzy_rank_items(&items, "does-not-exist");
        divan::black_box(ranked.len());
    });
}

#[divan::bench(args = [200usize, 1000usize, 5000usize])]
fn tui_fuzzy_rank_fuzz_typo(bencher: divan::Bencher, len: usize) {
    let items = make_items(len);
    bencher.counter(len).bench(|| {
        let ranked = fuzzy_rank_items(&items, "alhpa");
        divan::black_box(ranked.len());
    });
}

fn make_logs(len: usize) -> Vec<LogEntry> {
    (0..len)
        .map(|idx| {
            let color = if idx % 2 == 0 { "red" } else { "blue" };
            LogEntry {
                id: idx as u64,
                uuid: format!("bench-{idx:08}"),
                message: format!(
                    "request_id={idx:08x} path=/api/v1/items duration_ms={}",
                    idx % 100
                ),
                detail: if idx == 0 {
                    "{\"request\":{\"id\":1,\"tags\":[\"alpha\",\"beta\"]},\"ok\":true}".to_string()
                } else {
                    "plain detail".to_string()
                },
                origin: Some("main.rs:123".to_string()),
                origin_file: Some("main.rs".to_string()),
                origin_line: Some(123),
                timestamp: Some(1_700_000_000_000 + idx as u64),
                entry_type: Some("log".to_string()),
                color: Some(color.to_string()),
                screen: Some("main".to_string()),
            }
        })
        .collect()
}

#[divan::bench(args = [200usize, 1000usize, 5000usize])]
fn tui_render_warm(bencher: divan::Bencher, len: usize) {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut tui = Tui::new(TuiConfig::default());
    tui.state.logs = make_logs(len);
    tui.state.filtered = (0..len).collect();
    tui.state.selected = 0;

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).expect("terminal");

    // Warm the detail cache so we measure steady-state rendering.
    terminal.draw(|frame| tui.render(frame)).expect("draw");

    bencher.counter(len).bench_local(|| {
        terminal.draw(|frame| tui.render(frame)).expect("draw");
    });
}

#[divan::bench(args = [200usize, 1000usize])]
fn tui_render_selection_changes(bencher: divan::Bencher, len: usize) {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let mut tui = Tui::new(TuiConfig::default());
    tui.state.logs = make_logs(len);
    tui.state.filtered = (0..len).collect();
    tui.state.selected = 0;

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).expect("terminal");

    bencher.counter(len).bench_local(|| {
        if !tui.state.filtered.is_empty() {
            tui.state.selected = (tui.state.selected + 1) % tui.state.filtered.len();
        }
        terminal.draw(|frame| tui.render(frame)).expect("draw");
    });
}
