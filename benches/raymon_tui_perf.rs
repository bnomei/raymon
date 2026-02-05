#[path = "../src/raymon_tui.rs"]
mod raymon_tui;

use raymon_tui::{PickerItem, PickerItemId};

fn main() {
    divan::main();
}

fn make_items(len: usize) -> Vec<PickerItem> {
    (0..len)
        .map(|idx| PickerItem {
            label: format!("alpha-item-{idx:05}"),
            meta: None,
            id: PickerItemId::Log(idx),
            active: false,
        })
        .collect()
}

#[divan::bench(args = [50usize, 200usize, 1000usize, 5000usize])]
fn tui_fuzzy_rank_contains(bencher: divan::Bencher, len: usize) {
    let items = make_items(len);
    bencher.counter(len).bench(|| {
        let ranked = raymon_tui::fuzzy_rank_items(&items, "alpha");
        divan::black_box(ranked.len());
    });
}

#[divan::bench(args = [50usize, 200usize, 1000usize, 5000usize])]
fn tui_fuzzy_rank_fuzz_miss(bencher: divan::Bencher, len: usize) {
    let items = make_items(len);
    bencher.counter(len).bench(|| {
        let ranked = raymon_tui::fuzzy_rank_items(&items, "does-not-exist");
        divan::black_box(ranked.len());
    });
}

#[divan::bench(args = [200usize, 1000usize, 5000usize])]
fn tui_fuzzy_rank_fuzz_typo(bencher: divan::Bencher, len: usize) {
    let items = make_items(len);
    bencher.counter(len).bench(|| {
        let ranked = raymon_tui::fuzzy_rank_items(&items, "alhpa");
        divan::black_box(ranked.len());
    });
}
