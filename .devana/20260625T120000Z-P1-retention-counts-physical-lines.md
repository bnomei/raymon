DEVANA-FINDING: v1
Priority: P1 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_storage/mod.rs:271-287 | src/raymon_storage/index.rs:32-49 | src/raymon_ingest.rs:187-189 | Slug: retention-counts-physical-lines

# JSONL retention budget counts physical lines, not distinct entries, so updated UUIDs evict still-wanted entries

## Finding

Storage retention is documented and named as "keep the newest `N` entries", but the budget is measured in physical JSONL lines, not distinct UUIDs. Every ingest update for an existing UUID appends a brand-new JSONL line (`raymon_ingest.rs:188`) and unconditionally grows `Index.offsets` (`index.rs:44`). `record_count()` returns `offsets.len()` (physical lines) and `tail_offsets(max_entries)` slices the last `max_entries` physical lines. A workload that updates UUIDs (Ray's normal pattern: counters, measures, progress, chained `ray()->...` calls all reuse one UUID) inflates the physical-line count far beyond the number of distinct entries, so retention fires early and drops the only line of an older distinct UUID even though the store holds far fewer than `N` distinct entries. The dropped entry is gone from the persisted file, so it is lost on the next restart (`restore_from_storage`).

## Violated Invariant Or Contract

After retention with cap `N`, the store must retain the `N` most-recently-touched distinct entries. An entry must not be evicted while the number of distinct entries is `<= N`.

## Oracle

Doc comment at `src/raymon_storage/mod.rs:161-164` ("keeps the newest `N` entries") and README.md:270 ("Max number of entries kept in `data/entries.jsonl` ... keeping the newest entries"). Both promise an entry-count budget; the code enforces a line-count budget.

## Counterexample

`new_with_retention(root, 2)` → `retention_slack = (2/10).clamp(1,10000) = 1`, so pruning fires when `record_count() > 3`. Ingest sequence over two distinct UUIDs A and B:

1. POST A (insert) → line 0
2. POST A again (update) → line 1 (merged cumulative A)
3. POST B (insert) → line 2
4. POST B again (update) → line 3 (merged cumulative B)

Now `record_count() = 4 > 3` → `maybe_enforce_retention` fires. `tail_offsets(2) = [line2, line3]` — both are B. The file is rewritten to {B-v1, B-v2}; entry A is permanently dropped even though only **2** distinct entries exist and the cap is **2**. After restart, A is unrecoverable.

## Why It Might Matter

Durable, silent data loss of entries the user explicitly retained. Ray clients update the same UUID frequently, so on a real workload the persisted store can hold a small set of recent distinct entries while the bulk of the budget is consumed by stale duplicate versions of a handful of UUIDs. Older distinct entries vanish well before the documented cap is reached, and only resurface as missing after a restart.

## Proof

- Control-flow / state trace: `raymon_ingest.rs:188` calls `storage.append_entry(&entry)` on every update → `mod.rs:211-214` appends a JSONL line and `index.insert` → `index.rs:44` pushes to `offsets` unconditionally (while `by_id`/`order` dedup by UUID at `:45-48`).
- `mod.rs:277` `total = record_count()` = `offsets.len()` (physical lines) → `:282` `tail_offsets(max_entries)` slices the last `max_entries` physical offsets (`index.rs:36-39`) → `:283` rewrites file to those offsets.
- Contract mismatch: budget unit is physical lines; documented unit is distinct entries.

## Counterevidence Checked

- Could the entry survive in memory? The core `CoreState` keeps it until its own (separate) eviction, but the persisted file is the source of truth on restart (`restore_from_storage`, cli.rs:557+), and the entry is gone there → real durable loss.
- `append_entry` does not rewrite in place on update; it always appends (`raymon_ingest.rs:188`), confirmed — duplicates are real physical lines.
- Existing test `retention_counts_duplicate_ids_on_append` (mod.rs ~:498) only repeats a single UUID, so it never exercises the cross-UUID loss and masks the defect.
- `retention_slack` widens the threshold but does not change the unit; the loss occurs once total physical lines exceed `N + slack`.

## Suggested Next Step

Decide whether retention should be entry-based (dedupe by UUID before applying the budget — e.g. retain the latest line per UUID for the newest `N` distinct UUIDs) or document it explicitly as a physical-line budget. If entry-based is intended, change `record_count`/`tail_offsets` to operate on distinct UUIDs (latest offset per id) rather than `offsets.len()`.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed both retention paths budgeted physical JSONL lines: `Index::record_count` returned `offsets.len()` and `tail_offsets` sliced the last N physical offsets (per-append path), and the startup `enforce_retention` counted lines via a deque. Switched both to an entry-based budget (the report's primary recommendation): replaced `record_count`/`tail_offsets` with `distinct_entry_count` (`order.len()`) and `tail_offsets_by_entry` (latest offset per UUID for the newest N distinct UUIDs by first-seen order, matching core-state eviction, returned in ascending file order); the startup path now dedupes by UUID during the file scan, keeping one chronologically-ordered line per retained UUID. Retention now fires only when distinct entries exceed cap+slack and never drops a distinct entry while the count is <= N. Updated the misleading `retention_counts_duplicate_ids_on_append` test (renamed to `retention_does_not_count_duplicate_ids_against_budget` — duplicates no longer trigger pruning) and added `retention_keeps_distinct_entries_at_cap_despite_updates` reproducing the counterexample (cap 2, A+A-update+B+B-update → both survive, including across a reload). Full lib suite (154 tests) passes.

DEVANA-KEY: src/raymon_storage/mod.rs:271-287 | P1 | retention-counts-physical-lines
DEVANA-SUMMARY: Status=fixed | P1 high src/raymon_storage/mod.rs:271-287 - Retention now budgets distinct entries (by UUID) instead of physical JSONL lines in both the per-append and startup paths, so updated UUIDs no longer evict older distinct entries under the cap; regression tests added.
