DEVANA-FINDING: v1
Priority: P2 | Confidence: medium | Security-sensitive: no | Status: fixed
Location: src/raymon_ingest.rs:175-190 | src/cli/http.rs:54-80 | Slug: concurrent-uuid-ingest-race

# Concurrent ingests for the same UUID can lose merged payloads

## Finding

Duplicate-UUID ingest uses read-modify-write merge in `handle_inner` without per-UUID serialization. HTTP concurrency middleware allows up to 64 parallel requests. Two concurrent updates to the same UUID can each read the pre-merge state, merge independently, and last-writer-wins drops payloads from the other request.

## Violated Invariant Or Contract

Sequential duplicate-UUID ingests extend payloads via `merge_entry_update` (test `ingest_duplicate_uuid_updates_state`). Concurrent updates should produce the union of payloads, not whichever merge completes last.

## Oracle

`ingest_duplicate_uuid_updates_state` is single-threaded. `DEFAULT_MAX_CONCURRENCY = 64` with `try_acquire_owned` on ingest routes (`cli/http.rs:54-76`). `CoreState` uses `RwLock` but does not make get→merge→update atomic across requests.

## Counterexample

1. Core holds UUID `X` with payloads `[p1]`
2. Request A and B ingest additional payloads for `X` concurrently
3. Both `get_entry` read `[p1]`
4. A merges to `[p1, p2]`; B merges to `[p1, p3]` (not `[p1, p2, p3]`)
5. Last `update_entry` wins → one of `p2` or `p3` is permanently lost in core and MCP

## Why It Might Matter

Ray clients often send multiple payloads for one UUID in parallel during page renders. Under load, payload loss corrupts the merged log agents rely on.

## Proof

**Control-flow trace:** parallel `spawn_blocking` ingest handlers → each calls `get_entry` (read lock) → `merge_entry_update` locally → `update_entry` (write lock) with no compare-and-swap or per-UUID mutex.

## Counterevidence Checked

Single-threaded ingest tests pass. Storage appends both lines (append-only), so JSONL may retain both payloads while core loses one—widening storage/core divergence.

## Suggested Next Step

Serialize ingest per UUID (mutex map or queue) or re-read-and-retry merge on write conflict.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed `handle_inner`'s get_entry → merge → update sequence was not serialized, so concurrent same-UUID ingests (up to the 64-way HTTP concurrency limit) could each read pre-merge state and lose payloads via last-writer-wins. Implemented per-UUID serialization as the report's primary recommendation: added an `IngestGuard` returned by a new `StateStore::ingest_guard(uuid)` (default no-op), acquired in `handle_inner` before `get_entry` and held through the state/storage/bus commit. The production `IngestState` overrides it to lock one of 128 sharded `Mutex`es on `CoreState` (shared across all per-request ingestor clones via `Arc`), keyed by UUID hash, so same-UUID ingests serialize while distinct UUIDs still run concurrently. Poisoned shard locks are recovered (the merge data lives in the separate `RwLock`). Added a multi-threaded regression test `concurrent_same_uuid_ingest_preserves_all_payloads` (8 threads, same UUID, 5ms get-delay to widen the window); verified it asserts the union of payloads and that it FAILS (1 of 8 payloads) when the guard is stubbed to no-op. Full lib suite (151 tests) passes.

DEVANA-KEY: src/raymon_ingest.rs:175-190 | P2 | concurrent-uuid-ingest-race
DEVANA-SUMMARY: Status=fixed | P2 medium src/raymon_ingest.rs:175-190 - Per-UUID sharded serialization guard (StateStore::ingest_guard) now wraps the get→merge→commit section so concurrent same-UUID ingests no longer drop payloads; regression test added.