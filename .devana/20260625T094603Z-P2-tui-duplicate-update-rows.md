DEVANA-FINDING: v1
Priority: P2 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_tui.rs:847-876 | src/cli.rs:1553-1555 | src/raymon_ingest.rs:187-190 | Slug: tui-duplicate-update-rows

# TUI appends a new row on EntryUpdated instead of upserting by UUID

## Finding

When the same Ray UUID is ingested twice, core state merges payloads and emits `EntryUpdated`, but the TUI `push_log` always appends to `state.logs`. The live list can contain multiple rows with the same UUID showing stale and updated snapshots.

## Violated Invariant Or Contract

Core and storage treat UUID as the identity key (upsert/merge). The live TUI list should reflect one row per UUID, matching MCP `get_entries` and core `get_entry`.

## Oracle

`ingest_duplicate_uuid_updates_state` test: two ingests → one state entry, two storage lines, second event is `EntryUpdated`. `forward_events_to_ui` maps both `EntryInserted` and `EntryUpdated` to `UiEvent::Log` without distinction.

## Counterexample

1. Ingest UUID `A` → one TUI row
2. Ingest UUID `A` again with additional payloads
3. Core holds merged payloads; bus emits `EntryUpdated`
4. `push_log` pushes a second row; TUI shows two list entries with UUID `A`

## Why It Might Matter

Operators and fuzzy search in the TUI see duplicate rows for a single logical log entry, with stale messages above the current merged state. Lag resync from core temporarily collapses duplicates, masking the steady-state bug.

## Proof

**State transition mismatch:** ingest update path (`raymon_ingest.rs:187-190`) → `EntryUpdated` → forwarder (`cli.rs:1553-1555`) → `push_log` always `logs.push(entry)` (`raymon_tui.rs:875`) with no UUID lookup/replace.

## Counterevidence Checked

`resync_live_logs` rebuilds from core (one row per UUID) and can hide duplicates after broadcast lag. No uuid-based upsert exists elsewhere in `raymon_tui.rs`.

## Suggested Next Step

On `EntryUpdated`, replace existing log row by UUID or rebuild that row from core before append.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed `forward_events_to_ui` mapped both `EntryInserted` and `EntryUpdated` to `UiEvent::Log`, and `push_log` always appended to `state.logs`, so re-ingested UUIDs produced duplicate rows. Added a distinct `UiEvent::UpdateLog` variant (forwarder now emits it for `EntryUpdated`), and a `Tui::update_log` method that upserts by UUID: it replaces the existing row in place across the active buffers (`state.logs`/`state.queued`, or the `live_buffer` when viewing an archive) and marks the filter dirty so the refreshed content re-filters; if no row exists yet it falls back to appending. Inserts keep the O(1) append path (the UUID scan only runs on updates). The live-archive NDJSON stream still records the update line (matching storage's two-line behavior). Added regression test `update_log_upserts_existing_row_by_uuid`. Full lib suite (149 tests) passes.

DEVANA-KEY: src/raymon_tui.rs:847-876 | P2 | tui-duplicate-update-rows
DEVANA-SUMMARY: Status=fixed | P2 high src/raymon_tui.rs:847-876 - EntryUpdated now routes to Tui::update_log which upserts the row by UUID instead of appending a duplicate; regression test added.