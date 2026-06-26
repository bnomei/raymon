DEVANA-FINDING: v1
Priority: P2 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_ingest.rs:187-194 | Slug: ingest-storage-state-split

# Ingest appends to storage before core state without rollback

## Finding

`Ingestor::handle_inner` writes to JSONL storage before updating in-memory core state. If `StateStore` fails after a successful `storage.append_entry`, the HTTP response is 500 but the entry persists on disk while live MCP/TUI queries read core and miss it until restart.

## Violated Invariant Or Contract

Ingest should keep durable storage and queryable core state consistent on failure. A failed ingest should not leave orphaned JSONL records invisible to MCP for the current session.

## Oracle

Happy-path tests verify rejection before any write (`ingest_invalid_json_returns_400`, `ingest_missing_required_fields_returns_422`). No test covers mid-pipeline failure after storage append. `restore_from_storage` on restart reloads JSONL into core.

## Counterexample

1. Successful `storage.append_entry` appends a JSONL line
2. `state.update_entry` returns `Err` (e.g. poisoned `RwLock`)
3. Ingest returns HTTP 500; no bus event
4. `raymon.search` / `get_entries` miss the entry; `data/entries.jsonl` contains it
5. Process restart restores entry into core

## Why It Might Matter

Transient state errors create session-visible gaps between persisted history and MCP/TUI live views. Agents may conclude ingest failed and retry, producing duplicate JSONL lines for the same UUID.

## Proof

**Dataflow trace:** `handle_inner` update branch (`raymon_ingest.rs:187-190`): `storage.append_entry` → `state.update_entry` → `bus.emit` with no transaction or compensating delete on state failure.

## Counterevidence Checked

Insert branch has the same ordering (`192-194`). Restart heals via `restore_from_storage`. Production `StateStore` errors are rare (poisoned lock) but the error path is reachable.

## Suggested Next Step

Reorder to update core before storage, or roll back JSONL append / mark tombstone on state failure.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed both branches of `handle_inner` appended to storage before updating core state, so a `StateStore` failure (e.g. poisoned lock) left a JSONL line with no corresponding core entry, invisible to MCP/TUI until restart. Applied the report's primary recommendation: update core state first, then append to storage, then emit the bus event. Now storage never holds an entry absent from core. (Trade-off: a storage-append failure leaves the entry in live state but undurable — surfaced as the 500 — which is the louder, operator-actionable failure and does not create the reported JSONL-orphan-invisible-to-MCP inconsistency.) Added regression test `ingest_state_failure_does_not_orphan_storage` using a `FailingState` mock, asserting no storage line and no bus event on state failure. Full lib suite (150 tests) passes.

DEVANA-KEY: src/raymon_ingest.rs:187-194 | P2 | ingest-storage-state-split
DEVANA-SUMMARY: Status=fixed | P2 high src/raymon_ingest.rs:187-194 - Ingest now updates core state before storage append, so a state failure no longer orphans a JSONL line invisible to MCP; regression test added.