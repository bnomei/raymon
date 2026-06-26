DEVANA-FINDING: v1
Priority: P2 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/cli.rs:1553-1556,1600-1603 | README.md:242 | Slug: ctrl-l-clear-bypass-update

# Ctrl+l clear is undone by subsequent EntryUpdated events for pre-clear UUIDs

## Finding

After the operator clears the live log list with Ctrl+l, a duplicate-UUID ingest that emits `EntryUpdated` is forwarded to the TUI unconditionally. The cleared entry reappears even though README says Ctrl+l clears the live log list and the clear epoch (`started_at`) is meant to bound lag resync.

## Violated Invariant Or Contract

README: `Ctrl+l` clears the live log list (does not delete stored entries). After clear, pre-clear rows should stay hidden until genuinely new live traffic (new UUIDs or post-clear inserts), not updates to old UUIDs.

## Oracle

`forward_events_to_ui` applies `entry.received_at >= started_at` only in the lag-resync branch (lines 1600-1603), not on the normal `EntryInserted`/`EntryUpdated` path (lines 1553-1556). `merge_entry_update` preserves original `received_at` on updates (`raymon_ingest.rs:233`).

## Counterexample

1. Ingest entry UUID `A` (`received_at = t0`); TUI shows it
2. Press Ctrl+l at `t1` → TUI empty, `clear_tx` sets epoch to `t1`, `seen_uuids` cleared
3. Re-ingest same UUID (Ray merge) → `Event::EntryUpdated` with `received_at` still `t0`
4. Forwarder emits `UiEvent::Log` without epoch check → `push_log` appends `A` back into cleared list

## Why It Might Matter

Operators clearing noisy history during debugging immediately see old entries return on the next Ray payload chunk for the same UUID, defeating the purpose of Ctrl+l.

## Proof

**Control-flow trace:** Ctrl+l → `clear_screen_for(None)` + `clear_tx.send(now_millis())` (`cli.rs:1453-1455`) → forwarder clears `seen_uuids` on epoch change (`1546-1548`) → `EntryUpdated` path bypasses `started_at` filter → `push_log` appends (`raymon_tui.rs:875`).

## Counterevidence Checked

Clear intentionally does not mutate core/MCP state. Resync alone correctly filters by `started_at` when `seen_uuids` is empty; bug is live-event path ignoring epoch. `EntryInserted` for a brand-new post-clear UUID is expected to appear.

## Suggested Next Step

Filter live `EntryUpdated` (and possibly `EntryInserted` for pre-clear UUIDs) against `started_at` / clear epoch, or upsert TUI rows by UUID on update.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed the live `EntryInserted`/`EntryUpdated` arm of `forward_events_to_ui` forwarded unconditionally while only the lag-resync branch applied the `received_at >= started_at || seen_uuids.contains` epoch filter. Applied the same guard to the live path and now only record `seen_uuids` when the entry is actually forwarded, so a post-Ctrl+l update to a pre-clear UUID (whose merged received_at stays before the clear epoch) no longer repopulates the cleared list. New post-clear inserts (received_at >= epoch) and updates to entries shown after the clear (in seen_uuids) still pass. Added async regression test `forward_events_respects_clear_epoch_on_live_updates` (verified stable across repeated runs). Full lib suite passes.

DEVANA-KEY: src/cli.rs:1553-1556 | P2 | ctrl-l-clear-bypass-update
DEVANA-SUMMARY: Status=fixed | P2 high src/cli.rs:1553-1556 - Live EntryUpdated/EntryInserted now honor the Ctrl+l clear epoch (received_at >= started_at || already-seen), so pre-clear UUIDs no longer reappear; regression test added.