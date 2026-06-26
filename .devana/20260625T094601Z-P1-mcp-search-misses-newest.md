DEVANA-FINDING: v1
Priority: P1 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_mcp.rs:410,42 | src/raymon_core.rs:497-499 | src/cli.rs:457-460 | Slug: mcp-search-misses-newest

# `raymon.search` scan window is oldest-first, hiding newest in-core entries

## Finding

`raymon.search` sets `scan_limit` to 5000 and applies it by iterating core insertion order from the front. When more than 5000 entries live in core state, the newest entries fall outside the scan window and cannot appear in search results or `count`, even though `raymon.get_entries` can still fetch them by UUID.

## Violated Invariant Or Contract

README documents `count` as matches within the bounded scan window but does not state the window is the oldest N entries. Agents expect search to surface recent logs; newest entries should be discoverable while still in `RAYMON_MAX_ENTRIES` core state.

## Oracle

`search_bounds_count_scan_work` test caps `count` at 5000 for 5025 entries but does not assert which UUIDs are excluded. `Filters::apply_with_count` uses `entries.into_iter().take(scan_limit)` over `inner.order` (oldest-first deque). `MAX_SEARCH_SCAN_ENTRIES = 5000` with default `RAYMON_MAX_ENTRIES = 10000`.

## Counterexample

1. Ingest 6000 unique entries `entry-0` … `entry-5999` in order
2. Call `raymon.search` with default params
3. `count` = 5000; results only cover `entry-0` … `entry-4999`
4. `raymon.get_entries({ "uuids": ["entry-5999"] })` still returns the entry

## Why It Might Matter

MCP agents triaging live logs via `raymon.search` → `raymon.get_entries` will miss the most recent traffic under normal defaults, breaking the documented agent workflow for busy sessions.

## Proof

**Dataflow trace:** ingest pushes UUID to `order` tail (`cli.rs:428-429`) → MCP search sets `filters.scan_limit = Some(5000)` (`raymon_mcp.rs:410`) → `list_entries_with_count` iterates `inner.order` oldest-first with `.take(scan_limit)` (`raymon_core.rs:497-499`) → summaries for entries beyond position 5000 never emitted.

## Counterevidence Checked

`scan_limit` is returned in tool results (documents cap, not direction). TUI search runs over full in-memory log list without the 5000 cap, so TUI and MCP diverge. Parallel filter path also honors `scan_limit` on order iteration.

## Suggested Next Step

Scan newest-first (tail of `order`) or document explicitly; consider aligning scan window with recent-entry workflow.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed `CoreState::list_entries_with_count` (src/cli.rs:453) iterated `inner.order` oldest-first with `.take(scan_limit)`, so the newest entries beyond 5000 were excluded from search/count. Fixed by selecting the scan window from the *tail* of `order` (newest `scan_limit` entries via `.rev().take(scan_limit)`), then restoring chronological order within the window so result/pagination ordering is unchanged for the common case (<5000 entries). Only MCP `raymon.search` uses this path; the non-count `list` (TUI/REST) is untouched. Added regression test `list_entries_with_count_scan_window_covers_newest_entries`. Full lib suite (147 tests) passes.

DEVANA-KEY: src/raymon_mcp.rs:410 | P1 | mcp-search-misses-newest
DEVANA-SUMMARY: Status=fixed | P1 high src/raymon_mcp.rs:410 - raymon.search scanned oldest 5000 entries; now scans newest 5000 (tail of order) while preserving chronological result order, with regression test.