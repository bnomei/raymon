DEVANA-FINDING: v1
Priority: P3 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_tui.rs:2506-2553 | Slug: archive-flush-error-swallowed

# `archive_current_view` reports success and a positive count after a discarded flush error

## Finding

`archive_current_view` serializes each entry into a `BufWriter` and increments `written` on each `to_writer` success (`raymon_tui.rs:2514-2518`). After the loop it flushes with the error discarded: `let _ = writer.flush();` (`:2524`). Because `to_writer` only buffers into the `BufWriter`, the bytes are durably committed only by `flush`. If `flush` fails (disk full / I/O error), the file is truncated or empty, yet the code proceeds to register the archive with `count: written` and shows "archived N entries" (`:2532-2552`). The recorded count and success notice overstate what is actually on disk.

## Violated Invariant Or Contract

An operation that reports "archived N entries" and records `count: N` must have durably written N entries. A flush failure must not be reported as success.

## Oracle

Neighboring implementation in the same module: the live-archive path (`append_to_live_archive` / `flush_live_archive`, raymon_tui.rs ~:895-944) propagates flush errors and drops the live archive on failure. That establishes the intended contract; the discard at `:2524` is the inconsistency.

## Counterexample

User runs "archive current view" over 50 filtered entries on a near-full disk. All 50 `to_writer` calls succeed into the in-memory `BufWriter`, so `written = 50`. The final `flush()` fails with `ENOSPC`; the error is dropped at `:2524`. The archive is pushed with `count: 50` and the notice reads "archived 50 entries", but the on-disk `.jsonl` is empty or truncated. Reloading that archive later yields fewer (or zero) entries with no error surfaced at archive time.

## Why It Might Matter

A user believes a snapshot was safely archived (and may then clear the live view) when the archive file is actually incomplete — silent loss of the very data the archive was meant to preserve. Scoped to the TUI thread and requires an I/O failure during flush, so P3, but it is a concrete success-masking-failure with a clear sibling precedent for the fix.

## Proof

- Control-flow trace: `:2514-2518` increment `written` on buffered-write success → `:2524` `let _ = writer.flush()` discards the durability error → `:2526` only checks `written == 0` → `:2532-2537` records `count: written` → `:2548-2552` emits "archived {written} entries".
- Contract mismatch vs. `flush_live_archive`, which propagates the flush error.

## Counterevidence Checked

- `to_writer` errors are counted into `failed` and reported, but a *flush* failure after successful buffering is on a separate path and is the one discarded.
- `BufWriter` drop also attempts a flush, but its error is likewise ignored, so dropping the writer does not rescue the reporting.
- TUI-local: does not affect the HTTP/MCP server thread or core state, and is not a panic — keeping it at P3.

## Suggested Next Step

Capture the `flush()` result; on error set a failure notice (and skip registering the archive or mark it failed) the same way `flush_live_archive` handles it, rather than reporting `written` as a success.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed `archive_current_view` discarded the `BufWriter::flush()` result (`let _ = writer.flush();`) and then registered the archive with `count: written` and an "archived N entries" notice, overstating durable writes on a flush failure. Applied the report's suggested fix (matching `flush_live_archive`'s contract): capture the flush result; on error, drop the writer, remove the incomplete file best-effort, set an "archive failed: {err}" notice, and return before registering the archive. Added happy-path regression test `archive_current_view_writes_and_counts_entries` (archives 3 filtered entries, asserts the registered count is 3 and the file holds 3 durably-flushed lines). The flush-error path itself is not unit-tested: the function constructs its own `BufWriter<File>` internally and an ENOSPC/IO flush failure cannot be simulated without refactoring to inject a writer — out of scope for a P3; the fix is a direct sibling of the already-tested live-archive flush handling. Full lib suite (156 tests) passes.

DEVANA-KEY: src/raymon_tui.rs:2506-2553 | P3 | archive-flush-error-swallowed
DEVANA-SUMMARY: Status=fixed | P3 high src/raymon_tui.rs:2506-2553 - archive_current_view now captures the flush error, removes the incomplete file, and reports failure instead of registering the archive with an overstated count; happy-path regression test added.
