DEVANA-FINDING: v1
Priority: P3 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_mcp/schema.rs:48-56 | src/raymon_mcp.rs:494-525 | Slug: get-entries-empty-comma-segment

# `get_entries` aborts the whole batch when a comma-list UUID has an empty segment

## Finding

`raymon.get_entries` accepts a comma-separated UUID string as a convenience form. `UuidSelector::into_vec` splits on `,` and maps each segment through `compact_uuid_segment`, which does not drop empty segments (`schema.rs:50-51`). `normalize_get_entry_uuids` then trims each segment and returns a hard `INVALID_PARAMS` error the moment it sees an empty one (`raymon_mcp.rs:509-511`). So a trailing/leading/double comma — `"entry-1,"`, `", entry-1"`, `"entry-1,,entry-2"` — fails the entire request, even though the non-empty UUIDs are perfectly valid and fetchable. This contradicts the otherwise-lenient handling: missing/unknown UUIDs are silently skipped (`if let Some(entry)` at the fetch loop), so a caller reasonably expects empty separators to be ignored too.

## Violated Invariant Or Contract

The comma form is documented as a forgiving convenience (README.md ~:177-179, SKILL.md ~:137-141: "whitespace in each UUID token is ignored"), and absent entries are silently skipped. An empty separator segment should degrade gracefully (be ignored), not abort the whole call.

## Oracle

Neighboring behavior in the same handler: unknown UUIDs are skipped, not errored (the fetch loop guards each `get_entry` with `if let Some(...)`). The single-token path (`schema.rs:53`) also only trims. The comma branch is the lone path that produces empty tokens and the only one that hard-fails.

## Counterexample

`{ "uuids": "entry-1," }` → `UuidSelector::One` (contains `,`) → `"entry-1,".split(',')` → `["entry-1", ""]` → `compact_uuid_segment` keeps both → `normalize_get_entry_uuids` trims, hits `""` at `raymon_mcp.rs:509`, returns `McpError::invalid_params("uuid must not be empty")`. The valid `entry-1` is never fetched and the whole call fails.

## Why It Might Matter

An agent or client that builds the UUID list by string concatenation (a natural way to produce the documented comma form) and leaves a trailing comma gets a confusing whole-request failure instead of the entries for the valid UUIDs. Low impact (correctness/UX of one tool), hence P3, but concrete and easily triggered.

## Proof

- Dataflow trace: input `"entry-1,"` → `schema.rs:50-51` split keeps empty segment → `raymon_mcp.rs:507-511` loop returns `Err` on the empty token → handler returns `INVALID_PARAMS`, no entries.
- Contract mismatch: comma form documented as lenient + unknown UUIDs silently skipped vs. empty segment hard-fails.

## Counterevidence Checked

- The `Many` (explicit JSON array) path does not split on commas, so it is unaffected; the bug is specific to the comma-string convenience form.
- Tests around `normalize_get_entry_uuids` (raymon_mcp.rs ~:993-1015) only use comma lists with no empty segments, so this path is untested.
- No upstream empty-filter or dedup exists; the empty token reaches the validation loop intact.

## Suggested Next Step

Filter empty segments in the comma branch of `UuidSelector::into_vec` (e.g. `.filter(|s| !s.is_empty())` after `compact_uuid_segment`), so the convenience form tolerates stray separators consistently with the skip-unknown behavior.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed `UuidSelector::into_vec`'s comma branch kept empty segments, which `normalize_get_entry_uuids` then hard-failed with INVALID_PARAMS. Applied the report's suggested fix: added `.filter(|segment| !segment.is_empty())` after `compact_uuid_segment` so stray leading/trailing/double commas are ignored, consistent with unknown UUIDs being silently skipped. A string of only separators degrades to the empty-list path ("uuids must not be empty"). Added regression test `get_entries_tolerates_stray_commas_in_uuid_string` (`",entry-1,,entry-2,"` → both entries returned). Full lib suite (155 tests) passes.

DEVANA-KEY: src/raymon_mcp/schema.rs:48-56 | P3 | get-entries-empty-comma-segment
DEVANA-SUMMARY: Status=fixed | P3 high src/raymon_mcp/schema.rs:48-56 - UuidSelector::into_vec now filters empty comma segments, so stray separators in the get_entries UUID string are ignored instead of failing the whole request; regression test added.
