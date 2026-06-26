DEVANA-FINDING: v1
Priority: P2 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_mcp.rs:91-101 | src/cli.rs:484,1569-1612 | Slug: mcp-broadcast-lag-drop

# MCP event forwarder silently skips lagged broadcast events without resync

## Finding

`CoreBus` uses a broadcast channel with capacity 128. When the MCP event forwarder's subscription lags, `RecvError::Lagged` causes it to `continue` without notifying peers or replaying missed events from core state. The TUI forwarder resyncs from `CoreState` on lag; MCP has no equivalent recovery.

## Violated Invariant Or Contract

MCP clients subscribed to `ray/event` notifications expect to observe entry insert/update stream consistent with core state. Silent event loss under burst load breaks live agent triage without error signal.

## Oracle

`forwarder_resyncs_when_broadcast_lags` test covers TUI resync only (`cli.rs:2710-2763`). MCP `EventStream for broadcast::Receiver` (`raymon_mcp.rs:91-101`) loops on `Lagged` with `continue`. `CoreBus::emit` always returns `Ok(())` after `send`, ignoring subscriber lag.

## Counterexample

1. MCP peer connected; forwarder subscribed
2. Emit 200 `EntryInserted` events without consumer keeping up
3. Receiver gets `RecvError::Lagged` → skips to latest sequence
4. Intermediate entry notifications never reach MCP peers; no error returned to ingest or clients

## Why It Might Matter

High-volume Ray sessions during agent-driven debugging can drop MCP notifications while tools still report success, causing agents to miss new entries until they poll `raymon.search`.

## Proof

**Cross-entry mismatch:** same `CoreBus` (capacity 128, `cli.rs:484`) → TUI `forward_events_to_ui` rebuilds on lag (`1569-1612`) → MCP `EventStream` discards lagged gap (`raymon_mcp.rs:97-98`) with no state replay.

## Counterevidence Checked

MCP peers can call `raymon.search` to recover (if entries fall within scan window). Slow consumers are partially mitigated by peer cap pruning elsewhere. Lag requires burst >128 unread events per subscription.

## Suggested Next Step

On MCP lag, replay recent entries from core to affected peers or emit a gap notification so clients force-refresh.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed `EventStream for broadcast::Receiver` swallowed `RecvError::Lagged` with a silent `continue`, so the MCP forwarder dropped events with no signal to peers. Implemented the report's "emit a gap notification so clients force-refresh" option: changed `EventStream::recv` to return `Option<StreamMessage>` where `StreamMessage::Lagged(skipped)` surfaces the gap; the broadcast impl now maps `Lagged` to that variant (mpsc impl never lags). The forwarder emits a `ray/event` notification `{ "type": "lagged", "dropped": n }` on the same channel clients already observe, prompting them to recover via `raymon.search`. (Did not implement full per-peer entry replay — the gap notification is simpler, avoids guessing which entries each peer missed, and matches how MCP clients already recover.) Added regression tests `broadcast_event_stream_surfaces_lag_instead_of_swallowing` (overflows a cap-2 channel, asserts a `Lagged` signal then resumed delivery) and `lagged_notification_signals_drop`. Full lib suite (153 tests) passes.

DEVANA-KEY: src/raymon_mcp.rs:91-101 | P2 | mcp-broadcast-lag-drop
DEVANA-SUMMARY: Status=fixed | P2 high src/raymon_mcp.rs:91-101 - MCP forwarder now surfaces broadcast lag as a StreamMessage::Lagged and emits a ray/event "lagged" gap notification so peers force-refresh; regression tests added.