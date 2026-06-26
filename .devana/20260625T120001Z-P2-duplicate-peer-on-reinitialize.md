DEVANA-FINDING: v1
Priority: P2 | Confidence: high | Security-sensitive: no | Status: fixed
Location: src/raymon_mcp.rs:455-465,285-289 | Slug: duplicate-peer-on-reinitialize

# Repeat MCP `initialize` on one connection registers the same peer twice, doubling every event notification

# Finding

`initialize` calls `register_peer(context.peer.clone())` unconditionally (`raymon_mcp.rs:463`), and `register_peer` pushes the peer onto the `peers` vector with no identity/de-dup check (`:285-289`). The handler already treats `initialize` as idempotent for peer metadata — `set_peer_info` is guarded by `peer_info().is_none()` (`:460`) — but the peer *registration* is not guarded. If a client sends `initialize` twice on the same open transport/session, the same peer is registered twice. The single global event forwarder (`broadcast_notification`) iterates the `peers` vector and calls `peer.send_notification(...)` once per slot, so the client receives every `ray/event` notification twice for the lifetime of the connection.

## Violated Invariant Or Contract

A given live peer/connection must appear at most once in `peers`, so each ingested entry produces exactly one notification per connected client. The `set_peer_info` guard at `:460` encodes the author's intent that `initialize` be idempotent; `register_peer` breaks that intent.

## Oracle

Cross-statement contract mismatch within `initialize` itself: `set_peer_info` is conditioned on `peer_info().is_none()` (idempotent), but the adjacent `register_peer` call is not — the two lines disagree on whether a repeat `initialize` should mutate state.

## Counterexample

1. Client opens a streamable-HTTP MCP connection (transport stays open).
2. Client sends `initialize` → `register_peer` pushes peer P. `peers = [P]`.
3. Client sends `initialize` again on the same connection → `register_peer` pushes the same peer clone again. `prune_closed_peers` (`:287`) does not remove it (transport still open) and there is no `contains`/identity check. `peers = [P, P]`.
4. An entry is ingested → `broadcast_notification` iterates `peers` and calls `send_notification` for each slot → the client receives the `entry_inserted` notification **twice**.

## Why It Might Matter

Duplicate event delivery to MCP clients/agents for the connection's lifetime: an agent consuming `ray/event` notifications sees each log entry multiple times, which can double-count, double-act, or corrupt downstream state that assumes one notification per entry. With N repeated `initialize` calls the multiplier grows to N. No state corruption on the server side, hence P2 rather than P1.

## Proof

- Control-flow trace: `initialize` (`:455`) → `:463` `self.register_peer(context.peer.clone())` (unconditional) → `register_peer` (`:285-289`) `peers.push(peer)` with only `prune_closed_peers` (removes closed only) and `enforce_peer_cap` (trims only above `MAX_MCP_PEERS=64`).
- Contract mismatch: `:460` guards `set_peer_info` with `peer_info().is_none()`; `:463` does not guard `register_peer`.
- `broadcast_notification` sends once per vector slot, so duplicates multiply delivery.

## Counterevidence Checked

- `prune_closed_peers` (`:287`) only filters `transport_closed()` peers; both copies are open, so it does not collapse the duplicate.
- `enforce_peer_cap` only trims when length exceeds 64, so it does not dedup below the cap.
- `set_peer_info`'s guard confirms repeat `initialize` is a contemplated case, making the unguarded `register_peer` an inconsistency rather than an impossible path.
- Reachability: the MCP spec expects a single `initialize` per session, so this requires an out-of-spec or buggy client re-sending `initialize` on one open connection — real but not guaranteed, hence P2.

## Suggested Next Step

Make `register_peer` idempotent for an already-registered peer (skip if the peer is already present), or gate the `register_peer` call behind the same `peer_info().is_none()` check used for `set_peer_info`.

## Agent Handoff

After working this report, preserve the original finding body. Update line 2 `Status: ...` and the final `DEVANA-SUMMARY:` status. Use one of: `open`, `fixed`, `invalid`, `stale`, `duplicate`, `wontfix`. Add dated notes below with the evidence checked.

## Status Notes

- 2026-06-25: open by Devana. Initial report written from static source inspection.
- 2026-06-26: fixed. Confirmed `initialize` called `register_peer` unconditionally while `set_peer_info` was guarded by `peer_info().is_none()`, so a repeat `initialize` on one open connection pushed a duplicate peer (prune_closed_peers keeps it while the transport is open) and doubled every `ray/event` notification. Applied the report's suggested fix #2: moved the `register_peer` call inside the same `peer_info().is_none()` first-initialize guard, so the peer is registered exactly once per connection. This relies on the same peer_info signal the existing (working) set_peer_info guard already trusts. No automated test added: `initialize` takes a real `rmcp::service::RequestContext`/`rmcp::Peer`, which cannot be constructed without a full MCP transport handshake, and the repo has no MCP integration harness; the change is a one-line guard that now matches the adjacent set_peer_info idempotency. Full lib suite (154 tests) still passes.

DEVANA-KEY: src/raymon_mcp.rs:455-465 | P2 | duplicate-peer-on-reinitialize
DEVANA-SUMMARY: Status=fixed | P2 high src/raymon_mcp.rs:455-465 - register_peer is now gated behind the same first-initialize (peer_info().is_none()) guard as set_peer_info, so a repeat initialize no longer double-registers the peer or doubles ray/event notifications.
