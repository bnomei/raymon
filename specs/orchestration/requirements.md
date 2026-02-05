# Orchestration Requirements

## Scope
Coordinate parallel subagent work across multiple crates with clean boundaries and independent testing.

## Requirements (EARS)
- When parallel implementation starts, the system shall define crate ownership and dependency flow for each subagent.
- When a subagent begins work, the system shall restrict edits to the assigned crate(s) and their tests.
- When a subagent completes its tasks, the system shall require `cargo test -p <crate>` to pass before marking tasks done.
- When a change is needed in another crate, the system shall route the request to the owning subagent instead of editing it directly.
- When the core API changes, the system shall ensure only the core subagent edits `raymon-core`.
- When all subagent tasks are complete, the system shall confirm all per-crate tests are green.
