# Orchestration Design

## Overview
Use a single Cargo workspace with multiple crates. Each subagent owns exactly one crate (plus its tests) and may only change files within that crate directory. The orchestrator maintains the workspace wiring and merges requests between crates.

## Ownership Map
- Core agent: `crates/raymon-core`
- Storage agent: `crates/raymon-storage`
- Ingest agent: `crates/raymon-ingest`
- MCP agent: `crates/raymon-mcp`
- TUI agent: `crates/raymon-tui`
- CLI agent: `crates/raymon-cli`

## Dependency Flow
`raymon-core` is the root. Other crates depend on it. `raymon-cli` depends on all crates.

## Coordination Rules
- API requests across crates go through the orchestrator.
- Subagents use `cargo test -p <crate>` for verification.
- Tasks are only checked off after tests are green.

## Definition of Done
- Each subagent completes all tasks in its `tasks.md`.
- Each subagent runs its crate tests and records completion by checking tasks.
- The orchestrator confirms overall workspace build/test status.
