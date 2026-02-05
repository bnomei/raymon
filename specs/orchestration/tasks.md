# Orchestration Tasks
Note: Check tasks only after `cargo test -p <crate>` (or the specified crate) is green.

- [ ] Create the Cargo workspace layout and add crate entries in the root `Cargo.toml`.
- [ ] Create subagent specs for all crates.
- [ ] Define subagent ownership boundaries and communicate them.
- [ ] Verify each subagent runs `cargo test -p <crate>` and checks off its tasks.
- [ ] Run a final workspace build/test pass once all subagents are green.
