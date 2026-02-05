# raymon-ingest Tasks
Note: Check tasks only after `cargo test -p <crate>` (or the specified crate) is green.

- [x] Scaffold `crates/raymon-ingest` with `Cargo.toml` and `src/lib.rs`.
- [x] Implement `POST /` handler for Ray envelopes.
- [x] Validate required fields and error handling.
- [x] Integrate with state/store and emit events.
- [x] Add unit tests for happy path and error cases.
- [x] Run `cargo test -p raymon-ingest` and mark tasks complete when green.
