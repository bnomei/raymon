# raymon-cli Requirements

## Scope
Provide single-binary entrypoint, config loading, and runtime wiring.

## Requirements (EARS)
- The CLI shall parse flags for host, port, config, ide, editor, jq, and tui toggle.
- The CLI shall default to binding `127.0.0.1` and allow remote hosts when provided.
- The CLI shall load `ray.json` and env vars with CLI overrides.
- The CLI shall start a single HTTP server with both Ray ingest and MCP routes.
- The CLI shall start the TUI unless `--no-tui` is set.
- The CLI shall shut down cleanly on exit.
