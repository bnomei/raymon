# raymon-cli Design

## Config Resolution
- Load defaults
- Merge `ray.json` from current directory upward
- Merge env vars (`RAY_*`)
- Apply CLI overrides last

## Runtime Wiring
- Build shared state store + event bus
- Start HTTP server with ingest + MCP routes
- Start TUI in async task if enabled

## Shutdown
- Handle Ctrl+C, stop HTTP server and TUI gracefully
