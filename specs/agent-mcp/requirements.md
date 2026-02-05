# raymon-mcp Requirements

## Scope
Expose MCP tools and routes under `/mcp` using the shared HTTP server.

## Requirements (EARS)
- When an MCP request is received, the system shall route it to the correct tool handler.
- The MCP server shall implement `ray.list_entries`, `ray.get_entry`, `ray.list_screens`, and `ray.emit`.
- When `ray.list_entries` includes `query`, the system shall filter entries using core filters.
- The MCP server shall expose an event stream of incoming entries.
- The MCP server shall not accept Ray ingest envelopes on `/mcp`.
