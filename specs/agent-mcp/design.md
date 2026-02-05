# raymon-mcp Design

## Routes
- `/mcp` for MCP JSON requests
- `/mcp/events` for SSE stream (if implemented)

## Tool Handlers
- `ray.list_entries(filters)` -> list from `StateStore`
- `ray.get_entry(uuid)` -> fetch from `StateStore`
- `ray.list_screens()` -> summary from `StateStore`
- `ray.emit(type, data, ...)` -> inject local action into state/bus

## Request Matching
- Validate MCP request shape before executing handlers.

## Errors
- Invalid MCP requests return 400/422 with error details.
