# raymon

Stateful HTTP ingest + MCP server + terminal UI for Ray-style logs.

Raymon is:
- CLI-first: one binary, local-first defaults.
- MCP-first: a small set of tools with explicit schemas for agents/LLMs.
- Keyboard-first: a Ratatui TUI designed for fast filtering, yanking, and navigation.

> [!Warning]
> Raymon binds to `127.0.0.1` by default. If you enable remote binds (`RAYMON_ALLOW_REMOTE=1`),
> set `RAYMON_AUTH_TOKEN` and keep the server on a trusted network.

## Quickstart

Run Raymon (dev):

```bash
cargo run
```

Run Raymon on the Ray default port (handy if your Ray client defaults to `23517`):

```bash
RAYMON_PORT=23517 cargo run
```

Headless mode (no TUI):

```bash
RAYMON_NO_TUI=1 cargo run
```

### Sending Logs

If you want a Rust-native way to send Ray-compatible payloads, use the companion library
[`ray-dbg`](https://github.com/bnomei/ray-dbg).

## HTTP Endpoints

- `POST /`: Ray ingest endpoint (Ray payload envelope).
  - If the request body looks like JSON-RPC (`{"jsonrpc":"2.0","method":...}`), Raymon will treat it as MCP.
- `POST /mcp`: MCP Streamable HTTP endpoint (rmcp).

## MCP Tools (Small On Purpose)

Raymon exposes a small tool surface (compared to the Ray desktop app’s tool list) so it stays usable for agents.

Tools and their input/output shapes:

- `ray.list_entries` - list stored entries (supports `limit` + `offset`)

  Parameters:
  ```json
  {
    "query": "string (optional; plain text or /regex/)",
    "types": ["string"],
    "colors": ["string"],
    "screen": "string (optional)",
    "project": "string (optional)",
    "host": "string (optional)",
    "limit": "number (optional)",
    "offset": "number (optional)"
  }
  ```

  Result:
  ```json
  {
    "entries": [
      {
        "uuid": "string",
        "received_at": "number",
        "project": "string",
        "host": "string",
        "screen": "string",
        "payload_count": "number",
        "payload_types": ["string"]
      }
    ],
    "limit": "number",
    "offset": "number"
  }
  ```

- `ray.get_entry` - fetch one entry by UUID

  Parameters:
  ```json
  { "uuid": "string" }
  ```

  Result:
  ```json
  {
    "entry": {
      "uuid": "string",
      "received_at": "number",
      "project": "string",
      "host": "string",
      "screen": "string",
      "session_id": "string (or null)",
      "payloads": [
        {
          "type": "string",
          "content": "any",
          "origin": {
            "project": "string",
            "host": "string",
            "screen": "string (or null)",
            "session_id": "string (or null)",
            "function_name": "string (or null)",
            "file": "string (or null)",
            "line_number": "number (or null)"
          }
        }
      ]
    }
  }
  ```

- `ray.list_screens` - list screens

  Parameters:
  ```json
  {}
  ```

  Result:
  ```json
  { "screens": ["string"] }
  ```

- `ray.emit` - emit a local action into the event stream (useful for testing)

  Parameters:
  ```json
  { "type": "string", "data": "any (optional)" }
  ```

  Result:
  ```json
  { "ok": true }
  ```

- `ray.clear_screen` - clear entries for a screen (creates a new “session window” in the UI)

  Parameters:
  ```json
  { "screen": "string" }
  ```

  Result:
  ```json
  { "ok": true }
  ```

- `ray.clear_all` - clear all entries

  Parameters:
  ```json
  {}
  ```

  Result:
  ```json
  { "ok": true }
  ```

Shutdown signal (non-tool):
- Custom MCP request/notification methods `raymon/quit` / `raymon/exit` (also accepts `ray/quit`, `ray/exit`) trigger a graceful shutdown.

## TUI

The TUI is intentionally “editor-like” (vim/helix-ish):
- `Space` opens the Space modal (help/pickers).
- `Space q` quits (and shuts down the HTTP/MCP server).
- `/` searches, `Space r` opens regex search.
- `p` pauses/resumes live updates.
- `k` clears the current screen (“archive logs”).
- `y` yanks the selected list entry, `Y` yanks the detail pane.
- `Ctrl+y` pastes the yank register into inputs.
- `o` opens the origin in your IDE (see `RAYMON_IDE`), `e` opens the detail in `$EDITOR` via a temp file.

## Configuration

Raymon is configured primarily via environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `RAYMON_ENABLED` | `true` | Enable/disable the server. |
| `RAYMON_HOST` | `127.0.0.1` | Bind address for the HTTP server. |
| `RAYMON_PORT` | `7777` | Bind port for the HTTP server. |
| `RAYMON_TUI` | `true` | Enable the TUI. |
| `RAYMON_NO_TUI` | `false` | Disable the TUI (takes precedence over `RAYMON_TUI`). |
| `RAYMON_IDE` | `code` | IDE command used for “open origin” (for VS Code line jumps, use `code --goto`). |
| `RAYMON_EDITOR` | `VISUAL`/`EDITOR`/`vim` | Editor command used for “open in editor”. |
| `RAYMON_JQ` | `jq` | `jq` command used for detail search. |
| `RAYMON_MAX_BODY_BYTES` | `1048576` | Max size (bytes) for HTTP POST bodies. |
| `RAYMON_MAX_QUERY_LEN` | `265` | Max length (bytes) for search/command/picker queries. |
| `RAYMON_JQ_TIMEOUT_MS` | `10000` | `jq` timeout in milliseconds. |
| `RAYMON_ALLOW_REMOTE` | `false` | Allow binding to non-loopback addresses. |
| `RAYMON_AUTH_TOKEN` | unset | If set, requires `Authorization: Bearer <token>` or `x-raymon-token: <token>` on all HTTP requests. |
| `RAYMON_TOKEN` | unset | Alias for `RAYMON_AUTH_TOKEN`. |

Raymon also supports a `ray.json` config file (searched from the current directory upwards). CLI flags override env and file config.

## License

MIT. See [`LICENSE`](LICENSE).
