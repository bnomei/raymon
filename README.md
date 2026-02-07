# raymon

Stateful HTTP ingest + MCP server + terminal UI for Ray-style logs.

Raymon is:
- CLI-first: one binary, local-first defaults.
- MCP-first: a small set of tools with explicit schemas for agents/LLMs.
- Keyboard-first: a Ratatui TUI designed for fast filtering, yanking, and navigation.

## Development Notes

The source of truth is the root crate (`Cargo.toml` + `src/*`).

`legacy/crates/` contains an archived, older workspace split that is not maintained.

> [!Warning]
> Raymon binds to `127.0.0.1` by default. If you enable remote binds (`RAYMON_ALLOW_REMOTE=1`),
> Raymon requires `RAYMON_AUTH_TOKEN` by default. Use `RAYMON_ALLOW_INSECURE_REMOTE=1` only on a trusted network.

## Quickstart

Run Raymon:

```bash
raymon
```

Run Raymon on the Ray default port (handy if your Ray client defaults to `23517`):

```bash
RAYMON_PORT=23517 raymon
```

Headless mode (no TUI):

```bash
RAYMON_NO_TUI=1 raymon
```

Demo mode (self-generates events):

```bash
raymon --demo
```

### MCP Client Setup (Agents)

Raymon supports MCP over:
- **stdio (local)** via `raymon mcp`
- **Streamable HTTP (remote)** via `http://<host>:<port>/mcp` (default: `http://127.0.0.1:23517/mcp`)

#### Local (stdio)

In stdio mode, Raymon still starts the HTTP ingest endpoint on `RAYMON_HOST`/`RAYMON_PORT`
(default `127.0.0.1:23517`), but MCP runs over stdio for your MCP client.
This mode runs without the TUI (stdout is reserved for MCP).

Add it to your MCP client:
```bash
# Codex CLI
codex mcp add raymon -- raymon mcp

# Claude Code
claude mcp add --transport stdio raymon -- raymon mcp
```

```json
{
  "mcpServers": {
    "raymon": {
      "command": "raymon",
      "args": ["mcp"]
    }
  }
}
```

#### Remote (Streamable HTTP)

1) Start Raymon (recommended: require + send auth)
```bash
export RAYMON_AUTH_TOKEN="change-me"
RAYMON_ALLOW_REMOTE=1 RAYMON_HOST=0.0.0.0 RAYMON_NO_TUI=1 RAYMON_AUTH_TOKEN="$RAYMON_AUTH_TOKEN" raymon
```

Raymon will refuse non-loopback binds without `RAYMON_AUTH_TOKEN` unless you set `RAYMON_ALLOW_INSECURE_REMOTE=1`.

2) Add it to your MCP client:
```bash
codex mcp add raymon --url http://<host>:23517/mcp --bearer-token-env-var RAYMON_AUTH_TOKEN
```

```json
{
  "mcpServers": {
    "raymon": {
      "url": "http://<host>:23517/mcp"
    }
  }
}
```

If you change `RAYMON_HOST` / `RAYMON_PORT`, update the MCP URL accordingly.

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
- `?` opens keybindings/help.
- `q` quits (and shuts down the HTTP/MCP server).
- `Space` opens the pickers/filters modal.
- `/` searches (fuzzy, message + file; path-like queries are literal), `r` opens regex search (message + file).
- `:` searches inside detail (jq).
- `J/K` or `PageUp/PageDown` scrolls the detail pane.
- `s` snaps the color + type filters to the selected log entry.
- `p` pauses/resumes live updates.
- `x` archives the current view (writes a new archive file).
- `n` (in the Archives pane) renames the selected archive file (confirm with Enter; Esc cancels; live cannot be renamed).
- `d` (in the Archives pane) deletes the selected archive (confirm required; live cannot be deleted).
- `y` yanks the selected list entry, `Y` yanks the detail pane.
- `z` toggles JSON expanded/collapsed (default: expanded), `Z` toggles raw JSON.
- `u` resets search + filters (screens/types/colors).
- `Ctrl+y` pastes the yank register into inputs.
- `1` toggles color dot, `2` timestamp, `3` type label, `4` file, `5` message, `6` uuid (short).
- `o` opens the origin in your IDE (see `RAYMON_IDE`), `e` opens the detail in `$EDITOR` via a temp file.
- In the Archives pane, `Enter` loads the selected archive; the green `‣` row returns to live (`◼` = active archive, `◻` = inactive).

Color strategy: Raymon sticks to the terminal’s ANSI palette (16 colors + text attributes like bold/dim/reverse),
so it inherits your terminal theme (light/dark, base16, etc) without implementing full app theming.

## Configuration

Raymon is configured primarily via environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `RAYMON_ENABLED` | `true` | Enable/disable the server. |
| `RAYMON_HOST` | `127.0.0.1` | Bind address for the HTTP server. |
| `RAYMON_PORT` | `23517` | Bind port for the HTTP server. |
| `RAYMON_TUI` | `true` | Enable the TUI. |
| `RAYMON_NO_TUI` | `false` | Disable the TUI (takes precedence over `RAYMON_TUI`). |
| `RAYMON_IDE` | `code` | IDE command used for “open origin” (for VS Code line jumps, use `code --goto`). |
| `RAYMON_EDITOR` | `VISUAL`/`EDITOR`/`vim` | Editor command used for “open in editor”. |
| `RAYMON_JQ` | `jq` | `jq` command used for detail search. |
| `RAYMON_TUI_PALETTE` | unset | Optional TUI palette override: 18 comma-separated colors `fg,bg,black,red,green,yellow,blue,magenta,cyan,white,bright_black,bright_red,bright_green,bright_yellow,bright_blue,bright_magenta,bright_cyan,bright_white` as `#RRGGBB` (also accepts `rgb:RRRR/GGGG/BBBB`). |
| `RAYMON_PALETTE` | unset | Alias for `RAYMON_TUI_PALETTE`. |
| `RAYMON_MAX_BODY_BYTES` | `1048576` | Max size (bytes) for HTTP POST bodies. |
| `RAYMON_MAX_QUERY_LEN` | `265` | Max length (bytes) for search/command/picker queries. |
| `RAYMON_MAX_ENTRIES` | `10000` | Max number of entries kept in memory for the core state (MCP + resync). `0` disables eviction. |
| `RAYMON_STORAGE_MAX_ENTRIES` | `100000` | Max number of entries kept in `data/entries.jsonl`. When exceeded, Raymon rewrites the JSONL file keeping the newest entries. `0` disables retention. |
| `RAYMON_JQ_TIMEOUT_MS` | `10000` | `jq` timeout in milliseconds. |
| `RAYMON_ALLOW_REMOTE` | `false` | Allow binding to non-loopback addresses. |
| `RAYMON_ALLOW_INSECURE_REMOTE` | `false` | Allow binding to non-loopback addresses without auth (NOT recommended). |
| `RAYMON_AUTH_TOKEN` | unset | If set, requires `Authorization: Bearer <token>` or `x-raymon-token: <token>` on all HTTP requests. |
| `RAYMON_TOKEN` | unset | Alias for `RAYMON_AUTH_TOKEN`. |

Raymon also supports a `ray.json` config file (searched from the current directory upwards). Keys mirror env vars (e.g. `host`, `port`, `tui`, `max_entries`, `storage_max_entries`). CLI flags override env and file config.

## License

MIT. See [`LICENSE`](LICENSE).
