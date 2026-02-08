# raymon

[![Crates.io Version](https://img.shields.io/crates/v/raymon)](https://crates.io/crates/raymon)
[![CI](https://img.shields.io/github/actions/workflow/status/bnomei/tmux-mcp/ci.yml?branch=main)](https://github.com/bnomei/tmux-mcp/actions/workflows/ci.yml)
[![CodSpeed](https://img.shields.io/endpoint?url=https://codspeed.io/badge.json&style=flat)](https://codspeed.io/bnomei/raymon?utm_source=badge)
[![Crates.io Downloads](https://img.shields.io/crates/d/raymon)](https://crates.io/crates/raymon)
[![License](https://img.shields.io/crates/l/raymon)](https://crates.io/crates/raymon)
[![Discord](https://flat.badgen.net/badge/discord/bnomei?color=7289da&icon=discord&label)](https://discordapp.com/users/bnomei)
[![Buymecoffee](https://flat.badgen.net/badge/icon/donate?icon=buymeacoffee&color=FF813F&label)](https://www.buymeacoffee.com/bnomei)

Stateful HTTP ingest + MCP server + terminal UI for Ray-style logs.

Raymon is:
- CLI-first: one binary, local-first defaults.
- MCP-first: a small set of tools with explicit schemas for agents/LLMs.
- Keyboard-first: a [Ratatui](https://ratatui.rs) TUI designed for fast filtering, yanking, navigation and export.

<a title="click to open" target="_blank" style="cursor: zoom-in;" href="https://raw.githubusercontent.com/bnomei/raymon/main/screenshot.png"><img src="https://raw.githubusercontent.com/bnomei/raymon/main/screenshot.png" alt="screenshot" style="width: 100%;" /></a>

## Installation

### Cargo (crates.io)
```bash
cargo install raymon
```

### Homebrew
```bash
brew install bnomei/raymon/raymon
```

### GitHub Releases
Download a prebuilt archive from the GitHub Releases page, extract it, and place `raymon` on your `PATH`.

### From source
```bash
git clone https://github.com/bnomei/raymon.git
cd raymon
cargo build --release
```

## Quickstart

### Sending Logs

You can send from any compatible [Ray App](https://myray.app) library such as PHP, Javascript, Bash, Ruby, Python, Go and Dart.
If you want a Rust-native way to send Ray-compatible payloads, use my companion library [`ray-dbg`](https://github.com/bnomei/ray-dbg).

### Run Raymon locally with TUI

Run Raymon on the Ray default port:

```bash
raymon
# or
RAYMON_PORT=23517 raymon
```

### Demo mode (self-generates events):

```bash
raymon --demo
```

### TUI<-->MCPs (Streamable HTTP)

1) Start **your local HTTP** with TUI listening to default port `23517`
```bash
raymon
```

2) Add the local HTTP to the **agents harness** via MCP settings:
```bash
codex mcp add raymon --url http://127.0.0.1:23517/mcp
```

```json
{
  "mcpServers": {
    "raymon": {
      "url": "http://127.0.0.1:23517/mcp"
    }
  }
}
```

### Remote (Streamable HTTP)

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

## HTTP Endpoints

- `POST /`: Ray ingest endpoint (Ray payload envelope).
  - If the request body looks like JSON-RPC (`{"jsonrpc":"2.0","method":...}`), Raymon will treat it as MCP.
- `POST /mcp`: MCP Streamable HTTP endpoint.

## MCP Tools

Raymon exposes an intentionally small tool surface so it stays usable for agents.

Tools and their input/output shapes:

- `raymon.search` - search stored entries (supports `limit` + `offset`)

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
    "count": "number",
    "limit": "number",
    "offset": "number"
  }
  ```
  `count` is the total number of entries matching the filters (ignores `limit`/`offset`).

- `raymon.get_entries` - fetch entries by UUID(s)

  Parameters:
  ```json
  { "uuids": ["string"] }
  ```
  Fallback (legacy/single): `{ "uuid": "string" }`

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
    ]
  }
  ```

## Skill

This repo includes a [skill](https://agentskills.io) at `skills/raymon/SKILL.md` (an AI-facing runbook, not runtime code) that teaches an agent how to:

- generate Ray-style events using the official/community Ray libraries (PHP, JavaScript, Bash, Ruby, Rust, Python, Go, Dart),
- connect to Raymon locally or remotely (with auth) and add it as an MCP server, and
- use `raymon.search` → `raymon.get_entries` to triage logs and extract high-signal context (uuid, payload types, origin file/line).

## TUI

The TUI is intentionally "editor-like" (vim-ish):
- `?` opens keybindings/help.
- `q` quits (and shuts down the HTTP/MCP server).
- `Space` opens the pickers/filters modal.
- `/` searches (fuzzy, message + file; path-like queries are literal), `r` opens regex search (message + file).
- `:` searches inside detail ([jq](https://jqlang.org)).
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

### Theming

Raymon sticks to the terminal's ANSI palette (16 colors + text attributes like bold/dim/reverse), so it inherits your terminal theme (light/dark, base16, etc)without implementing full app theming. You can also enforce a set of colors via an `RAYMON_TUI_PALETTE` environment variable.

## Configuration

Raymon is configured primarily via environment variables:

| Variable | Default | Meaning |
| --- | --- | --- |
| `RAYMON_ENABLED` | `true` | Enable/disable the server. |
| `RAYMON_HOST` | `127.0.0.1` | Bind address for the HTTP server. |
| `RAYMON_PORT` | `23517` | Bind port for the HTTP server. |
| `RAYMON_TUI` | `true` | Enable the TUI. |
| `RAYMON_NO_TUI` | `false` | Disable the TUI (takes precedence over `RAYMON_TUI`). |
| `RAYMON_IDE` | `code` | IDE command used for "open origin" (for VS Code line jumps, use `code --goto`). |
| `RAYMON_EDITOR` | `VISUAL`/`EDITOR`/`vim` | Editor command used for "open in editor". |
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
