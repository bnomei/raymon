# Ray-Compatible CLI + MCP Server Plan

## Overview
Build a single CLI process that:
1. Receives Ray HTTP payloads with full compatibility to the official Ray app.
2. Exposes a **stateful HTTP MCP server** over the same runtime.
3. Provides a local TUI for inspection and basic control.

Reference docs:
- [Developing Ray libraries: Getting started](https://myray.app/docs/developing-ray-libraries/getting-started)
- [Developing Ray libraries: Payload structure](https://myray.app/docs/developing-ray-libraries/payload)
- [Ray reference methods list](https://myray.app/docs/php/vanilla-php/reference)
- [Spatie Ray repository](https://github.com/spatie/ray)

## Goals
- 100% wire-compatibility with Ray payloads produced by Spatie’s official libraries.
- Accept, parse, and store all payload types used by the Ray app.
- Provide MCP tools/resources that reflect incoming Ray events and internal state.
- Single binary with **HTTP-only MCP transport**.
- Provide a TUI built with Ratatui.

## Non-Goals
- Replicate the Ray GUI.
- Re-implement client libraries for every language.
- Enforce strict schema validation that could reject forward-compatible payloads.

## Compatibility Contract (HTTP Ingest)
The server must implement the Ray HTTP receiver contract.

Required behavior:
- Bind `POST /` on the configured host/port.
- Accept `Content-Type: application/json`.
- Parse JSON payloads using the documented envelope and payload shapes.
- Tolerate unknown fields and unknown payload types.
- Return 2xx quickly when payload is well-formed.

Envelope format (required fields):
- `uuid`: UUIDv4 string. Used to update existing entries.
- `payloads`: array of payload objects.
- `meta`: optional object with integration metadata.

Payload format (required fields):
- `type`: string payload type.
- `content`: payload-specific JSON.
- `origin`: object with `function_name`, `file`, `line_number`, `hostname`.

## Payload Coverage Plan
Compatibility requires handling the entire reference method surface.

Approach:
- Implement a generic payload model: `type`, `content`, `origin`, `uuid`.
- Maintain type-specific handlers only where needed for internal state updates.
- Always store unknown payloads for MCP inspection.

Known payload families from the reference list:
- Logging and content: `log`, `custom`, `table`, `json`, `xml`, `html`, `text`, `file`, `image`, `exception`.
- UI and control: `new_screen`, `clear_all`, `separator`, `show_app`, `hide_app`, `confetti`, `hide`, `remove`.
- Annotation: `color`, `size`, `label`, `notify`.
- Diagnostics: `trace`, `caller`, `measure`, `count`/`counter`.

## MCP Interface Plan
Expose a **stateful HTTP MCP server** that reflects Ray activity and state.

Minimal tool set:
- `ray.list_entries`: list stored entries by UUID and metadata, with `query`, `limit`, and `offset`.
- `ray.get_entry`: fetch full entry by UUID.
- `ray.list_screens`: list screens and their entries.
- `ray.clear_screen` and `ray.clear_all`: mutate state.
- `ray.notify`, `ray.confetti`, `ray.show_app`, `ray.hide_app`: generate Ray payloads locally if desired.

Resource/stream suggestions:
- `ray/events`: stream of incoming payloads.
- `ray/entries`: snapshot of current stored state.

HTTP routing:
- Single HTTP server for both Ray ingest and MCP.
- Primary routes: `POST /` for Ray ingest, `/mcp` (and `/mcp/*` if needed) for MCP.
- Optional fallback: if `POST /` JSON does **not** match Ray envelope, attempt to treat it as MCP only when it matches MCP request shape; otherwise return 422.

## TUI Plan (Ratatui)
Provide a local terminal UI for live inspection and navigation.

Core views:
- Logs list (by time/uuid/type), with filters.
- Entry detail view with payload and origin.
- Screens list and active screen indicator.

Input/actions:
- Navigate entries, switch screens, clear screen/all.
- Toggle auto-follow on newest events.
- Pause/resume listening to incoming events.
- Search (live filter list by query).
- Regex search (explicit via `Space r` or by `/pattern/` input).
- JSON detail search with jq fallback (executes local `jq` on the selected JSON blob).
- Archive logs button (maps to clear screen = new session).
- Color filter toggles (per color label).
- Toggle archived screens list visibility.
- Toggle JSON view mode (pretty vs raw).
- Copy selected log or detail content to a yank register (and OS clipboard if available).
- Paste yank into search/command inputs.
- Open selected origin in IDE or editor.

Layout elements:
- Top bar with pause/resume, search, and active filters.
- Right/secondary panel for archived screens (collapsible).
- Left panel for logs list; main panel for entry details.

MVP rendering:
- JSON shown as pretty-printed text in detail view with scrolling; list shows a one-line summary.
- HTML/custom content is not rendered in the TUI (show a short placeholder with type + size).
- Non-text blobs are not rendered in the TUI (show blob metadata only).
- Large JSON rendering is lazy: collapsed by default with a toggle to expand/pretty-print on demand.

JSON search (jq integration):
- In the **detail view** for a JSON blob, search first does a plain text match.
- If it yields **zero** matches and `jq` is available, retry the same input as a jq filter against the **selected blob only**.
- Use `jq -e` to test match and render the filtered output when it matches.
- If `jq` is not available, keep the zero-result state and show a notice.

Space modal (Helix-style):
- `Space` opens a help overlay listing available follow-up keys.
- `Space f` opens a fuzzy picker for active-session logs.
- `Space r` opens regex search for active-session logs.
- `Space s` opens the screens picker (active only).
- `Space c` opens the color filter picker.
- `Space t` opens the type filter picker.
- `Space j` opens jq detail search for the selected JSON blob.
- `Space ?` opens keymap help.

Shortcuts (subset):
- `f` find logs (focus search)
- `p` pause/resume
- `k` clear screen
- `1` toggle timestamp
- `2` toggle filename
- `3` toggle color indicator
- `4` toggle log labels
- `z` toggle expand/collapse for JSON detail
- `y` copy selected log summary
- `Y` copy detail view content
- `o` open origin in configured IDE
- `e` open selected entry in `$EDITOR` via temp file (suspends TUI)
- `Ctrl+y` paste yank into input fields (search/command)

## CLI Plan (clap)
Use `clap` for flags and config overrides.

Initial flags:
- `--host`, `--port` (HTTP bind address; default `127.0.0.1`)
- `--tui` / `--no-tui` (enable or disable TUI)
- `--config` (path to `ray.json`)
- `--ide` (set IDE for clickable file links; e.g., vscode, cursor, zed, sublime, phpstorm)
- `--jq` (path to jq binary; optional, defaults to `jq` on PATH)
- `--editor` (override `$EDITOR`/`$VISUAL` for opening files)

## Server Architecture
Single runtime with shared state.

Modules:
- `http_ingest`: HTTP server that parses Ray payloads.
- `state`: in-memory store keyed by UUID and screen.
- `mcp`: MCP server implementation.
- `bus`: broadcast channel for streaming events to MCP and CLI output.
- `tui`: Ratatui application loop reading from `state` and `bus`.

## Workspace Layout (Cargo)
Single binary with internal crates for separation of concerns.

Crates:
- `raymon-core`: types, state, filters, event bus interfaces.
- `raymon-storage`: JSONL writer/reader, offset index, blob store.
- `raymon-ingest`: HTTP ingest handlers (Ray POST `/`), state updates.
- `raymon-mcp`: MCP handlers and routing (served on `/mcp` in same server).
- `raymon-tui`: Ratatui UI, keymap, pickers, jq integration.
- `raymon-cli`: binary entrypoint, config, wiring, runtime startup.

Dependency flow:
- `raymon-core` has no internal deps.
- `raymon-storage` -> `raymon-core`
- `raymon-ingest` -> `raymon-core`, `raymon-storage`
- `raymon-mcp` -> `raymon-core`, `raymon-storage`
- `raymon-tui` -> `raymon-core`, `raymon-storage`
- `raymon-cli` -> all above

State model:
- Entry map keyed by UUID with ordered payload history.
- Screen map keyed by screen name.
- Current screen pointer.
- Optional timer/counter registry for `measure` and `count`.
- Session id per screen to delimit retention windows.
- Default screen name when none is provided: `{projectName}:{hostname}:default`.

## Storage and Indexing
Persist all entries across restarts with an append-only JSONL log and a lightweight in-memory index.

Primary store:
- `data/entries.jsonl`: one JSON line per Ray envelope, includes `uuid`, `received_at`, `projectName`, `hostname`, `screen`, `session_id`, and payloads.

Blobs:
- Any **non-text** payload data is stored as an external blob in `data/blobs/`.
- JSONL stores a reference `{ "blob_path": "..." }` instead of embedding binary/large non-text data.

Indexing:
- Maintain in-memory indices for **active sessions** (per screen).
- Each index entry includes file `offset`, `len`, and precomputed `search_text` for fast filtering.
- On startup, scan `entries.jsonl` to rebuild the active-session index; older sessions remain on disk for `rg`/offline search.

Retention policy:
- Sessions are created by user actions like `new_screen` or `clear_screen`.
- Only the **current session** for each screen is kept in memory for performance.
- Older sessions are retained on disk and can be searched externally.

## Ingest Pipeline
1. Receive POST body and parse JSON.
2. Validate required fields, but do not hard-fail on extra fields.
3. For each payload:
4. Update state as needed.
5. Emit event on broadcast channel.
6. Respond with 2xx.

Blob handling:
- If payload contains non-text content, write it to `data/blobs/` and store a blob reference in state/JSONL.

## Error Handling
- Malformed JSON: return 400 and log error.
- Missing fields: return 422 and log error.
- Unknown payload type: store as generic payload and continue.
- Internal errors: return 500 but do not crash the server.

## Configuration
Support Ray-compatible config:
- `RAY_HOST`, `RAY_PORT`, `RAY_ENABLED`.
- `ray.json` discovery from current directory upward.
- CLI flags override env and file config.
- `RAY_IDE` and `--ide` to control file/link behavior in the UI.
- Default IDE: `vscode` if not specified.
- Editor selection: `$VISUAL` > `$EDITOR` > `--editor` override, with a fallback to `vim` if none is set.
 
Clipboard:
- Use an internal yank register for copy/paste.
- Optionally sync to OS clipboard when available (best-effort, non-fatal if unsupported).

Network scope:
- Default to loopback-only (`127.0.0.1`) for local use.
- Allow explicit host override to accept payloads from other machines on the network.

## Compatibility Harness (Required for 100%)
Because not every payload shape is fully documented:

Steps:
- Use `ray-proxy` (from the Ray docs) to intercept payloads.
- Run a test suite that exercises every method in the Ray reference list.
- Store captured payloads as golden fixtures per payload type.
- Build schema samples from these fixtures.
- Add regression tests comparing new payloads to fixtures.

Outputs:
- `fixtures/` payload JSON files.
- `schemas/` derived JSON schema per payload type.
- `compat/` test runner that validates sample payloads.

## Milestones
1. Scaffold CLI, config loader, and HTTP ingest server.
2. Implement payload parsing and generic state store.
3. Add MCP server with list/get tools and event stream.
4. Build ray-proxy capture harness and fixture suite.
5. Expand handlers for all payload types and verify parity.

## Open Questions
- Should the CLI emit human-readable logs for each payload by default?
- Should the MCP HTTP server share the ingest port or run on a separate port?
