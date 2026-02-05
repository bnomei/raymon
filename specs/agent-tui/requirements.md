# raymon-tui Requirements

## Scope
Implement Ratatui interface with vim/helix-style interactions and required controls.

## Requirements (EARS)
- The TUI shall show a logs list, detail panel, and archived screens panel.
- The TUI shall provide pause/resume for incoming events.
- The TUI shall provide live search on the logs list.
- The TUI shall support a Helix-style `Space` modal for pickers and help.
- The TUI shall support JSON detail search with jq fallback on the selected blob.
- The TUI shall support copy/yank and paste into search/command inputs.
- The TUI shall open a temp file in `$EDITOR` for the selected entry.
- The TUI shall open the origin in the configured IDE when requested.
