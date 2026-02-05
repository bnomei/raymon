# raymon-tui Design

## Layout
- Top bar: pause/resume, search, filters
- Left: logs list
- Center/right: detail view
- Optional side panel: archived screens (toggle)

## Modes
- Normal: navigation
- Search: live filter input
- Command: `:` commands
- Space modal: help overlay + follow-up keys

## Keymap (subset)
- `j/k` move selection
- `/` search
- `Space` modal (f/s/c/t/j/?)
- `p` pause/resume
- `k` clear screen
- `z` toggle JSON expand/collapse
- `y/Y` yank
- `Ctrl+y` paste into input
- `e` open temp file in `$EDITOR`
- `o` open origin in IDE

## JSON Detail
- Collapsed by default
- Expand on `z`
- jq fallback only when plain text search returns zero

## Integration
- Subscribe to core event bus
- Read from state store for list/detail
