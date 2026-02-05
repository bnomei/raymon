# raymon-storage Design

## Modules
- `jsonl`: append-only writer + reader
- `index`: offset index builder
- `blobs`: blob store helpers

## Storage Layout
- `data/entries.jsonl`
- `data/blobs/`

## Index
- In-memory index keyed by UUID and screen/session
- Stores `{ offset, len, summary, search_text }`

## API Sketch
- `append_entry(entry) -> OffsetMeta`
- `get_entry_by_offset(offset, len)`
- `rebuild_index()`
- `store_blob(bytes) -> blob_path`

## Error Handling
- IO errors propagate as storage errors
- Corrupt lines are skipped with warnings
