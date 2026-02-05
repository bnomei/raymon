# raymon-storage Requirements

## Scope
Implement JSONL persistence, offset indexing, and blob storage APIs.

## Requirements (EARS)
- When a new entry is stored, the system shall append a JSON line to `data/entries.jsonl`.
- When an entry is appended, the system shall record its byte offset and length for fast retrieval.
- When the process starts, the system shall rebuild the in-memory index by scanning `entries.jsonl`.
- When payload content is non-text, the system shall store it as a blob and store a reference in JSONL.
- The storage layer shall expose methods for list/get based on offsets and filters from core.
