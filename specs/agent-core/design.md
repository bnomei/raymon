# raymon-core Design

## Modules
- `types`: Envelope, Payload, Origin, Entry, Screen, SessionId
- `filters`: Filter struct(s) for list/search
- `state`: State traits and in-memory reference types
- `events`: Event enum and bus trait

## Key Types
- `Envelope { uuid, payloads, meta }`
- `Payload { type, content, origin }`
- `Entry { uuid, received_at, project, host, screen, session_id, payloads }`
- `Filters { query, types, colors, screen, project, host, limit, offset }`

## State Interface
Trait `StateStore` (or similar) exposes:
- `insert_entry(entry)`
- `get_entry(uuid)`
- `list_entries(filters)`
- `list_screens()`
- `clear_screen(screen)` / `clear_all()`

## Event Bus
Trait `EventBus` with:
- `emit(event)`
- `subscribe()`

## Invariants
- Screen name default uses `{projectName}:{hostname}:default`.
- Entry ordering is stable by insertion time.
