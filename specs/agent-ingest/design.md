# raymon-ingest Design

## HTTP Handler
- Route: `POST /`
- Parse JSON into core `Envelope`
- Validate required fields (`uuid`, `payloads`)

## State Updates
- Map envelope to `Entry`
- Apply default screen naming if missing
- Store via `StateStore` and `Storage` append

## Errors
- 400: invalid JSON
- 422: missing required fields
- 500: internal error

## Event Emission
- Emit `EntryAdded` event after successful store
