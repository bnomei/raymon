# raymon-ingest Requirements

## Scope
HTTP ingest handler for Ray payloads on `POST /`.

## Requirements (EARS)
- When a valid Ray envelope is received, the system shall parse it and update state.
- When the envelope is malformed JSON, the system shall return 400.
- When required fields are missing, the system shall return 422.
- When payload types are unknown, the system shall store them as generic payloads.
- The ingest handler shall be tolerant of unknown fields.
- Each accepted envelope shall emit an event on the bus.
