# raymon-core Requirements

## Scope
Define shared domain types, state model, filters, and core traits used by all crates.

## Requirements (EARS)
- The core shall define types for Ray envelopes, payloads, origin, and entry metadata.
- When no screen is specified by a payload, the core shall derive a default screen name as `{projectName}:{hostname}:default`.
- The core shall expose filter types to support list search, type filters, color filters, and screen filters.
- The core shall define a state interface that supports insert, update, list, and get by UUID.
- The core shall define an event bus interface to emit new entries and state changes.
- The core shall remain free of IO, HTTP, or UI dependencies.
