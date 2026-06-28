# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2026-06-28
### Added
- signal MCP clients with a `ray/event` lag notification when the event stream drops messages

### Changed
- serialize duplicate-UUID ingest merges and persist entries before exposing them in live state
- refresh merged TUI rows in place and keep cleared live views from repopulating with stale updates
- budget storage retention by distinct UUIDs rather than physical JSONL update lines
- search the newest entries first for bounded MCP scans while preserving stable result ordering

### Fixed
- trim configured auth tokens from files and environment variables before comparing request tokens
- tolerate stray separators in comma-separated `raymon.get_entries` UUID strings
- report archive flush failures and remove truncated archive files on write errors

## [0.6.0] - 2026-06-17
### Added
- document and test the MCP root fallback for JSON-RPC requests
- add opt-in MCP payload redaction for `raymon.get_entries` and MCP event notifications

### Changed
- split HTTP routing, MCP schema, and TUI archive helpers into dedicated modules
- avoid repeated full-result serialization in `raymon.get_entries` while preserving the response shape and size cap

## [0.5.1] - 2026-06-01
### Changed
- upgrade `axum` to 0.8.9, `crossterm` to 0.29.0, `ratatui` to 0.30.0, and `tiktoken-rs` to 0.11.0

## [0.5.0] - 2026-06-01
### Security
- harden release version validation before creating release artifacts
- enforce MCP request body, response size, and search scan-work bounds
- bound duplicate UUID ingest growth against storage retention limits
- require explicit opt-in for custom MCP shutdown methods
- escape terminal control bytes before rendering TUI text
- validate local origin files before launching configured IDE commands

## [0.4.1] - 2026-05-26
- update Cargo dependencies to the latest scoped patch-release set

## [0.4.0] - 2026-05-26
- upgrade `rmcp` to 1.7.0
- add read-only, non-destructive MCP tool hints for Raymon search and fetch tools

## [0.3.0] - 2026-05-08
- accept comma-separated string values for `raymon.get_entries` UUIDs
- accept comma-separated string values for `raymon.search` `types` and `colors`
- update Cargo dependencies to the latest semver-compatible versions
- raise the Rust version requirement to 1.89
- hide colors/label/size meta from DETAIL
- make default CLI output quiet; add `-v/--verbose` logging
- add `Ctrl+l` to clear the live log list in the TUI

## [0.1.0] - 2026-02-08
- Initial Release
