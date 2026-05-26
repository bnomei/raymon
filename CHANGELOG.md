# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
