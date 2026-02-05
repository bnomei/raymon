//! Raymon: stateful MCP server and TUI for Ray-style logs.

mod cli;
mod colors;
mod raymon_core;
mod raymon_ingest;
mod raymon_mcp;
mod raymon_storage;
mod raymon_tui;

pub use cli::{run, DynError};
