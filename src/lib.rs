//! Raymon is a stateful HTTP ingest + MCP server + terminal UI for Ray-style logs.
//!
//! Most users interact with Raymon via the `raymon` binary. This crate also exposes a small API so
//! Raymon can be embedded and launched from Rust.
//!
//! Public modules:
//! - [`raymon_core`] — IO-free entry, filter, event, and state contracts
//! - [`raymon_ingest`] — HTTP ingest pipeline
//! - [`raymon_storage`] — durable JSONL persistence and indexing
//! - [`raymon_mcp`] — MCP tools and live notifications
//! - [`raymon_tui`] — terminal log browser
//! - [`colors`] — canonical Ray color names
//!
//! # Running
//! ```no_run
//! #[tokio::main]
//! async fn main() -> Result<(), raymon::DynError> {
//!     raymon::run().await
//! }
//! ```

mod cli;
pub mod colors;
pub mod raymon_core;
pub mod raymon_ingest;
pub mod raymon_mcp;
pub mod raymon_storage;
pub mod raymon_tui;
mod sanitize;

pub use cli::{run, DynError};
