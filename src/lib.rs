//! Raymon is a stateful HTTP ingest + MCP server + terminal UI for Ray-style logs.
//!
//! Most users interact with Raymon via the `raymon` binary. This crate also exposes a small API so
//! Raymon can be embedded and launched from Rust.
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
