#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

pub mod audit;
pub mod server;
pub mod store;

use thiserror::Error;

pub use audit::AuditLogger;
pub use server::RelayServer;
pub use store::{PeerRecord, SqliteStore, TokenRecord};

/// Errors encountered within the relay service.
#[derive(Debug, Error)]
pub enum RelayError {
    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    /// Transport or networking error.
    #[error("transport error: {0}")]
    Transport(String),
    /// Identity or crypto error.
    #[error("identity error: {0}")]
    Identity(#[from] rtunnel_identity::IdentityError),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
