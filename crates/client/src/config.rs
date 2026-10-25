#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Configuration parameters for the rtunnel client CLI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Relay network host or IP.
    pub relay_host: String,
    /// Relay listening UDP port.
    pub relay_port: u16,
    /// Relay pinned SPKI fingerprint.
    pub relay_fingerprint: String,
    /// Name assigned to this client upon enrollment.
    pub client_name: String,
}

impl ClientConfig {
    /// Loads client configuration from `<state_dir>/config.toml`.
    ///
    /// # Errors
    ///
    /// Returns a [`std::io::Error`] if the file cannot be read or parsed.
    pub fn load(state_dir: &Path) -> std::io::Result<Self> {
        let content = fs::read_to_string(state_dir.join("config.toml"))?;
        toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    /// Saves client configuration to `<state_dir>/config.toml`.
    ///
    /// # Errors
    ///
    /// Returns a [`std::io::Error`] if file creation or serialization fails.
    pub fn save(&self, state_dir: &Path) -> std::io::Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(state_dir.join("config.toml"), content)
    }
}
