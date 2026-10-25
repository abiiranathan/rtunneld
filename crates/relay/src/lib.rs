#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use rusqlite::{Connection, OptionalExtension, Result as SqliteResult, params};
use std::collections::HashMap;
use std::path::Path;

/// Known peer roles, used for enrollment records and authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerRole {
    /// Agent peer that accepts tunnel targets.
    Agent,
    /// Client peer that opens connections to agents.
    Client,
}

impl PeerRole {
    /// Converts a role into the canonical string stored in the SQLite database.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Client => "client",
        }
    }
}

/// Minimal static peer registry for testing and relay scaffolding.
#[derive(Clone, Debug, Default)]
pub struct PeerRecord {
    /// Name the peer enrolled under.
    pub name: String,
    /// Role, such as agent or client.
    pub role: String,
    /// Fingerprint of the pinned certificate.
    pub fingerprint: String,
    /// Whether the peer is revoked.
    pub revoked: bool,
}

/// A single-use enrollment token persisted by the relay to authorize a peer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenRecord {
    /// The token hash as a stable identifier in the relay DB.
    pub token_hash: String,
    /// The peer name bound to the token.
    pub name: String,
    /// The role requested by the peer.
    pub role: String,
    /// Unix timestamp when the token expires.
    pub expires_at: i64,
}

/// In-memory grant map described by the protocol.
#[derive(Clone, Debug, Default)]
pub struct GrantStore {
    /// Maps a client to a list of granted agent names.
    pub grants: HashMap<String, Vec<String>>,
}

impl GrantStore {
    /// Grants a client to connect to the specified agent.
    pub fn add_grant(&mut self, client: &str, agent: &str) {
        let agents = self.grants.entry(client.to_string()).or_default();
        if !agents.iter().any(|name| name == agent) {
            agents.push(agent.to_string());
        }
    }

    /// Removes a grant.
    pub fn remove_grant(&mut self, client: &str, agent: &str) -> bool {
        let Some(agents) = self.grants.get_mut(client) else {
            return false;
        };
        let before = agents.len();
        agents.retain(|name| name != agent);
        before != agents.len()
    }

    /// Checks if a client is authorized to reach an agent.
    #[must_use]
    pub fn allows(&self, client: &str, agent: &str) -> bool {
        self.grants
            .get(client)
            .is_some_and(|agents| agents.iter().any(|name| name == agent))
    }
}

/// SQLite-backed relay store with a simple schema.
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Opens or creates a relay state database at the given path.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be created or initialized.
    pub fn open(path: impl AsRef<Path>) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS peers (name TEXT PRIMARY KEY, role TEXT NOT NULL, fingerprint TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)",
            (),
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS grants (client_name TEXT NOT NULL, agent_name TEXT NOT NULL, PRIMARY KEY (client_name, agent_name))",
            (),
        )?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, expires_at INTEGER NOT NULL)",
            (),
        )?;
        Ok(Self { conn })
    }

    /// Persists a peer.
    ///
    /// # Errors
    ///
    /// Returns an error when the insert or update statement fails.
    pub fn upsert_peer(&self, record: &PeerRecord) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT INTO peers (name, role, fingerprint, revoked) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(name) DO UPDATE SET role=excluded.role, fingerprint=excluded.fingerprint, revoked=excluded.revoked",
            params![record.name, record.role, record.fingerprint, record.revoked],
        )?;
        Ok(())
    }

    /// Lists all peers.
    ///
    /// # Errors
    ///
    /// Returns an error when the query cannot be executed or mapped.
    pub fn list_peers(&self) -> SqliteResult<Vec<PeerRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, role, fingerprint, revoked FROM peers ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok(PeerRecord {
                name: row.get(0)?,
                role: row.get(1)?,
                fingerprint: row.get(2)?,
                revoked: row.get::<_, i64>(3)? != 0,
            })
        })?;
        rows.collect()
    }

    /// Adds a grant to the database.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant insertion fails.
    pub fn add_grant(&self, client_name: &str, agent_name: &str) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO grants (client_name, agent_name) VALUES (?1, ?2)",
            params![client_name, agent_name],
        )?;
        Ok(())
    }

    /// Lists grants for a client.
    ///
    /// # Errors
    ///
    /// Returns an error when the query cannot be executed or mapped.
    pub fn grant_list(&self, client_name: &str) -> SqliteResult<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT agent_name FROM grants WHERE client_name = ?1 ORDER BY agent_name")?;
        let rows = stmt.query_map([client_name], |row| row.get(0))?;
        rows.collect()
    }

    /// Stores a single-use token hash. This is the relay-side equivalent of the enrollment token.
    ///
    /// # Errors
    ///
    /// Returns an error when the token record cannot be inserted.
    pub fn store_token(&self, token_hash: &str, name: &str, role: &str, expires_at: i64) -> SqliteResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO tokens (token_hash, name, role, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token_hash, name, role, expires_at],
        )?;
        Ok(())
    }

    /// Validates and consumes a token if it is still within its lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error if the token lookup or delete operation fails.
    pub fn consume_token(&self, token_hash: &str) -> SqliteResult<Option<TokenRecord>> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expires_at = i64::try_from(now).unwrap_or(i64::MAX);

        let mut stmt = self.conn.prepare(
            "SELECT name, role, expires_at FROM tokens WHERE token_hash = ?1 AND expires_at > ?2",
        )?;
        let maybe = stmt
            .query_row((token_hash, expires_at), |row| {
                Ok(TokenRecord {
                    token_hash: token_hash.to_string(),
                    name: row.get(0)?,
                    role: row.get(1)?,
                    expires_at: row.get(2)?,
                })
            })
            .optional()?;

        if maybe.is_some() {
            self.conn.execute("DELETE FROM tokens WHERE token_hash = ?1", [token_hash])?;
        }
        Ok(maybe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_store_allows_only_granted_agents() {
        let mut store = GrantStore::default();
        store.add_grant("alice", "db");
        assert!(store.allows("alice", "db"));
        assert!(!store.allows("alice", "web"));
        assert!(!store.allows("bob", "db"));
    }
}
