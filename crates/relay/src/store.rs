#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use rusqlite::{Connection, OptionalExtension, Result as SqliteResult, params};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

fn current_epoch_seconds() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// Database record for an enrolled peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    /// Peer unique name.
    pub name: String,
    /// Peer role (`"agent"` or `"client"`).
    pub role: String,
    /// Pinned `SubjectPublicKeyInfo` hex fingerprint.
    pub fingerprint: String,
    /// Whether the peer has been revoked.
    pub revoked: bool,
}

/// Database record for a single-use enrollment token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRecord {
    /// SHA-256 hash of the enrollment token.
    pub token_hash: String,
    /// Peer name bound to the token.
    pub name: String,
    /// Role authorized for this token.
    pub role: String,
    /// Expiration timestamp in seconds since the UNIX epoch.
    pub expires_at: i64,
}

/// SQLite-backed store with thread-safe connection pooling for relay configuration.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

#[allow(clippy::missing_panics_doc)]
impl SqliteStore {
    /// Opens the SQLite database in WAL mode and runs schema migrations.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] if the database cannot be created, locked, or migrated.
    pub fn open(path: impl AsRef<Path>) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS peers (
                name TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                revoked INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            )",
            (),
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS tokens (
                token_hash TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )",
            (),
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS grants (
                client_name TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (client_name, agent_name)
            )",
            (),
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Stores or updates an enrolled peer.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] if the statement execution fails.
    pub fn upsert_peer(&self, record: &PeerRecord) -> SqliteResult<()> {
        let lock = self.conn.lock().expect("lock acquired");
        let now = current_epoch_seconds();
        lock.execute(
            "INSERT INTO peers (name, role, fingerprint, revoked, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET
                role = excluded.role,
                fingerprint = excluded.fingerprint,
                revoked = excluded.revoked",
            params![
                record.name,
                record.role,
                record.fingerprint,
                record.revoked,
                now
            ],
        )?;
        Ok(())
    }

    /// Queries a peer record by its certificate SPKI fingerprint.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database query failure.
    pub fn get_peer_by_fingerprint(&self, fingerprint: &str) -> SqliteResult<Option<PeerRecord>> {
        let lock = self.conn.lock().expect("lock acquired");
        let mut stmt = lock
            .prepare("SELECT name, role, fingerprint, revoked FROM peers WHERE fingerprint = ?1")?;
        let row = stmt
            .query_row([fingerprint], |r| {
                Ok(PeerRecord {
                    name: r.get(0)?,
                    role: r.get(1)?,
                    fingerprint: r.get(2)?,
                    revoked: r.get::<_, i64>(3)? != 0,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Queries a peer record by its unique name.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database query failure.
    pub fn get_peer_by_name(&self, name: &str) -> SqliteResult<Option<PeerRecord>> {
        let lock = self.conn.lock().expect("lock acquired");
        let mut stmt =
            lock.prepare("SELECT name, role, fingerprint, revoked FROM peers WHERE name = ?1")?;
        let row = stmt
            .query_row([name], |r| {
                Ok(PeerRecord {
                    name: r.get(0)?,
                    role: r.get(1)?,
                    fingerprint: r.get(2)?,
                    revoked: r.get::<_, i64>(3)? != 0,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Retrieves all registered peers.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on query failure.
    pub fn list_peers(&self) -> SqliteResult<Vec<PeerRecord>> {
        let lock = self.conn.lock().expect("lock acquired");
        let mut stmt =
            lock.prepare("SELECT name, role, fingerprint, revoked FROM peers ORDER BY name ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok(PeerRecord {
                name: r.get(0)?,
                role: r.get(1)?,
                fingerprint: r.get(2)?,
                revoked: r.get::<_, i64>(3)? != 0,
            })
        })?;
        rows.collect()
    }

    /// Revokes a peer by name or fingerprint.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on execution failure.
    pub fn revoke_peer(&self, target: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let updated = lock.execute(
            "UPDATE peers SET revoked = 1 WHERE name = ?1 OR fingerprint = ?1",
            [target],
        )?;
        Ok(updated > 0)
    }

    /// Persists a single-use token hash and expiration.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] if the token insert fails.
    pub fn store_token(
        &self,
        token_hash: &str,
        name: &str,
        role: &str,
        expires_at: i64,
    ) -> SqliteResult<()> {
        let lock = self.conn.lock().expect("lock acquired");
        let now = current_epoch_seconds();
        lock.execute(
            "INSERT INTO tokens (token_hash, name, role, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![token_hash, name, role, expires_at, now],
        )?;
        Ok(())
    }

    /// Validates and deletes a token atomically if it is active.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] if the transaction fails.
    pub fn consume_token(&self, token_hash: &str) -> SqliteResult<Option<TokenRecord>> {
        let mut lock = self.conn.lock().expect("lock acquired");
        let tx = lock.transaction()?;
        let now = current_epoch_seconds();

        let record = tx
            .query_row(
                "SELECT name, role, expires_at FROM tokens WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash, now],
                |r| {
                    Ok(TokenRecord {
                        token_hash: token_hash.to_string(),
                        name: r.get(0)?,
                        role: r.get(1)?,
                        expires_at: r.get(2)?,
                    })
                },
            )
            .optional()?;

        if record.is_some() {
            tx.execute("DELETE FROM tokens WHERE token_hash = ?1", [token_hash])?;
        }
        tx.commit()?;
        Ok(record)
    }

    /// Lists active unexpired tokens.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn list_tokens(&self) -> SqliteResult<Vec<TokenRecord>> {
        let lock = self.conn.lock().expect("lock acquired");
        let now = current_epoch_seconds();
        let mut stmt = lock.prepare(
            "SELECT token_hash, name, role, expires_at FROM tokens WHERE expires_at > ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([now], |r| {
            Ok(TokenRecord {
                token_hash: r.get(0)?,
                name: r.get(1)?,
                role: r.get(2)?,
                expires_at: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// Deletes an enrollment token.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn revoke_token(&self, token_hash: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let deleted = lock.execute("DELETE FROM tokens WHERE token_hash = ?1", [token_hash])?;
        Ok(deleted > 0)
    }

    /// Grants a client access to connect to an agent.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn add_grant(&self, client_name: &str, agent_name: &str) -> SqliteResult<()> {
        let lock = self.conn.lock().expect("lock acquired");
        let now = current_epoch_seconds();
        lock.execute(
            "INSERT OR IGNORE INTO grants (client_name, agent_name, created_at) VALUES (?1, ?2, ?3)",
            params![client_name, agent_name, now],
        )?;
        Ok(())
    }

    /// Removes a client authorization to reach an agent.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on database failure.
    pub fn remove_grant(&self, client_name: &str, agent_name: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let deleted = lock.execute(
            "DELETE FROM grants WHERE client_name = ?1 AND agent_name = ?2",
            params![client_name, agent_name],
        )?;
        Ok(deleted > 0)
    }

    /// Checks if a client is authorized to access an agent.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on query failure.
    pub fn has_grant(&self, client_name: &str, agent_name: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let count: i64 = lock.query_row(
            "SELECT COUNT(*) FROM grants WHERE client_name = ?1 AND agent_name = ?2",
            params![client_name, agent_name],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Lists granted agent names for a client.
    ///
    /// # Errors
    ///
    /// Returns a [`rusqlite::Error`] on query failure.
    pub fn list_grants(&self, client_name: Option<&str>) -> SqliteResult<Vec<(String, String)>> {
        let lock = self.conn.lock().expect("lock acquired");
        if let Some(client) = client_name {
            let mut stmt = lock.prepare(
                "SELECT client_name, agent_name FROM grants WHERE client_name = ?1 ORDER BY agent_name ASC",
            )?;
            let rows = stmt.query_map([client], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        } else {
            let mut stmt = lock.prepare(
                "SELECT client_name, agent_name FROM grants ORDER BY client_name, agent_name ASC",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        }
    }
}
