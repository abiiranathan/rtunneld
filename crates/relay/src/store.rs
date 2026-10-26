#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use rand::Rng;
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
    /// Peer unique name or 9-digit Device ID.
    pub name: String,
    /// Peer role (`"agent"`, `"client"`, or `"node"`).
    pub role: String,
    /// Pinned `SubjectPublicKeyInfo` hex fingerprint.
    pub fingerprint: String,
    /// Whether the peer has been revoked.
    pub revoked: bool,
}

/// Database record for a single-use enrollment token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRecord {
    /// Hash of the enrollment token.
    pub token_hash: String,
    /// Name of the peer the token enrolls.
    pub name: String,
    /// Role granted to the peer on enrollment.
    pub role: String,
    /// Expiry as seconds since the Unix epoch.
    pub expires_at: i64,
}

/// SQLite-backed store with thread-safe connection pooling for relay configuration.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

#[allow(clippy::missing_panics_doc)]
impl SqliteStore {
    /// Opens (or creates) the database at `path`, enables WAL mode, and
    /// ensures all tables exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the database file cannot be opened, a pragma
    /// cannot be applied, or any of the schema statements fail.
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

        conn.execute(
            "CREATE TABLE IF NOT EXISTS agent_targets (
                agent_name TEXT PRIMARY KEY,
                targets TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            )",
            (),
        )?;

        // Active pairing codes for AnyDesk-style rendezvous
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pairing_codes (
                device_id TEXT PRIMARY KEY,
                code_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            )",
            (),
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Allocates or retrieves a unique 9-digit Device ID for a given fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if any database query fails, or
    /// [`rusqlite::Error::QueryReturnedNoRows`] if a unique Device ID could
    /// not be generated after 100 attempts.
    pub fn get_or_allocate_device_id(
        &self,
        fingerprint: &str,
        label: &str,
    ) -> SqliteResult<String> {
        let lock = self.conn.lock().expect("lock acquired");

        // Check if this fingerprint already has a record
        let existing: Option<String> = lock
            .query_row(
                "SELECT name FROM peers WHERE fingerprint = ?1",
                [fingerprint],
                |r| r.get(0),
            )
            .optional()?;

        if let Some(id) = existing {
            return Ok(id);
        }

        // Generate a random 9-digit Device ID (100 000 000 to 999 999 999)
        let mut rng = rand::thread_rng();
        let mut attempts = 0;
        let device_id = loop {
            let candidate = rng.gen_range(100_000_000..=999_999_999).to_string();
            let exists: i64 = lock.query_row(
                "SELECT COUNT(*) FROM peers WHERE name = ?1",
                [&candidate],
                |r| r.get(0),
            )?;
            if exists == 0 {
                break candidate;
            }
            attempts += 1;
            if attempts > 100 {
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        };

        let now = current_epoch_seconds();
        lock.execute(
            "INSERT INTO peers (name, role, fingerprint, revoked, created_at)
             VALUES (?1, 'node', ?2, 0, ?3)",
            params![device_id, fingerprint, now],
        )?;

        // Default grant: each device can connect to its own label
        let _ = lock.execute(
            "INSERT OR IGNORE INTO grants (client_name, agent_name, created_at) VALUES (?1, ?1, ?2)",
            params![device_id, now],
        );

        let _ = label;
        Ok(device_id)
    }

    /// Stores a pairing code hash for `device_id`, replacing any existing
    /// code and resetting its attempt counter.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert or update fails.
    pub fn set_pairing_code(
        &self,
        device_id: &str,
        code_hash: &str,
        ttl_secs: u32,
    ) -> SqliteResult<()> {
        let lock = self.conn.lock().expect("lock acquired");
        let expires_at = current_epoch_seconds() + i64::from(ttl_secs);
        lock.execute(
            "INSERT INTO pairing_codes (device_id, code_hash, expires_at, attempts)
             VALUES (?1, ?2, ?3, 0)
             ON CONFLICT(device_id) DO UPDATE SET
                code_hash = excluded.code_hash,
                expires_at = excluded.expires_at,
                attempts = 0",
            params![device_id, code_hash, expires_at],
        )?;
        Ok(())
    }

    /// Verifies a pairing code hash against active records with rate limiting/lockout.
    ///
    /// Returns `Ok(false)` if no code exists, the code has expired, the
    /// attempt limit has been reached, or the hash does not match.
    ///
    /// # Errors
    ///
    /// Returns an error if the lookup query fails.
    pub fn verify_pairing_code(&self, device_id: &str, submitted_hash: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let now = current_epoch_seconds();

        let row: Option<(String, i64, i64)> = lock
            .query_row(
                "SELECT code_hash, expires_at, attempts FROM pairing_codes WHERE device_id = ?1",
                [device_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        let Some((stored_hash, expires_at, attempts)) = row else {
            return Ok(false);
        };

        if now > expires_at || attempts >= 5 {
            return Ok(false);
        }

        // Increment attempt counter
        let _ = lock.execute(
            "UPDATE pairing_codes SET attempts = attempts + 1 WHERE device_id = ?1",
            [device_id],
        );

        let valid =
            rtunnel_identity::constant_time_eq(stored_hash.as_bytes(), submitted_hash.as_bytes());
        if valid {
            // Delete code after successful validation
            let _ = lock.execute(
                "DELETE FROM pairing_codes WHERE device_id = ?1",
                [device_id],
            );
        }
        Ok(valid)
    }

    /// Inserts a peer, or updates its role, fingerprint, and revoked flag if
    /// a peer with the same name already exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert or update fails, for example when the
    /// fingerprint is already pinned to a different peer.
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

    /// Looks up a peer by its pinned fingerprint.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a row cannot be decoded.
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

    /// Looks up a peer by name (or 9-digit Device ID).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a row cannot be decoded.
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

    /// Lists all enrolled peers ordered by name.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or any row cannot be decoded.
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

    /// Replaces the advertised targets for `agent_name`.
    ///
    /// # Errors
    ///
    /// Returns an error if `targets` cannot be serialized to JSON or the
    /// insert or update fails.
    pub fn set_agent_targets(&self, agent_name: &str, targets: &[String]) -> SqliteResult<()> {
        let encoded = serde_json::to_string(targets)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let lock = self.conn.lock().expect("lock acquired");
        lock.execute(
            "INSERT INTO agent_targets (agent_name, targets, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_name) DO UPDATE SET
                targets = excluded.targets,
                updated_at = excluded.updated_at",
            params![agent_name, encoded, current_epoch_seconds()],
        )?;
        Ok(())
    }

    /// Returns the advertised targets for `agent_name`, or an empty list if
    /// none have been stored.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or the stored JSON cannot be
    /// deserialized.
    pub fn get_agent_targets(&self, agent_name: &str) -> SqliteResult<Vec<String>> {
        let lock = self.conn.lock().expect("lock acquired");
        let encoded: Option<String> = lock
            .query_row(
                "SELECT targets FROM agent_targets WHERE agent_name = ?1",
                [agent_name],
                |r| r.get(0),
            )
            .optional()?;
        let Some(encoded) = encoded else {
            return Ok(Vec::new());
        };
        serde_json::from_str(&encoded).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
    }

    /// Marks a peer, matched by name or fingerprint, as revoked.
    ///
    /// Returns `true` if at least one peer was updated.
    ///
    /// # Errors
    ///
    /// Returns an error if the update fails.
    pub fn revoke_peer(&self, target: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let updated = lock.execute(
            "UPDATE peers SET revoked = 1 WHERE name = ?1 OR fingerprint = ?1",
            [target],
        )?;
        Ok(updated > 0)
    }

    /// Stores a single-use enrollment token.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails, for example when a token with
    /// the same hash already exists.
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

    /// Atomically validates and deletes an unexpired token.
    ///
    /// Returns `None` if the token does not exist or has expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the transaction cannot be started or committed,
    /// or if the lookup or delete fails.
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

    /// Lists all unexpired tokens, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or any row cannot be decoded.
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

    /// Deletes a token by hash.
    ///
    /// Returns `true` if a token was deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    pub fn revoke_token(&self, token_hash: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let deleted = lock.execute("DELETE FROM tokens WHERE token_hash = ?1", [token_hash])?;
        Ok(deleted > 0)
    }

    /// Grants `client_name` permission to connect to `agent_name`.
    /// Granting an existing pair is a no-op.
    ///
    /// # Errors
    ///
    /// Returns an error if the insert fails.
    pub fn add_grant(&self, client_name: &str, agent_name: &str) -> SqliteResult<()> {
        let lock = self.conn.lock().expect("lock acquired");
        let now = current_epoch_seconds();
        lock.execute(
            "INSERT OR IGNORE INTO grants (client_name, agent_name, created_at) VALUES (?1, ?2, ?3)",
            params![client_name, agent_name, now],
        )?;
        Ok(())
    }

    /// Removes the grant from `client_name` to `agent_name`.
    ///
    /// Returns `true` if a grant was removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    pub fn remove_grant(&self, client_name: &str, agent_name: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let deleted = lock.execute(
            "DELETE FROM grants WHERE client_name = ?1 AND agent_name = ?2",
            params![client_name, agent_name],
        )?;
        Ok(deleted > 0)
    }

    /// Reports whether `client_name` is granted access to `agent_name`.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub fn has_grant(&self, client_name: &str, agent_name: &str) -> SqliteResult<bool> {
        let lock = self.conn.lock().expect("lock acquired");
        let count: i64 = lock.query_row(
            "SELECT COUNT(*) FROM grants WHERE client_name = ?1 AND agent_name = ?2",
            params![client_name, agent_name],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Lists `(client_name, agent_name)` grants, optionally filtered to a
    /// single client.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or any row cannot be decoded.
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
