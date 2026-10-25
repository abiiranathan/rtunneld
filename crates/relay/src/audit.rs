#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use chrono::Utc;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

/// Append-only audit logger writing structured JSONL event records to disk.
pub struct AuditLogger {
    file: Mutex<File>,
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    timestamp: String,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_up: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_down: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'a str>,
}

/// Identifies a relay session in audit records.
#[derive(Debug, Clone, Copy)]
pub struct SessionRef<'a> {
    /// Name of the client that opened the session.
    pub client: &'a str,
    /// Name of the agent serving the session.
    pub agent: &'a str,
    /// Destination on the agent LAN, or `"default"`.
    pub target: &'a str,
    /// Unique session identifier.
    pub session_id: &'a str,
}

/// How a relay session ended.
#[derive(Debug, Clone, Copy)]
pub struct SessionOutcome<'a> {
    /// Bytes relayed from client to agent.
    pub bytes_up: u64,
    /// Bytes relayed from agent to client.
    pub bytes_down: u64,
    /// Session lifetime in milliseconds.
    pub duration_ms: u128,
    /// Human-readable termination reason.
    pub reason: &'a str,
}

impl AuditLogger {
    /// Opens or creates the append-only JSONL audit log in the specified state directory.
    ///
    /// # Errors
    ///
    /// Returns a [`std::io::Error`] if the audit log file cannot be opened for append.
    pub fn open(state_dir: &Path) -> std::io::Result<Self> {
        let path = state_dir.join("audit.log");
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    fn write_record(&self, record: &AuditRecord<'_>) {
        if let Ok(json) = serde_json::to_string(record)
            && let Ok(mut lock) = self.file.lock()
        {
            let _ = writeln!(lock, "{json}");
        }
    }

    /// Logs a session open event.
    pub fn log_session_open(&self, client: &str, agent: &str, target: &str, session_id: &str) {
        self.write_record(&AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            event: "session_open",
            client: Some(client),
            agent: Some(agent),
            target: Some(target),
            session_id: Some(session_id),
            bytes_up: None,
            bytes_down: None,
            duration_ms: None,
            reason: None,
            fingerprint: None,
            action: None,
        });
    }

    /// Logs a session termination event with traffic volumes and duration.
    /// Logs a session termination event with traffic volumes and duration.
    pub fn log_session_close(&self, session: &SessionRef<'_>, outcome: &SessionOutcome<'_>) {
        self.write_record(&AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            event: "session_close",
            client: Some(session.client),
            agent: Some(session.agent),
            target: Some(session.target),
            session_id: Some(session.session_id),
            bytes_up: Some(outcome.bytes_up),
            bytes_down: Some(outcome.bytes_down),
            duration_ms: Some(outcome.duration_ms),
            reason: Some(outcome.reason),
            fingerprint: None,
            action: None,
        });
    }

    /// Logs an authentication or authorization failure.
    pub fn log_auth_failure(&self, fingerprint: &str, reason: &str) {
        self.write_record(&AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            event: "auth_failure",
            client: None,
            agent: None,
            target: None,
            session_id: None,
            bytes_up: None,
            bytes_down: None,
            duration_ms: None,
            reason: Some(reason),
            fingerprint: Some(fingerprint),
            action: None,
        });
    }

    /// Logs a peer enrollment event.
    pub fn log_enroll(&self, name: &str, role: &str, fingerprint: &str) {
        self.write_record(&AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            event: "enroll",
            client: if role == "client" { Some(name) } else { None },
            agent: if role == "agent" { Some(name) } else { None },
            target: None,
            session_id: None,
            bytes_up: None,
            bytes_down: None,
            duration_ms: None,
            reason: None,
            fingerprint: Some(fingerprint),
            action: None,
        });
    }

    /// Logs a grant modification.
    pub fn log_grant_change(&self, action: &str, client: &str, agent: &str) {
        self.write_record(&AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            event: "grant_change",
            client: Some(client),
            agent: Some(agent),
            target: None,
            session_id: None,
            bytes_up: None,
            bytes_down: None,
            duration_ms: None,
            reason: None,
            fingerprint: None,
            action: Some(action),
        });
    }

    /// Logs a revocation event.
    pub fn log_revoke(&self, target: &str) {
        self.write_record(&AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            event: "revoke",
            client: None,
            agent: None,
            target: Some(target),
            session_id: None,
            bytes_up: None,
            bytes_down: None,
            duration_ms: None,
            reason: None,
            fingerprint: None,
            action: None,
        });
    }
}
