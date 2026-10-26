#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

//! QUIC relay coordinator for `rtunneld`.
//!
//! Accepts inbound QUIC connections, dispatches them by ALPN (enrollment,
//! rendezvous, or authenticated tunnel), tracks connected agents, and splices
//! client and agent streams together once a session is authorised.

use crate::RelayError;
use crate::audit::{AuditLogger, SessionOutcome, SessionRef};
use crate::store::{PeerRecord, SqliteStore};

use quinn::{Connection, Endpoint, Incoming, RecvStream, SendStream, VarInt};
use rtunnel_identity::{KeyMaterial, PinnedClientVerifier, hex_encode};
use rtunnel_proto::{
    ALPN_ENROLL, ALPN_RENDEZVOUS, ALPN_TUNNEL, AgentDetail, AgentInfo, ControlMessage, ErrorCode,
    GrantDuration, HostPort, ResultStatus, compute_sas, normalize_device_id,
};
use rtunnel_transport::{
    RateLimiter, create_server_endpoint, extract_alpn, extract_peer_fingerprint,
    make_server_config, read_frame, splice_quic_streams, write_frame,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, watch};
use tracing::{debug, info, warn};

/// How often the revocation watcher scans the peer store.
const REVOCATION_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Client identity recorded when a peer's fingerprint is not in the peer store.
const UNKNOWN_CLIENT_ID: &str = "unknown";

/// Number of random bytes used to build a session or pairing-session ID.
const SESSION_ID_BYTES: usize = 16;

/// Shared registry of currently connected agents, keyed by agent name.
type AgentMap = Arc<RwLock<HashMap<String, AgentSession>>>;

/// A live agent connection tracked by the relay.
struct AgentSession {
    /// QUIC connection to the agent.
    connection: Connection,
    /// Certificate fingerprint of the agent, used by the revocation watcher.
    fingerprint: String,
    /// Most recent targets advertised by this agent connection.
    targets: Vec<String>,
    /// Control stream send half, held so the stream stays open for the
    /// lifetime of the session.
    _ctrl_send: SendStream,
}

/// Borrowed view of a `PairRequest` frame plus the authenticated identity of
/// the requesting connection.
///
/// Bundling the parameters keeps `process_pairing_request` within clippy's
/// argument limit and gives each value a name at the call site.
struct PairingAttempt<'a> {
    /// Certificate fingerprint of the requesting client's QUIC connection.
    client_fp: &'a str,
    /// Target device ID exactly as supplied by the client (not yet normalised).
    raw_target_id: &'a str,
    /// Plain-text ephemeral pairing code supplied by the client.
    code: &'a str,
    /// Human-readable label the client advertises for itself.
    client_label: &'a str,
    /// Optional SSH public key the client wants installed on the host.
    ssh_pubkey: Option<&'a str>,
}

/// The core asynchronous QUIC relay coordinator.
pub struct RelayServer {
    /// Bound QUIC endpoint accepting inbound connections.
    endpoint: Endpoint,
    /// Address the endpoint is bound to, resolved once at construction.
    local_addr: SocketAddr,
    /// Persistent store of peers, tokens, grants, and pairing codes.
    store: Arc<SqliteStore>,
    /// Audit sink for security-relevant events.
    audit: Arc<AuditLogger>,
    /// Currently connected agents, keyed by agent name.
    agents: AgentMap,
    /// Rate limiter for authenticated tunnel connections.
    normal_limiter: RateLimiter,
    /// Rate limiter for enrollment connections.
    enroll_limiter: RateLimiter,
    /// Rate limiter for rendezvous connections.
    rendezvous_limiter: RateLimiter,
    /// Signals that the relay should stop accepting connections.
    shutdown_rx: watch::Receiver<bool>,
}

/// Closes `connection` with the numeric value of `code` and a human-readable `reason`.
fn close_connection(connection: &Connection, code: ErrorCode, reason: &[u8]) {
    connection.close(VarInt::from_u32(code as u32), reason);
}

/// Writes `frame` to `send`.
///
/// `what` names the frame for log output. Returns `false` (after logging a
/// warning) if the write failed, for example because the peer disconnected.
async fn write_logged(send: &mut SendStream, frame: &ControlMessage, what: &str) -> bool {
    if let Err(e) = write_frame(&mut *send, frame).await {
        warn!(frame = what, error = %e, "failed to write frame to peer");
        return false;
    }
    true
}

/// Finishes the send half of a stream.
///
/// `what` names the exchange for log output. Finishing only fails when the
/// stream is already closed, which is expected when the peer has gone away, so
/// the failure is logged at debug level.
fn finish_logged(send: &mut SendStream, what: &str) {
    if let Err(e) = send.finish() {
        debug!(exchange = what, error = %e, "stream already closed when finishing");
    }
}

/// Sends an `Error` frame and finishes the stream.
///
/// Best effort: the peer may already be gone, so failures are logged rather
/// than propagated.
async fn send_error(send: &mut SendStream, code: ErrorCode, message: impl Into<String>) {
    let frame = ControlMessage::Error {
        code,
        message: message.into(),
    };
    write_logged(send, &frame, "Error").await;
    finish_logged(send, "Error");
}

/// Sends a `ConnectResponse` frame. Returns `false` if the frame could not be written.
async fn send_connect_response(
    send: &mut SendStream,
    session_id: &str,
    status: ResultStatus,
) -> bool {
    let resp = ControlMessage::ConnectResponse {
        session_id: session_id.to_owned(),
        status,
    };
    write_logged(send, &resp, "ConnectResponse").await
}

/// Sends a `PairResult` frame to the requesting client.
///
/// `error == None` signals success. A failed write is logged rather than
/// propagated: the client has gone away and there is nobody left to notify.
async fn send_pair_result(send: &mut SendStream, host_device_id: &str, error: Option<ErrorCode>) {
    let resp = ControlMessage::PairResult {
        success: error.is_none(),
        host_device_id: host_device_id.to_owned(),
        error,
    };
    write_logged(send, &resp, "PairResult").await;
}

impl RelayServer {
    /// Constructs and initializes a new QUIC relay server endpoint.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::RelayError`] if socket binding, certificate loading, or endpoint setup fails.
    pub fn new(
        listen_addr: SocketAddr,
        identity: &KeyMaterial,
        store: Arc<SqliteStore>,
        audit: Arc<AuditLogger>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Result<Self, RelayError> {
        let client_verifier = Arc::new(PinnedClientVerifier::new_enrollment());

        let server_config = make_server_config(
            &identity.certificate_der,
            &identity.private_key_pem,
            client_verifier,
            vec![
                ALPN_TUNNEL.to_vec(),
                ALPN_RENDEZVOUS.to_vec(),
                ALPN_ENROLL.to_vec(),
            ],
        )
        .map_err(|e| RelayError::Transport(e.to_string()))?;

        let endpoint = create_server_endpoint(listen_addr, server_config)
            .map_err(|e| RelayError::Transport(e.to_string()))?;

        // Resolve the bound address once so local_addr is infallible.
        let local_addr = endpoint
            .local_addr()
            .map_err(|e| RelayError::Transport(e.to_string()))?;

        Ok(Self {
            endpoint,
            local_addr,
            store,
            audit,
            agents: Arc::new(RwLock::new(HashMap::new())),
            normal_limiter: RateLimiter::new(20, 10),
            enroll_limiter: RateLimiter::new(5, 1),
            rendezvous_limiter: RateLimiter::new(10, 5),
            shutdown_rx,
        })
    }

    /// Returns the local bound listening socket address.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Runs the main relay listening loop and background revocation supervisor.
    pub async fn run(self: Arc<Self>) {
        let revocation_self = Arc::clone(&self);
        tokio::spawn(async move {
            revocation_self.run_revocation_watcher().await;
        });

        info!(addr = %self.local_addr(), "rtunneld listening for inbound QUIC datagrams");
        let mut shutdown = self.shutdown_rx.clone();

        loop {
            tokio::select! {
                res = shutdown.changed() => {
                    if let Err(e) = res {
                        warn!(error = %e, "shutdown channel closed unexpectedly");
                    }
                    info!("relay received shutdown trigger; draining incoming connection loop");
                    break;
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let remote_ip = incoming.remote_address().ip();
                    let relay = Arc::clone(&self);
                    tokio::spawn(async move {
                        relay.handle_incoming(incoming, remote_ip).await;
                    });
                }
            }
        }
        self.endpoint.wait_idle().await;
    }

    /// Completes the handshake for `incoming`, applies the per-ALPN rate limit,
    /// and dispatches the connection to the matching handler.
    async fn handle_incoming(self: &Arc<Self>, incoming: Incoming, remote_ip: IpAddr) {
        let connection = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                warn!(ip = %remote_ip, error = %e, "handshake failed");
                return;
            }
        };

        let alpn = extract_alpn(&connection).unwrap_or_default();
        if alpn == ALPN_ENROLL {
            if !self.enroll_limiter.check(remote_ip) {
                warn!(ip = %remote_ip, "enrollment rate limit exceeded");
                close_connection(&connection, ErrorCode::RateLimited, b"rate limited");
                return;
            }
            self.handle_enrollment(&connection).await;
        } else if alpn == ALPN_RENDEZVOUS {
            if !self.rendezvous_limiter.check(remote_ip) {
                warn!(ip = %remote_ip, "rendezvous rate limit exceeded");
                close_connection(&connection, ErrorCode::RateLimited, b"rate limited");
                return;
            }
            self.handle_rendezvous_peer(connection).await;
        } else if alpn == ALPN_TUNNEL {
            if !self.normal_limiter.check(remote_ip) {
                warn!(ip = %remote_ip, "tunnel rate limit exceeded");
                close_connection(&connection, ErrorCode::RateLimited, b"rate limited");
                return;
            }
            self.handle_authenticated_peer(connection).await;
        } else {
            close_connection(&connection, ErrorCode::ProtocolViolation, b"invalid ALPN");
        }
    }

    /// Handles a single-use enrollment exchange: redeems the token, records the
    /// peer's certificate fingerprint, and acknowledges the enrollment.
    async fn handle_enrollment(&self, connection: &Connection) {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                debug!(error = %e, "enrollment connection closed before opening a stream");
                return;
            }
        };

        let msg = match read_frame(&mut recv).await {
            Ok(m) => m,
            Err(e) => {
                send_error(&mut send, ErrorCode::ProtocolViolation, e.to_string()).await;
                return;
            }
        };

        let ControlMessage::Enroll { token } = msg else {
            send_error(
                &mut send,
                ErrorCode::ProtocolViolation,
                "expected Enroll frame",
            )
            .await;
            return;
        };

        // Only the hash of the token is ever stored or logged.
        let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));
        let record = match self.store.consume_token(&token_hash) {
            Ok(Some(record)) => record,
            Ok(None) => {
                self.audit
                    .log_auth_failure(&token_hash, "invalid or expired token");
                send_error(
                    &mut send,
                    ErrorCode::Unauthorized,
                    "token invalid or expired",
                )
                .await;
                return;
            }
            Err(e) => {
                warn!(error = %e, "token store lookup failed");
                send_error(&mut send, ErrorCode::Internal, "token store unavailable").await;
                return;
            }
        };

        let peer_fp = match extract_peer_fingerprint(connection) {
            Ok(fp) => fp,
            Err(e) => {
                send_error(&mut send, ErrorCode::Internal, e.to_string()).await;
                return;
            }
        };

        let new_peer = PeerRecord {
            name: record.name.clone(),
            role: record.role.clone(),
            fingerprint: peer_fp.clone(),
            revoked: false,
        };

        if let Err(e) = self.store.upsert_peer(&new_peer) {
            send_error(&mut send, ErrorCode::Internal, e.to_string()).await;
            return;
        }

        self.audit.log_enroll(&record.name, &record.role, &peer_fp);
        info!(name = %record.name, role = %record.role, "peer enrolled successfully");

        let ack = ControlMessage::EnrollAck {
            name: record.name,
            role: record.role,
        };
        write_logged(&mut send, &ack, "EnrollAck").await;
        finish_logged(&mut send, "EnrollAck");

        // Wait for the peer to close its side so the ack is delivered before
        // the connection is dropped.
        let mut drain = [0u8; 1];
        if let Err(e) = recv.read(&mut drain).await {
            debug!(error = %e, "enrollment stream ended with an error while draining");
        }
    }

    /// Handles AnyDesk-style rendezvous peers: Device ID registration, ephemeral
    /// access code updates, and out-of-band SAS pairing requests.
    async fn handle_rendezvous_peer(self: &Arc<Self>, connection: Connection) {
        let peer_fp = match extract_peer_fingerprint(&connection) {
            Ok(fp) => fp,
            Err(e) => {
                warn!(error = %e, "rendezvous peer has no usable fingerprint");
                close_connection(&connection, ErrorCode::Unauthorized, b"unauthorized");
                return;
            }
        };

        loop {
            let (mut send, mut recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    debug!(error = %e, "rendezvous connection closed");
                    break;
                }
            };
            let msg = match read_frame(&mut recv).await {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "cannot read rendezvous frame");
                    break;
                }
            };

            match msg {
                ControlMessage::RegisterDevice { label, .. } => {
                    self.handle_register_device(&mut send, &peer_fp, &label)
                        .await;
                }
                ControlMessage::SetPairingCode {
                    code_hash,
                    ttl_secs,
                } => {
                    let device_id = match self.registered_peer_name(&peer_fp) {
                        Ok(name) => name,
                        Err(code) => {
                            send_error(&mut send, code, "device not registered or lookup failed")
                                .await;
                            continue;
                        }
                    };

                    match self
                        .store
                        .set_pairing_code(&device_id, &code_hash, ttl_secs)
                    {
                        Ok(..) => {
                            info!(device_id = %device_id, "updated pairing code");
                            finish_logged(&mut send, "SetPairingCode");
                        }
                        Err(e) => {
                            send_error(&mut send, ErrorCode::Internal, e.to_string()).await;
                        }
                    }
                }
                ControlMessage::PairRequest {
                    target_device_id,
                    code,
                    client_label,
                    ssh_pubkey,
                } => {
                    let attempt = PairingAttempt {
                        client_fp: &peer_fp,
                        raw_target_id: &target_device_id,
                        code: &code,
                        client_label: &client_label,
                        ssh_pubkey: ssh_pubkey.as_deref(),
                    };
                    self.process_pairing_request(&mut send, &attempt).await;
                }
                ControlMessage::ConnectRequest { agent, target } => {
                    let client_id = match self.registered_peer_name(&peer_fp) {
                        Ok(name) => name,
                        Err(code) => {
                            send_connect_response(&mut send, "", ResultStatus::Err(code)).await;
                            continue;
                        }
                    };
                    self.process_connect_request(send, recv, &client_id, &agent, target.as_ref())
                        .await;
                }
                other => {
                    send_error(
                        &mut send,
                        ErrorCode::ProtocolViolation,
                        format!("unexpected rendezvous message: {other:?}"),
                    )
                    .await;
                }
            }
        }
    }

    /// Allocates (or returns the existing) device ID for the peer with
    /// fingerprint `peer_fp` and replies with `RegisterDeviceAck`.
    async fn handle_register_device(&self, send: &mut SendStream, peer_fp: &str, label: &str) {
        match self.store.get_or_allocate_device_id(peer_fp, label) {
            Ok(device_id) => {
                info!(device_id = %device_id, label = %label, "allocated device id");
                let resp = ControlMessage::RegisterDeviceAck { device_id };
                write_logged(send, &resp, "RegisterDeviceAck").await;
                finish_logged(send, "RegisterDeviceAck");
            }
            Err(e) => {
                send_error(send, ErrorCode::Internal, e.to_string()).await;
            }
        }
    }

    /// Returns the registered name of the peer with the given fingerprint.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Unauthorized`] if the fingerprint is not registered,
    /// [`ErrorCode::Internal`] if the store lookup fails.
    fn registered_peer_name(&self, fingerprint: &str) -> Result<String, ErrorCode> {
        match self.store.get_peer_by_fingerprint(fingerprint) {
            Ok(Some(peer)) => Ok(peer.name),
            Ok(None) => Err(ErrorCode::Unauthorized),
            Err(e) => {
                warn!(error = %e, "peer lookup by fingerprint failed");
                Err(ErrorCode::Internal)
            }
        }
    }

    /// Coordinates out-of-band SAS code pairing between a client and a host.
    ///
    /// Runs the pairing workflow via [`Self::run_pairing`] and reports the
    /// outcome to the client as a single `PairResult` frame.
    async fn process_pairing_request(
        &self,
        client_send: &mut SendStream,
        attempt: &PairingAttempt<'_>,
    ) {
        let target_device_id = normalize_device_id(attempt.raw_target_id);
        let error = self.run_pairing(attempt, &target_device_id).await.err();
        send_pair_result(client_send, &target_device_id, error).await;
    }

    /// Executes the pairing workflow end to end.
    ///
    /// # Errors
    ///
    /// Returns the [`ErrorCode`] that should be reported to the client when the
    /// host is unknown or revoked, the pairing code is wrong, the host is
    /// offline or unresponsive, the host denies the request, or a store
    /// operation fails.
    async fn run_pairing(
        &self,
        attempt: &PairingAttempt<'_>,
        target_device_id: &str,
    ) -> Result<(), ErrorCode> {
        let host_peer = self.lookup_active_host(target_device_id)?;
        self.verify_pairing_code(attempt, target_device_id)?;

        // Clone the connection so the agents lock is not held across awaits.
        let host_conn = self
            .agents
            .read()
            .await
            .get(target_device_id)
            .map(|s| s.connection.clone())
            .ok_or(ErrorCode::AgentOffline)?;

        let client_id = self.resolve_client_id(attempt.client_fp)?;

        let pair_session_id = hex_encode(&rand::random::<[u8; SESSION_ID_BYTES]>());
        let prompt = ControlMessage::IncomingPairPrompt {
            sas: compute_sas(attempt.client_fp, &host_peer.fingerprint, &pair_session_id),
            pair_session_id: pair_session_id.clone(),
            client_id: client_id.clone(),
            client_label: attempt.client_label.to_owned(),
            ssh_pubkey: attempt.ssh_pubkey.map(ToOwned::to_owned),
        };

        let duration = match Self::await_host_decision(&host_conn, &prompt, &pair_session_id).await
        {
            Ok(duration) => duration,
            Err(code) => {
                if matches!(code, ErrorCode::PairingDenied) {
                    self.audit
                        .log_auth_failure(&client_id, "pairing request denied by host");
                }
                return Err(code);
            }
        };

        if duration == GrantDuration::Always {
            self.store
                .add_grant(&client_id, target_device_id)
                .map_err(|e| {
                    warn!(client = %client_id, host = %target_device_id, error = %e, "failed to persist grant");
                    ErrorCode::Internal
                })?;
        }
        self.audit
            .log_grant_change("pair_approved", &client_id, target_device_id);
        Ok(())
    }

    /// Looks up the host peer registered under `device_id`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::DeviceNotFound`] if the host is unknown or revoked,
    /// [`ErrorCode::Internal`] if the store lookup fails.
    fn lookup_active_host(&self, device_id: &str) -> Result<PeerRecord, ErrorCode> {
        match self.store.get_peer_by_name(device_id) {
            Ok(Some(peer)) if !peer.revoked => Ok(peer),
            Ok(_) => Err(ErrorCode::DeviceNotFound),
            Err(e) => {
                warn!(host = %device_id, error = %e, "host lookup failed");
                Err(ErrorCode::Internal)
            }
        }
    }

    /// Validates the ephemeral pairing code against the store.
    ///
    /// The store performs the constant-time comparison and progressive lockout.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::InvalidPairingCode`] (and an audit entry) on a wrong or
    /// expired code, [`ErrorCode::Internal`] if the store lookup fails.
    fn verify_pairing_code(
        &self,
        attempt: &PairingAttempt<'_>,
        device_id: &str,
    ) -> Result<(), ErrorCode> {
        let code_hash = hex_encode(&Sha256::digest(attempt.code.as_bytes()));
        match self.store.verify_pairing_code(device_id, &code_hash) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.audit
                    .log_auth_failure(attempt.client_fp, "invalid or expired pairing code");
                Err(ErrorCode::InvalidPairingCode)
            }
            Err(e) => {
                warn!(host = %device_id, error = %e, "pairing code verification failed");
                Err(ErrorCode::Internal)
            }
        }
    }

    /// Maps a client fingerprint to its registered name, falling back to
    /// [`UNKNOWN_CLIENT_ID`] when the fingerprint is not in the peer store.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Internal`] if the store lookup itself fails.
    fn resolve_client_id(&self, fingerprint: &str) -> Result<String, ErrorCode> {
        match self.store.get_peer_by_fingerprint(fingerprint) {
            Ok(Some(peer)) => Ok(peer.name),
            Ok(None) => Ok(UNKNOWN_CLIENT_ID.to_owned()),
            Err(e) => {
                warn!(error = %e, "client lookup by fingerprint failed");
                Err(ErrorCode::Internal)
            }
        }
    }

    /// Opens a stream to the host, delivers `prompt`, and waits for the
    /// operator's decision.
    ///
    /// Returns the [`GrantDuration`] the operator approved.
    ///
    /// # Errors
    ///
    /// * [`ErrorCode::AgentOffline`] if the stream cannot be opened, the prompt
    ///   cannot be written, or the reply cannot be read.
    /// * [`ErrorCode::PairingDenied`] if the operator rejected the request.
    /// * [`ErrorCode::Internal`] if the host replied with an unexpected frame
    ///   or a mismatched `pair_session_id`.
    async fn await_host_decision(
        host_conn: &Connection,
        prompt: &ControlMessage,
        pair_session_id: &str,
    ) -> Result<GrantDuration, ErrorCode> {
        let (mut send, mut recv) = host_conn.open_bi().await.map_err(|e| {
            warn!(error = %e, "cannot open pairing stream to host");
            ErrorCode::AgentOffline
        })?;

        write_frame(&mut send, prompt).await.map_err(|e| {
            warn!(error = %e, "cannot deliver pairing prompt to host");
            ErrorCode::AgentOffline
        })?;

        match read_frame(&mut recv).await {
            Ok(ControlMessage::PairPromptResponse {
                pair_session_id: reply_id,
                approved,
                duration,
                ..
            }) if reply_id == pair_session_id => {
                if approved {
                    Ok(duration)
                } else {
                    Err(ErrorCode::PairingDenied)
                }
            }
            Ok(_) => {
                warn!("host sent an unexpected or mismatched pairing reply");
                Err(ErrorCode::Internal)
            }
            Err(e) => {
                warn!(error = %e, "cannot read pairing reply from host");
                Err(ErrorCode::AgentOffline)
            }
        }
    }

    /// Authenticates a tunnel-ALPN peer against the peer store and routes it
    /// by role (agent/node or client).
    async fn handle_authenticated_peer(self: &Arc<Self>, connection: Connection) {
        let peer_fp = match extract_peer_fingerprint(&connection) {
            Ok(fp) => fp,
            Err(e) => {
                warn!(error = %e, "tunnel peer has no usable fingerprint");
                close_connection(&connection, ErrorCode::Unauthorized, b"unauthorized");
                return;
            }
        };

        let peer = match self.store.get_peer_by_fingerprint(&peer_fp) {
            Ok(Some(peer)) if !peer.revoked => peer,
            Ok(_) => {
                self.audit
                    .log_auth_failure(&peer_fp, "peer unknown or revoked");
                close_connection(&connection, ErrorCode::Unauthorized, b"unauthorized");
                return;
            }
            Err(e) => {
                warn!(error = %e, "peer store lookup failed during authentication");
                close_connection(&connection, ErrorCode::Internal, b"internal error");
                return;
            }
        };

        match peer.role.as_str() {
            "agent" | "node" => self.handle_agent_connection(connection, &peer).await,
            "client" => self.handle_client_connection(&connection, &peer).await,
            _ => close_connection(
                &connection,
                ErrorCode::ProtocolViolation,
                b"invalid peer role",
            ),
        }
    }

    /// Registers an authenticated agent: performs the hello exchange, replaces
    /// any older connection for the same agent, and spawns the background
    /// tasks that track the control stream and advertised targets.
    async fn handle_agent_connection(&self, connection: Connection, peer: &PeerRecord) {
        let (mut ctrl_send, mut ctrl_recv) = match connection.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                debug!(agent = %peer.name, error = %e, "agent closed before opening control stream");
                return;
            }
        };

        let hello = match read_frame(&mut ctrl_recv).await {
            Ok(msg) => msg,
            Err(e) => {
                warn!(agent = %peer.name, error = %e, "cannot read AgentHello");
                close_connection(
                    &connection,
                    ErrorCode::ProtocolViolation,
                    b"expected AgentHello",
                );
                return;
            }
        };
        let ControlMessage::AgentHello {
            agent_version,
            hostname,
            ..
        } = hello
        else {
            close_connection(
                &connection,
                ErrorCode::ProtocolViolation,
                b"expected AgentHello",
            );
            return;
        };

        info!(agent = %peer.name, version = %agent_version, hostname = %hostname, "agent registered");

        let ack = ControlMessage::HelloAck {
            agent_name: peer.name.clone(),
        };
        if !write_logged(&mut ctrl_send, &ack, "HelloAck").await {
            return;
        }

        let session = AgentSession {
            connection: connection.clone(),
            fingerprint: peer.fingerprint.clone(),
            targets: Vec::new(),
            _ctrl_send: ctrl_send,
        };

        let previous = self.agents.write().await.insert(peer.name.clone(), session);
        if let Some(old) = previous {
            info!(agent = %peer.name, "superseding older agent connection");
            close_connection(
                &old.connection,
                ErrorCode::Superseded,
                b"superseded by newer connection",
            );
        }

        Self::spawn_control_watcher(
            Arc::clone(&self.agents),
            peer.name.clone(),
            connection.stable_id(),
            ctrl_recv,
        );
        Self::spawn_target_listener(
            Arc::clone(&self.agents),
            Arc::clone(&self.store),
            peer.name.clone(),
            connection,
        );
    }

    /// Spawns a task that waits for the agent's control stream to end and then
    /// deregisters the agent, provided the registered session still belongs to
    /// the connection identified by `connection_id` (a newer connection may
    /// have superseded it).
    fn spawn_control_watcher(
        agents: AgentMap,
        agent_name: String,
        connection_id: usize,
        mut ctrl_recv: RecvStream,
    ) {
        tokio::spawn(async move {
            match read_frame(&mut ctrl_recv).await {
                Ok(_) => {
                    warn!(agent = %agent_name, "agent sent an unexpected control frame; deregistering");
                }
                Err(e) => {
                    debug!(agent = %agent_name, error = %e, "agent control stream ended");
                }
            }
            let mut lock = agents.write().await;
            if lock
                .get(&agent_name)
                .is_some_and(|s| s.connection.stable_id() == connection_id)
            {
                lock.remove(&agent_name);
            }
        });
    }

    /// Spawns a task that accepts `AgentTargets` advertisements on `connection`,
    /// validates them, persists them, and updates the live session.
    fn spawn_target_listener(
        agents: AgentMap,
        store: Arc<SqliteStore>,
        agent_name: String,
        connection: Connection,
    ) {
        tokio::spawn(async move {
            loop {
                let (mut send, mut recv) = match connection.accept_bi().await {
                    Ok(streams) => streams,
                    Err(e) => {
                        debug!(agent = %agent_name, error = %e, "agent connection closed");
                        break;
                    }
                };
                let msg = match read_frame(&mut recv).await {
                    Ok(msg) => msg,
                    Err(e) => {
                        warn!(agent = %agent_name, error = %e, "cannot read agent frame");
                        continue;
                    }
                };
                let ControlMessage::AgentTargets { targets } = msg else {
                    warn!(agent = %agent_name, "ignoring unexpected agent frame; expected AgentTargets");
                    continue;
                };

                // Drop malformed entries rather than trusting the agent.
                let targets: Vec<String> = targets
                    .into_iter()
                    .filter(|target| match HostPort::parse(target) {
                        Ok(_) => true,
                        Err(e) => {
                            warn!(agent = %agent_name, target = %target, error = %e, "discarding invalid advertised target");
                            false
                        }
                    })
                    .collect();

                info!(agent = %agent_name, targets = ?targets, "agent advertised targets");
                if let Err(e) = store.set_agent_targets(&agent_name, &targets) {
                    warn!(agent = %agent_name, error = %e, "cannot persist advertised targets");
                }
                if let Some(session) = agents.write().await.get_mut(&agent_name) {
                    session.targets = targets;
                }
                finish_logged(&mut send, "AgentTargets");
            }
        });
    }

    /// Serves an authenticated client connection, handling each bidirectional
    /// stream in its own task.
    async fn handle_client_connection(
        self: &Arc<Self>,
        connection: &Connection,
        peer: &PeerRecord,
    ) {
        info!(client = %peer.name, "client connected");
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    debug!(client = %peer.name, error = %e, "client connection closed");
                    break;
                }
            };
            let server = Arc::clone(self);
            let client_name = peer.name.clone();
            tokio::spawn(async move {
                server.handle_client_stream(send, recv, &client_name).await;
            });
        }
    }

    /// Reads the first frame of a client stream and dispatches it.
    async fn handle_client_stream(
        &self,
        mut client_send: SendStream,
        mut client_recv: RecvStream,
        client_name: &str,
    ) {
        let msg = match read_frame(&mut client_recv).await {
            Ok(msg) => msg,
            Err(e) => {
                warn!(client = %client_name, error = %e, "cannot read client frame");
                return;
            }
        };

        match msg {
            ControlMessage::ListAgents { .. } => {
                self.handle_list_agents(&mut client_send, client_name).await;
            }
            ControlMessage::ListAgentsDetailed { .. } => {
                self.handle_list_agents_detailed(&mut client_send, client_name)
                    .await;
            }
            ControlMessage::ConnectRequest { agent, target } => {
                self.process_connect_request(
                    client_send,
                    client_recv,
                    client_name,
                    &agent,
                    target.as_ref(),
                )
                .await;
            }
            _ => {
                send_error(
                    &mut client_send,
                    ErrorCode::ProtocolViolation,
                    "unexpected client frame",
                )
                .await;
            }
        }
    }

    /// Returns the names of all agents `client_name` has been granted access to.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Internal`] if the grant lookup fails.
    fn granted_agents(&self, client_name: &str) -> Result<Vec<String>, ErrorCode> {
        self.store
            .list_grants(Some(client_name))
            .map(|grants| grants.into_iter().map(|(_, agent)| agent).collect())
            .map_err(|e| {
                warn!(client = %client_name, error = %e, "grant lookup failed");
                ErrorCode::Internal
            })
    }

    /// Returns the targets persisted for `agent`, or an empty list (after
    /// logging) if the lookup fails.
    fn persisted_targets(&self, agent: &str) -> Vec<String> {
        self.store.get_agent_targets(agent).unwrap_or_else(|e| {
            warn!(agent = %agent, error = %e, "persisted target lookup failed");
            Vec::new()
        })
    }

    /// Replies to `ListAgents` with the granted agents and their online status.
    async fn handle_list_agents(&self, client_send: &mut SendStream, client_name: &str) {
        let granted = match self.granted_agents(client_name) {
            Ok(granted) => granted,
            Err(code) => {
                send_error(client_send, code, "grant lookup failed").await;
                return;
            }
        };

        let agents: Vec<AgentInfo> = {
            let lock = self.agents.read().await;
            granted
                .into_iter()
                .map(|name| {
                    let online = lock.contains_key(&name);
                    AgentInfo { name, online }
                })
                .collect()
        };

        let resp = ControlMessage::ListAgentsResponse { agents };
        write_logged(client_send, &resp, "ListAgentsResponse").await;
    }

    /// Replies to `ListAgentsDetailed` with the granted agents, their online
    /// status, and their targets (live advertisement first, persisted
    /// targets as a fallback).
    async fn handle_list_agents_detailed(&self, client_send: &mut SendStream, client_name: &str) {
        let granted = match self.granted_agents(client_name) {
            Ok(granted) => granted,
            Err(code) => {
                send_error(client_send, code, "grant lookup failed").await;
                return;
            }
        };

        // Snapshot live state under the lock, then release it before touching
        // the store.
        let mut live: HashMap<String, (bool, Vec<String>)> = {
            let lock = self.agents.read().await;
            granted
                .iter()
                .map(|agent| {
                    let session = lock.get(agent);
                    (
                        agent.clone(),
                        (
                            session.is_some(),
                            session.map_or_else(Vec::new, |s| s.targets.clone()),
                        ),
                    )
                })
                .collect()
        };

        let agents: Vec<AgentDetail> = granted
            .into_iter()
            .map(|name| {
                let (online, advertised) = live.remove(&name).unwrap_or_default();
                let targets = if advertised.is_empty() {
                    self.persisted_targets(&name)
                } else {
                    advertised
                };
                AgentDetail {
                    name,
                    online,
                    targets,
                }
            })
            .collect();

        let resp = ControlMessage::AgentsDetailedResponse { agents };
        write_logged(client_send, &resp, "AgentsDetailedResponse").await;
    }

    /// Checks that `client_name` may connect to `agent_name`.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Unauthorized`] (and an audit entry) if no grant exists,
    /// [`ErrorCode::Internal`] if the grant lookup fails.
    fn authorize_connect(&self, client_name: &str, agent_name: &str) -> Result<(), ErrorCode> {
        match self.store.has_grant(client_name, agent_name) {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.audit
                    .log_auth_failure(client_name, "grant missing for target agent");
                Err(ErrorCode::Unauthorized)
            }
            Err(e) => {
                warn!(client = %client_name, agent = %agent_name, error = %e, "grant check failed");
                Err(ErrorCode::Internal)
            }
        }
    }

    /// Authorises a client's connect request, asks the agent to open the
    /// target, reports the result to the client, and (on success) relays the
    /// session until either side closes.
    async fn process_connect_request(
        &self,
        mut client_send: SendStream,
        client_recv: RecvStream,
        client_name: &str,
        agent_name: &str,
        target: Option<&HostPort>,
    ) {
        if let Err(code) = self.authorize_connect(client_name, agent_name) {
            send_connect_response(&mut client_send, "", ResultStatus::Err(code)).await;
            return;
        }

        // Clone the connection so the agents lock is not held across awaits.
        let agent_conn = self
            .agents
            .read()
            .await
            .get(agent_name)
            .map(|s| s.connection.clone());

        let Some(agent_conn) = agent_conn else {
            send_connect_response(
                &mut client_send,
                "",
                ResultStatus::Err(ErrorCode::AgentOffline),
            )
            .await;
            return;
        };

        let (mut agent_send, mut agent_recv) = match agent_conn.open_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                warn!(agent = %agent_name, error = %e, "cannot open session stream to agent");
                send_connect_response(
                    &mut client_send,
                    "",
                    ResultStatus::Err(ErrorCode::AgentOffline),
                )
                .await;
                return;
            }
        };

        let session_id = hex_encode(&rand::random::<[u8; SESSION_ID_BYTES]>());
        let (host, port) =
            target.map_or_else(|| (String::new(), 0), |hp| (hp.host.clone(), hp.port));

        let open_msg = ControlMessage::OpenTarget {
            session_id: session_id.clone(),
            client_name: client_name.to_owned(),
            host: host.clone(),
            port,
        };
        let open_result =
            Self::negotiate_open(&mut agent_send, &mut agent_recv, &open_msg, agent_name).await;

        if !send_connect_response(&mut client_send, &session_id, open_result.clone()).await {
            return;
        }

        if open_result == ResultStatus::Ok {
            let target_str = if host.is_empty() {
                String::from("default")
            } else {
                format!("{host}:{port}")
            };
            let session = SessionRef {
                client: client_name,
                agent: agent_name,
                target: &target_str,
                session_id: &session_id,
            };
            self.relay_session(&session, client_send, client_recv, agent_send, agent_recv)
                .await;
        }
    }

    /// Sends `open_msg` to the agent and waits for its `OpenResult`.
    ///
    /// Failures are logged and mapped to a [`ResultStatus::Err`] so the caller
    /// can report them to the client: a write failure becomes
    /// [`ErrorCode::AgentOffline`]; an unreadable or unexpected reply becomes
    /// [`ErrorCode::Internal`].
    async fn negotiate_open(
        agent_send: &mut SendStream,
        agent_recv: &mut RecvStream,
        open_msg: &ControlMessage,
        agent_name: &str,
    ) -> ResultStatus {
        if let Err(e) = write_frame(agent_send, open_msg).await {
            warn!(agent = %agent_name, error = %e, "cannot deliver OpenTarget to agent");
            return ResultStatus::Err(ErrorCode::AgentOffline);
        }

        match read_frame(agent_recv).await {
            Ok(ControlMessage::OpenResult { status, .. }) => status,
            Ok(_) => {
                warn!(agent = %agent_name, "agent replied with an unexpected frame to OpenTarget");
                ResultStatus::Err(ErrorCode::Internal)
            }
            Err(e) => {
                warn!(agent = %agent_name, error = %e, "cannot read OpenResult from agent");
                ResultStatus::Err(ErrorCode::Internal)
            }
        }
    }

    /// Splices the client and agent streams together, auditing the session
    /// open and close (including byte counts, duration, and exit reason).
    async fn relay_session(
        &self,
        session: &SessionRef<'_>,
        client_send: SendStream,
        client_recv: RecvStream,
        agent_send: SendStream,
        agent_recv: RecvStream,
    ) {
        self.audit.log_session_open(
            session.client,
            session.agent,
            session.target,
            session.session_id,
        );
        let start = Instant::now();

        let splice_res =
            splice_quic_streams(client_send, client_recv, agent_send, agent_recv).await;
        let duration = start.elapsed().as_millis();

        let (up, down, reason) = match splice_res {
            Ok((up, down)) => (up, down, String::from("clean exit")),
            Err(e) => {
                warn!(session = %session.session_id, error = %e, "session splice failed");
                (0, 0, format!("splice error: {e}"))
            }
        };

        self.audit.log_session_close(
            session,
            &SessionOutcome {
                bytes_up: up,
                bytes_down: down,
                duration_ms: duration,
                reason: &reason,
            },
        );
    }

    /// Periodically scans the peer store and closes the connections of any
    /// connected agent whose identity has been revoked.
    async fn run_revocation_watcher(&self) {
        let mut interval = tokio::time::interval(REVOCATION_POLL_INTERVAL);
        loop {
            interval.tick().await;
            let peers = match self.store.list_peers() {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "revocation watcher cannot list peers");
                    continue;
                }
            };
            let revoked_fps: Vec<String> = peers
                .into_iter()
                .filter(|p| p.revoked)
                .map(|p| p.fingerprint)
                .collect();

            if revoked_fps.is_empty() {
                continue;
            }

            let mut lock = self.agents.write().await;
            lock.retain(|name, session| {
                if revoked_fps.contains(&session.fingerprint) {
                    info!(agent = %name, "terminating connection of revoked agent");
                    close_connection(&session.connection, ErrorCode::Revoked, b"identity revoked");
                    false
                } else {
                    true
                }
            });
        }
    }
}
