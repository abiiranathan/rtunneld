#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use crate::RelayError;
use crate::audit::{AuditLogger, SessionOutcome, SessionRef};
use crate::store::{PeerRecord, SqliteStore};

use quinn::{Connection, Endpoint, Incoming, RecvStream, SendStream, VarInt};
use rtunnel_identity::{KeyMaterial, PinnedClientVerifier, hex_encode};
use rtunnel_proto::{
    ALPN_ENROLL, ALPN_TUNNEL, AgentDetail, AgentInfo, ControlMessage, ErrorCode, HostPort,
    ResultStatus,
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
use tracing::{info, warn};

/// How often the revocation watcher scans the peer store.
const REVOCATION_POLL_INTERVAL: Duration = Duration::from_secs(1);

struct AgentSession {
    connection: Connection,
    fingerprint: String,
    /// Most recent targets advertised by this agent connection.
    targets: Vec<String>,
    _ctrl_send: SendStream,
}

/// The core asynchronous QUIC relay coordinator.
pub struct RelayServer {
    endpoint: Endpoint,
    local_addr: SocketAddr,
    store: Arc<SqliteStore>,
    audit: Arc<AuditLogger>,
    agents: Arc<RwLock<HashMap<String, AgentSession>>>,
    normal_limiter: RateLimiter,
    enroll_limiter: RateLimiter,
    shutdown_rx: watch::Receiver<bool>,
}

/// Closes `connection` with the numeric value of `code` and a human-readable `reason`.
fn close_connection(connection: &Connection, code: ErrorCode, reason: &[u8]) {
    connection.close(VarInt::from_u32(code as u32), reason);
}

/// Sends an `Error` frame and finishes the stream. Best effort: the peer may
/// already be gone, so failures are deliberately ignored.
async fn send_error(send: &mut SendStream, code: ErrorCode, message: impl Into<String>) {
    let frame = ControlMessage::Error {
        code,
        message: message.into(),
    };
    let _ = write_frame(&mut *send, &frame).await;
    let _ = send.finish();
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
    write_frame(&mut *send, &resp).await.is_ok()
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
            vec![ALPN_TUNNEL.to_vec(), ALPN_ENROLL.to_vec()],
        )
        .map_err(|e| RelayError::Transport(e.to_string()))?;

        let endpoint = create_server_endpoint(listen_addr, server_config)
            .map_err(|e| RelayError::Transport(e.to_string()))?;

        // Resolve the bound address once, here, where failure can be reported,
        // so `local_addr()` is infallible and never has to panic.
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
                _ = shutdown.changed() => {
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
        } else if alpn == ALPN_TUNNEL {
            if !self.normal_limiter.check(remote_ip) {
                close_connection(&connection, ErrorCode::RateLimited, b"rate limited");
                return;
            }
            self.handle_authenticated_peer(connection).await;
        } else {
            close_connection(&connection, ErrorCode::ProtocolViolation, b"invalid ALPN");
        }
    }

    async fn handle_enrollment(&self, connection: &Connection) {
        let Ok((mut send, mut recv)) = connection.accept_bi().await else {
            return;
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

        let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));
        let consumed = self.store.consume_token(&token_hash).unwrap_or_else(|e| {
            warn!(error = %e, "token store lookup failed");
            None
        });

        let Some(record) = consumed else {
            self.audit
                .log_auth_failure(&token_hash, "invalid or expired token");
            send_error(
                &mut send,
                ErrorCode::Unauthorized,
                "token invalid or expired",
            )
            .await;
            return;
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
        // Best effort: the enrollment is already persisted, so a lost ack only
        // means the client must retry with a fresh token.
        let _ = write_frame(&mut send, &ack).await;
        let _ = send.finish();

        // Wait for the peer to close its side so the ack is delivered before
        // the connection is dropped.
        let mut drain = [0u8; 1];
        let _ = recv.read(&mut drain).await;
    }

    async fn handle_authenticated_peer(self: &Arc<Self>, connection: Connection) {
        let Ok(peer_fp) = extract_peer_fingerprint(&connection) else {
            close_connection(&connection, ErrorCode::Unauthorized, b"unauthorized");
            return;
        };

        // Unknown, revoked and store-failure cases are all treated as unauthorized.
        let peer = self
            .store
            .get_peer_by_fingerprint(&peer_fp)
            .ok()
            .flatten()
            .filter(|p| !p.revoked);

        let Some(peer) = peer else {
            self.audit
                .log_auth_failure(&peer_fp, "peer unknown or revoked");
            close_connection(&connection, ErrorCode::Unauthorized, b"unauthorized");
            return;
        };

        match peer.role.as_str() {
            "agent" => self.handle_agent_connection(connection, &peer).await,
            "client" => self.handle_client_connection(&connection, &peer).await,
            _ => close_connection(
                &connection,
                ErrorCode::ProtocolViolation,
                b"invalid peer role",
            ),
        }
    }

    async fn handle_agent_connection(&self, connection: Connection, peer: &PeerRecord) {
        let Ok((mut ctrl_send, mut ctrl_recv)) = connection.accept_bi().await else {
            return;
        };

        let Ok(ControlMessage::AgentHello {
            agent_version,
            hostname,
            ..
        }) = read_frame(&mut ctrl_recv).await
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
        if write_frame(&mut ctrl_send, &ack).await.is_err() {
            return;
        }

        let session = AgentSession {
            connection: connection.clone(),
            fingerprint: peer.fingerprint.clone(),
            targets: Vec::new(),
            _ctrl_send: ctrl_send,
        };
        // `insert` hands back any previous session for this agent name, which
        // is then superseded by the new connection.
        let previous = self.agents.write().await.insert(peer.name.clone(), session);
        if let Some(old) = previous {
            info!(agent = %peer.name, "superseding older agent connection");
            close_connection(
                &old.connection,
                ErrorCode::Superseded,
                b"superseded by newer connection",
            );
        }

        let agents = Arc::clone(&self.agents);
        let agent_name = peer.name.clone();
        let control_connection_id = connection.stable_id();
        tokio::spawn(async move {
            // Resolves when the agent closes or drops its control stream.
            let _ = read_frame(&mut ctrl_recv).await;
            let mut lock = agents.write().await;
            // Deregister only if a newer connection has not already replaced this one.
            if lock
                .get(&agent_name)
                .is_some_and(|s| s.connection.stable_id() == control_connection_id)
            {
                lock.remove(&agent_name);
            }
        });

        // Target advertisements arrive on their own streams. Relays that predate
        // discovery never accept these streams, so an agent can send them safely.
        let agents = Arc::clone(&self.agents);
        let store = Arc::clone(&self.store);
        let agent_name = peer.name.clone();
        tokio::spawn(async move {
            while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                let Ok(ControlMessage::AgentTargets { targets }) = read_frame(&mut recv).await
                else {
                    continue;
                };
                // Targets are display and discovery metadata. Drop anything that
                // is not a well-formed host:port so clients never see junk.
                let targets: Vec<String> = targets
                    .into_iter()
                    .filter(|target| HostPort::parse(target).is_ok())
                    .collect();

                info!(agent = %agent_name, targets = ?targets, "agent advertised targets");
                if let Err(e) = store.set_agent_targets(&agent_name, &targets) {
                    warn!(agent = %agent_name, error = %e, "cannot persist advertised targets");
                }
                if let Some(session) = agents.write().await.get_mut(&agent_name) {
                    session.targets = targets;
                }
                let _ = send.finish();
            }
        });
    }

    async fn handle_client_connection(
        self: &Arc<Self>,
        connection: &Connection,
        peer: &PeerRecord,
    ) {
        info!(client = %peer.name, "client connected");
        while let Ok((send, recv)) = connection.accept_bi().await {
            // Share this server (and therefore its rate limiters and agent
            // registry) with the stream task instead of building a copy.
            let server = Arc::clone(self);
            let client_name = peer.name.clone();
            tokio::spawn(async move {
                server.handle_client_stream(send, recv, &client_name).await;
            });
        }
    }

    async fn handle_client_stream(
        &self,
        mut client_send: SendStream,
        mut client_recv: RecvStream,
        client_name: &str,
    ) {
        let Ok(msg) = read_frame(&mut client_recv).await else {
            return;
        };

        match msg {
            ControlMessage::ListAgents { .. } => {
                let grants = self
                    .store
                    .list_grants(Some(client_name))
                    .unwrap_or_else(|e| {
                        warn!(client = %client_name, error = %e, "grant lookup failed");
                        Vec::new()
                    });
                let lock = self.agents.read().await;
                let agents: Vec<AgentInfo> = grants
                    .into_iter()
                    .map(|(_, agent)| {
                        let online = lock.contains_key(&agent);
                        AgentInfo {
                            name: agent,
                            online,
                        }
                    })
                    .collect();
                let resp = ControlMessage::ListAgentsResponse { agents };
                // Best effort: the client may already have disconnected.
                let _ = write_frame(&mut client_send, &resp).await;
            }
            ControlMessage::ListAgentsDetailed { .. } => {
                let grants = self
                    .store
                    .list_grants(Some(client_name))
                    .unwrap_or_else(|e| {
                        warn!(client = %client_name, error = %e, "grant lookup failed");
                        Vec::new()
                    });

                // Snapshot the live registry without touching the store, so the
                // read lock is never held across a database call.
                let live: HashMap<String, (bool, Vec<String>)> = {
                    let lock = self.agents.read().await;
                    grants
                        .iter()
                        .map(|(_, agent)| {
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

                let agents: Vec<AgentDetail> = grants
                    .into_iter()
                    .map(|(_, agent)| {
                        let (online, advertised) = live.get(&agent).cloned().unwrap_or_default();
                        // Fall back to the last advertisement so an offline agent
                        // still shows what it can reach.
                        let targets = if advertised.is_empty() {
                            self.store.get_agent_targets(&agent).unwrap_or_default()
                        } else {
                            advertised
                        };
                        AgentDetail {
                            name: agent,
                            online,
                            targets,
                        }
                    })
                    .collect();

                let resp = ControlMessage::AgentsDetailedResponse { agents };
                let _ = write_frame(&mut client_send, &resp).await;
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

    async fn process_connect_request(
        &self,
        mut client_send: SendStream,
        client_recv: RecvStream,
        client_name: &str,
        agent_name: &str,
        target: Option<&HostPort>,
    ) {
        let allowed = self
            .store
            .has_grant(client_name, agent_name)
            .unwrap_or_else(|e| {
                warn!(client = %client_name, agent = %agent_name, error = %e, "grant check failed");
                false
            });
        if !allowed {
            self.audit
                .log_auth_failure(client_name, "grant missing for target agent");
            send_connect_response(
                &mut client_send,
                "",
                ResultStatus::Err(ErrorCode::Unauthorized),
            )
            .await;
            return;
        }

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

        let Ok((mut agent_send, mut agent_recv)) = agent_conn.open_bi().await else {
            send_connect_response(
                &mut client_send,
                "",
                ResultStatus::Err(ErrorCode::AgentOffline),
            )
            .await;
            return;
        };

        let session_id = hex_encode(&rand::random::<[u8; 16]>());
        // An empty host with port 0 tells the agent to use its default target.
        let (host, port) =
            target.map_or_else(|| (String::new(), 0), |hp| (hp.host.clone(), hp.port));

        let open_msg = ControlMessage::OpenTarget {
            session_id: session_id.clone(),
            client_name: client_name.to_owned(),
            host: host.clone(),
            port,
        };

        if write_frame(&mut agent_send, &open_msg).await.is_err() {
            send_connect_response(
                &mut client_send,
                &session_id,
                ResultStatus::Err(ErrorCode::AgentOffline),
            )
            .await;
            return;
        }

        let open_result = match read_frame(&mut agent_recv).await {
            Ok(ControlMessage::OpenResult { status, .. }) => status,
            _ => ResultStatus::Err(ErrorCode::Internal),
        };

        if !send_connect_response(&mut client_send, &session_id, open_result.clone()).await {
            return;
        }

        if open_result == ResultStatus::Ok {
            let target_str = if host.is_empty() {
                String::from("default")
            } else {
                format!("{host}:{port}")
            };
            self.audit
                .log_session_open(client_name, agent_name, &target_str, &session_id);
            let start = Instant::now();

            let splice_res =
                splice_quic_streams(client_send, client_recv, agent_send, agent_recv).await;
            let duration = start.elapsed().as_millis();

            // Record how the session actually ended instead of always claiming a clean exit.
            let (up, down, reason) = match splice_res {
                Ok((up, down)) => (up, down, String::from("clean exit")),
                Err(e) => (0, 0, format!("splice error: {e}")),
            };

            self.audit.log_session_close(
                &SessionRef {
                    client: client_name,
                    agent: agent_name,
                    target: &target_str,
                    session_id: &session_id,
                },
                &SessionOutcome {
                    bytes_up: up,
                    bytes_down: down,
                    duration_ms: duration,
                    reason: &reason,
                },
            );
        }
    }

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

            // Avoid taking the agent registry's write lock when there is nothing to do.
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
