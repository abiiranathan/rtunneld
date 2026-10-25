#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use crate::audit::AuditLogger;
use crate::store::SqliteStore;
use quinn::{Connection, Endpoint, SendStream, VarInt};
use rtunnel_identity::{KeyMaterial, PinnedClientVerifier, hex_encode};
use rtunnel_proto::{
    ALPN_ENROLL, ALPN_TUNNEL, AgentInfo, ControlMessage, ErrorCode, HostPort, ResultStatus,
};
use rtunnel_transport::{
    RateLimiter, create_server_endpoint, extract_alpn, extract_peer_fingerprint,
    make_server_config, read_frame, splice_quic_streams, write_frame,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, watch};
use tracing::{info, warn};

struct AgentSession {
    connection: Connection,
    fingerprint: String,
    _ctrl_send: SendStream,
}

/// The core asynchronous QUIC relay coordinator.
pub struct RelayServer {
    endpoint: Endpoint,
    store: Arc<SqliteStore>,
    audit: Arc<AuditLogger>,
    agents: Arc<RwLock<HashMap<String, AgentSession>>>,
    normal_limiter: RateLimiter,
    enroll_limiter: RateLimiter,
    shutdown_rx: watch::Receiver<bool>,
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
    ) -> Result<Self, crate::RelayError> {
        let client_verifier = Arc::new(PinnedClientVerifier::new_enrollment());

        let server_config = make_server_config(
            &identity.certificate_der,
            &identity.private_key_pem,
            client_verifier,
            vec![ALPN_TUNNEL.to_vec(), ALPN_ENROLL.to_vec()],
        )
        .map_err(|e| crate::RelayError::Transport(e.to_string()))?;

        let endpoint = create_server_endpoint(listen_addr, server_config)
            .map_err(|e| crate::RelayError::Transport(e.to_string()))?;

        Ok(Self {
            endpoint,
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
        self.endpoint
            .local_addr()
            .expect("endpoint has bound address")
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

    async fn handle_incoming(&self, incoming: quinn::Incoming, remote_ip: std::net::IpAddr) {
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
                connection.close(
                    VarInt::from_u32(ErrorCode::RateLimited as u32),
                    b"rate limited",
                );
                return;
            }
            self.handle_enrollment(connection).await;
        } else if alpn == ALPN_TUNNEL {
            if !self.normal_limiter.check(remote_ip) {
                connection.close(
                    VarInt::from_u32(ErrorCode::RateLimited as u32),
                    b"rate limited",
                );
                return;
            }
            self.handle_authenticated_peer(connection).await;
        } else {
            connection.close(
                VarInt::from_u32(ErrorCode::ProtocolViolation as u32),
                b"invalid ALPN",
            );
        }
    }

    async fn handle_enrollment(&self, connection: Connection) {
        let (mut send, mut recv) = match connection.accept_bi().await {
            Ok(bi) => bi,
            Err(_) => return,
        };

        let msg = match read_frame(&mut recv).await {
            Ok(m) => m,
            Err(e) => {
                let _ = write_frame(
                    &mut send,
                    &ControlMessage::Error {
                        code: ErrorCode::ProtocolViolation,
                        message: e.to_string(),
                    },
                )
                .await;
                return;
            }
        };

        let ControlMessage::Enroll { token } = msg else {
            let _ = write_frame(
                &mut send,
                &ControlMessage::Error {
                    code: ErrorCode::ProtocolViolation,
                    message: "expected Enroll frame".into(),
                },
            )
            .await;
            return;
        };

        let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));
        let consumed = self.store.consume_token(&token_hash).unwrap_or(None);

        let Some(record) = consumed else {
            self.audit
                .log_auth_failure(&token_hash, "invalid or expired token");
            let _ = write_frame(
                &mut send,
                &ControlMessage::Error {
                    code: ErrorCode::Unauthorized,
                    message: "token invalid or expired".into(),
                },
            )
            .await;
            let _ = send.finish();
            return;
        };

        let peer_fp = match extract_peer_fingerprint(&connection) {
            Ok(fp) => fp,
            Err(e) => {
                let _ = write_frame(
                    &mut send,
                    &ControlMessage::Error {
                        code: ErrorCode::Internal,
                        message: e.to_string(),
                    },
                )
                .await;
                let _ = send.finish();
                return;
            }
        };

        let new_peer = crate::store::PeerRecord {
            name: record.name.clone(),
            role: record.role.clone(),
            fingerprint: peer_fp.clone(),
            revoked: false,
        };

        if let Err(e) = self.store.upsert_peer(&new_peer) {
            let _ = write_frame(
                &mut send,
                &ControlMessage::Error {
                    code: ErrorCode::Internal,
                    message: e.to_string(),
                },
            )
            .await;
            let _ = send.finish();
            return;
        }

        self.audit.log_enroll(&record.name, &record.role, &peer_fp);
        info!(name = %record.name, role = %record.role, "peer enrolled successfully");

        let _ = write_frame(
            &mut send,
            &ControlMessage::EnrollAck {
                name: record.name,
                role: record.role,
            },
        )
        .await;

        let _ = send.finish();
        let mut drain = [0u8; 1];
        let _ = recv.read(&mut drain).await;
    }

    async fn handle_authenticated_peer(&self, connection: Connection) {
        let peer_fp = match extract_peer_fingerprint(&connection) {
            Ok(fp) => fp,
            Err(_) => {
                connection.close(
                    VarInt::from_u32(ErrorCode::Unauthorized as u32),
                    b"unauthorized",
                );
                return;
            }
        };

        let peer = match self.store.get_peer_by_fingerprint(&peer_fp) {
            Ok(Some(p)) if !p.revoked => p,
            _ => {
                self.audit
                    .log_auth_failure(&peer_fp, "peer unknown or revoked");
                connection.close(
                    VarInt::from_u32(ErrorCode::Unauthorized as u32),
                    b"unauthorized",
                );
                return;
            }
        };

        if peer.role == "agent" {
            self.handle_agent_connection(connection, peer).await;
        } else if peer.role == "client" {
            self.handle_client_connection(connection, peer).await;
        } else {
            connection.close(
                VarInt::from_u32(ErrorCode::ProtocolViolation as u32),
                b"invalid peer role",
            );
        }
    }

    async fn handle_agent_connection(
        &self,
        connection: Connection,
        peer: crate::store::PeerRecord,
    ) {
        let (mut ctrl_send, mut ctrl_recv) = match connection.accept_bi().await {
            Ok(bi) => bi,
            Err(_) => return,
        };

        let hello = match read_frame(&mut ctrl_recv).await {
            Ok(ControlMessage::AgentHello {
                protocol_minor,
                agent_version,
                hostname,
            }) => (protocol_minor, agent_version, hostname),
            _ => {
                connection.close(
                    VarInt::from_u32(ErrorCode::ProtocolViolation as u32),
                    b"expected AgentHello",
                );
                return;
            }
        };

        info!(agent = %peer.name, version = %hello.1, hostname = %hello.2, "agent registered");

        let ack = ControlMessage::HelloAck {
            agent_name: peer.name.clone(),
        };
        if write_frame(&mut ctrl_send, &ack).await.is_err() {
            return;
        }

        {
            let mut lock = self.agents.write().await;
            if let Some(old) = lock.remove(&peer.name) {
                info!(agent = %peer.name, "superseding older agent connection");
                old.connection.close(
                    VarInt::from_u32(ErrorCode::Superseded as u32),
                    b"superseded by newer connection",
                );
            }
            lock.insert(
                peer.name.clone(),
                AgentSession {
                    connection: connection.clone(),
                    fingerprint: peer.fingerprint.clone(),
                    _ctrl_send: ctrl_send,
                },
            );
        }

        let agents = Arc::clone(&self.agents);
        let agent_name = peer.name.clone();
        tokio::spawn(async move {
            let _ = read_frame(&mut ctrl_recv).await;
            let mut lock = agents.write().await;
            if let Some(current) = lock.get(&agent_name) {
                if current.connection.stable_id() == connection.stable_id() {
                    lock.remove(&agent_name);
                }
            }
        });
    }

    async fn handle_client_connection(
        &self,
        connection: Connection,
        peer: crate::store::PeerRecord,
    ) {
        info!(client = %peer.name, "client connected");
        loop {
            let (send, recv) = match connection.accept_bi().await {
                Ok(bi) => bi,
                Err(_) => break,
            };

            let server = Arc::clone(&Arc::new(self.clone_handles()));
            let client_name = peer.name.clone();
            tokio::spawn(async move {
                server.handle_client_stream(send, recv, client_name).await;
            });
        }
    }

    fn clone_handles(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            store: Arc::clone(&self.store),
            audit: Arc::clone(&self.audit),
            agents: Arc::clone(&self.agents),
            normal_limiter: RateLimiter::new(20, 10),
            enroll_limiter: RateLimiter::new(5, 1),
            shutdown_rx: self.shutdown_rx.clone(),
        }
    }

    async fn handle_client_stream(
        &self,
        mut client_send: SendStream,
        mut client_recv: quinn::RecvStream,
        client_name: String,
    ) {
        let msg = match read_frame(&mut client_recv).await {
            Ok(m) => m,
            Err(_) => return,
        };

        match msg {
            ControlMessage::ListAgents { .. } => {
                let grants = self
                    .store
                    .list_grants(Some(&client_name))
                    .unwrap_or_default();
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
                let _ = write_frame(&mut client_send, &resp).await;
            }
            ControlMessage::ConnectRequest { agent, target } => {
                self.process_connect_request(client_send, client_recv, client_name, agent, target)
                    .await;
            }
            _ => {
                let _ = write_frame(
                    &mut client_send,
                    &ControlMessage::Error {
                        code: ErrorCode::ProtocolViolation,
                        message: "unexpected client frame".into(),
                    },
                )
                .await;
            }
        }
    }

    async fn process_connect_request(
        &self,
        mut client_send: SendStream,
        client_recv: quinn::RecvStream,
        client_name: String,
        agent_name: String,
        target: Option<HostPort>,
    ) {
        let allowed = self
            .store
            .has_grant(&client_name, &agent_name)
            .unwrap_or(false);
        if !allowed {
            self.audit
                .log_auth_failure(&client_name, "grant missing for target agent");
            let resp = ControlMessage::ConnectResponse {
                session_id: String::new(),
                status: ResultStatus::Err(ErrorCode::Unauthorized),
            };
            let _ = write_frame(&mut client_send, &resp).await;
            return;
        }

        let agent_conn = {
            let lock = self.agents.read().await;
            lock.get(&agent_name).map(|s| s.connection.clone())
        };

        let Some(agent_conn) = agent_conn else {
            let resp = ControlMessage::ConnectResponse {
                session_id: String::new(),
                status: ResultStatus::Err(ErrorCode::AgentOffline),
            };
            let _ = write_frame(&mut client_send, &resp).await;
            return;
        };

        let (mut agent_send, mut agent_recv) = match agent_conn.open_bi().await {
            Ok(bi) => bi,
            Err(_) => {
                let resp = ControlMessage::ConnectResponse {
                    session_id: String::new(),
                    status: ResultStatus::Err(ErrorCode::AgentOffline),
                };
                let _ = write_frame(&mut client_send, &resp).await;
                return;
            }
        };

        let session_id = hex_encode(&rand::random::<[u8; 16]>());
        let (host, port) = match &target {
            Some(hp) => (hp.host.clone(), hp.port),
            None => (String::new(), 0),
        };

        let open_msg = ControlMessage::OpenTarget {
            session_id: session_id.clone(),
            client_name: client_name.clone(),
            host: host.clone(),
            port,
        };

        if write_frame(&mut agent_send, &open_msg).await.is_err() {
            let resp = ControlMessage::ConnectResponse {
                session_id: session_id.clone(),
                status: ResultStatus::Err(ErrorCode::AgentOffline),
            };
            let _ = write_frame(&mut client_send, &resp).await;
            return;
        }

        let open_result = match read_frame(&mut agent_recv).await {
            Ok(ControlMessage::OpenResult { status, .. }) => status,
            _ => ResultStatus::Err(ErrorCode::Internal),
        };

        let client_resp = ControlMessage::ConnectResponse {
            session_id: session_id.clone(),
            status: open_result.clone(),
        };

        if write_frame(&mut client_send, &client_resp).await.is_err() {
            return;
        }

        if open_result == ResultStatus::Ok {
            let target_str = if host.is_empty() {
                "default".to_string()
            } else {
                format!("{host}:{port}")
            };
            self.audit
                .log_session_open(&client_name, &agent_name, &target_str, &session_id);
            let start = Instant::now();

            let splice_res =
                splice_quic_streams(client_send, client_recv, agent_send, agent_recv).await;
            let duration = start.elapsed().as_millis();
            let (up, down) = splice_res.unwrap_or((0, 0));

            self.audit.log_session_close(
                &client_name,
                &agent_name,
                &target_str,
                &session_id,
                up,
                down,
                duration,
                "clean exit",
            );
        }
    }

    async fn run_revocation_watcher(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let peers = match self.store.list_peers() {
                Ok(p) => p,
                Err(_) => continue,
            };
            let revoked_fps: Vec<String> = peers
                .into_iter()
                .filter(|p| p.revoked)
                .map(|p| p.fingerprint)
                .collect();

            let mut lock = self.agents.write().await;
            lock.retain(|name, session| {
                if revoked_fps.contains(&session.fingerprint) {
                    info!(agent = %name, "terminating connection of revoked agent");
                    session.connection.close(
                        VarInt::from_u32(ErrorCode::Revoked as u32),
                        b"identity revoked",
                    );
                    false
                } else {
                    true
                }
            });
        }
    }
}
