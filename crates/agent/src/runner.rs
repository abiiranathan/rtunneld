#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use crate::config::AgentConfig;
use quinn::{Connection, RecvStream, SendStream};
use rtunnel_identity::{KeyMaterial, PinnedServerVerifier};
use rtunnel_proto::{
    ALPN_TUNNEL, ControlMessage, ErrorCode, HostPort, PROTOCOL_MINOR, ResultStatus,
};
use rtunnel_transport::{
    Backoff, create_client_endpoint, limits, make_client_config, read_frame, splice_quic_to_tcp,
    write_frame,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// A relay session that lasted at least this long is considered healthy, and the
/// reconnect backoff is reset once it ends.
const HEALTHY_SESSION_THRESHOLD: Duration = Duration::from_secs(60);

/// Agent connector that executes the resilient connection loop to the relay.
pub struct AgentRunner {
    config: AgentConfig,
    identity: KeyMaterial,
    session_limiter: Arc<Semaphore>,
}

impl AgentRunner {
    /// Creates a new agent runner instance.
    #[must_use]
    pub fn new(config: AgentConfig, identity: KeyMaterial) -> Self {
        let max_sessions = config.max_sessions;
        Self {
            config,
            identity,
            session_limiter: Arc::new(Semaphore::new(max_sessions)),
        }
    }

    /// Runs the infinite reconnection loop using exponential backoff and full jitter.
    ///
    /// Relay resolution and connection failures are logged and retried; they never
    /// terminate the loop.
    ///
    /// # Errors
    ///
    /// Returns an error if the local QUIC client endpoint or the TLS client
    /// configuration cannot be created. Once setup succeeds this function does not
    /// return.
    pub async fn run(self) -> Result<(), String> {
        let mut backoff = Backoff::default();

        // Wildcard IPv4 address with an OS-assigned port. Built from typed parts
        // so there is no string parsing that could fail.
        let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
        let endpoint = create_client_endpoint(bind_addr)
            .map_err(|e| format!("cannot create client endpoint: {e}"))?;

        let verifier = Arc::new(PinnedServerVerifier::new(&self.config.relay_fingerprint));
        let client_config = make_client_config(
            &self.identity.certificate_der,
            &self.identity.private_key_pem,
            verifier,
            vec![ALPN_TUNNEL.to_vec()],
        )
        .map_err(|e| format!("cannot create client config: {e}"))?;

        loop {
            let connect_start = Instant::now();

            // Resolve (so hostnames work, not only IP literals) and dial in one
            // fallible unit so every failure shares a single retry path below.
            let attempt = async {
                let target_addr =
                    lookup_host((self.config.relay_host.as_str(), self.config.relay_port))
                        .await
                        .map_err(|e| format!("cannot resolve relay address: {e}"))?
                        // The client endpoint is bound to an IPv4 socket.
                        .find(SocketAddr::is_ipv4)
                        .ok_or_else(|| String::from("relay has no IPv4 address"))?;

                info!(relay = %target_addr, "dialing relay");
                endpoint
                    .connect_with(client_config.clone(), target_addr, &self.config.relay_host)
                    .map_err(|e| format!("connection initialization failed: {e}"))?
                    .await
                    .map_err(|e| format!("relay TLS/QUIC handshake failed: {e}"))
            };

            let connection = match attempt.await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "relay dial failed");
                    tokio::time::sleep(backoff.next_delay()).await;
                    continue;
                }
            };

            info!("connected to relay; initializing control session");
            let session_res = self.handle_relay_connection(&connection).await;

            if connect_start.elapsed() >= HEALTHY_SESSION_THRESHOLD {
                backoff.reset();
            }

            if let Err(e) = session_res {
                warn!(error = %e, "agent connection closed");
            }
            tokio::time::sleep(backoff.next_delay()).await;
        }
    }

    async fn handle_relay_connection(&self, connection: &Connection) -> Result<(), String> {
        let (mut ctrl_send, mut ctrl_recv) = connection
            .open_bi()
            .await
            .map_err(|e| format!("cannot open control stream: {e}"))?;

        let hello = ControlMessage::AgentHello {
            protocol_minor: PROTOCOL_MINOR,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            hostname: gethostname(),
        };
        write_frame(&mut ctrl_send, &hello)
            .await
            .map_err(|e| format!("cannot send AgentHello: {e}"))?;

        match read_frame(&mut ctrl_recv).await {
            Ok(ControlMessage::HelloAck { agent_name }) => {
                info!(agent = %agent_name, "control session acknowledged by relay");
            }
            Ok(ControlMessage::Error { code, message }) => {
                return Err(format!("relay rejected registration: {code} - {message}"));
            }
            _ => return Err("unexpected response to AgentHello".into()),
        }

        // Advertise the allowlist on a separate stream. Old relays do not accept
        // extra streams and simply ignore it, so this stays backward compatible.
        advertise_targets(connection, &self.config.allowed_targets).await;

        // Keep ctrl_send alive inside ctrl_monitor so the stream is not closed prematurely
        let ctrl_monitor = async {
            let _keep_alive = ctrl_send;
            let _ = read_frame(&mut ctrl_recv).await;
            Err::<(), String>("control stream closed by relay".into())
        };

        let stream_acceptor = async {
            while let Ok((send, recv)) = connection.accept_bi().await {
                let Ok(permit) = Arc::clone(&self.session_limiter).try_acquire_owned() else {
                    warn!("maximum concurrent sessions exceeded; dropping incoming stream");
                    continue;
                };
                let allowed_targets = self.config.allowed_targets.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_target_stream(send, recv, &allowed_targets).await;
                });
            }
            Ok::<(), String>(())
        };

        tokio::select! {
            res = ctrl_monitor => res,
            res = stream_acceptor => res,
        }
    }
}

/// Sends the agent's allowed targets to the relay so clients can discover them.
///
/// The advertisement is best effort: a relay that predates target discovery
/// never accepts the stream, and the agent continues serving sessions either way.
async fn advertise_targets(connection: &Connection, targets: &[String]) {
    let advertisement = async {
        let (mut send, _recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
        write_frame(
            &mut send,
            &ControlMessage::AgentTargets {
                targets: targets.to_vec(),
            },
        )
        .await
        .map_err(|e| e.to_string())?;
        send.finish().map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    };

    match tokio::time::timeout(Duration::from_secs(5), advertisement).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => warn!(error = %e, "cannot advertise targets to relay"),
        Err(_) => warn!("timed out while advertising targets to relay"),
    }
}

async fn handle_target_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    allowed_targets: &[String],
) {
    let Ok(msg) = read_frame(&mut recv).await else {
        return;
    };

    let ControlMessage::OpenTarget {
        session_id,
        client_name,
        host,
        port,
    } = msg
    else {
        return;
    };

    let target_str = if host.is_empty() && port == 0 {
        allowed_targets.first().cloned().unwrap_or_default()
    } else {
        format!("{host}:{port}")
    };

    if !allowed_targets.iter().any(|t| t == &target_str) {
        warn!(target = %target_str, client = %client_name, "target disallowed by local agent configuration");
        let resp = ControlMessage::OpenResult {
            session_id,
            status: ResultStatus::Err(ErrorCode::TargetNotAllowed),
        };
        // Best effort: the peer may already have gone away.
        let _ = write_frame(&mut send, &resp).await;
        return;
    }

    let Ok(hp) = HostPort::parse(&target_str) else {
        let resp = ControlMessage::OpenResult {
            session_id,
            status: ResultStatus::Err(ErrorCode::TargetNotAllowed),
        };
        let _ = write_frame(&mut send, &resp).await;
        return;
    };

    let dial_res = tokio::time::timeout(
        limits::TARGET_DIAL_TIMEOUT,
        TcpStream::connect(format!("{}:{}", hp.host, hp.port)),
    )
    .await;

    // Both a timeout (outer Err) and a connect failure (inner Err) are "unreachable".
    let Ok(Ok(tcp)) = dial_res else {
        warn!(target = %target_str, "target destination unreachable");
        let resp = ControlMessage::OpenResult {
            session_id,
            status: ResultStatus::Err(ErrorCode::TargetUnreachable),
        };
        let _ = write_frame(&mut send, &resp).await;
        return;
    };

    // A failure here only costs latency, so log it and carry on.
    if let Err(e) = tcp.set_nodelay(true) {
        warn!(target = %target_str, error = %e, "cannot enable TCP_NODELAY");
    }

    let resp = ControlMessage::OpenResult {
        session_id,
        status: ResultStatus::Ok,
    };
    if write_frame(&mut send, &resp).await.is_err() {
        return;
    }

    // The splice ends when either side closes; its result carries nothing actionable.
    let _ = splice_quic_to_tcp(send, recv, tcp).await;
}

fn gethostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into())
}
