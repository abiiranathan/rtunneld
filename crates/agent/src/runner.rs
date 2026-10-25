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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{info, warn};

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
    pub async fn run(self) {
        let mut backoff = Backoff::default();
        let target_addr: SocketAddr =
            format!("{}:{}", self.config.relay_host, self.config.relay_port)
                .parse()
                .expect("valid relay address");

        let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let endpoint = create_client_endpoint(bind_addr).expect("client endpoint created");

        let verifier = Arc::new(PinnedServerVerifier::new(&self.config.relay_fingerprint));
        let client_config = make_client_config(
            &self.identity.certificate_der,
            &self.identity.private_key_pem,
            verifier,
            vec![ALPN_TUNNEL.to_vec()],
        )
        .expect("client config created");

        loop {
            info!(relay = %target_addr, "dialing relay");
            let connect_start = Instant::now();
            let connect_fut =
                endpoint.connect_with(client_config.clone(), target_addr, &self.config.relay_host);

            let connecting = match connect_fut {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "connection initialization failed");
                    tokio::time::sleep(backoff.next_delay()).await;
                    continue;
                }
            };

            let connection = match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "relay TLS/QUIC handshake failed");
                    tokio::time::sleep(backoff.next_delay()).await;
                    continue;
                }
            };

            info!("connected to relay; initializing control session");
            let session_res = self.handle_relay_connection(&connection).await;

            if connect_start.elapsed().as_secs() >= 60 {
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

        // Keep ctrl_send alive inside ctrl_monitor so the stream is not closed prematurely
        let ctrl_monitor = async {
            let _keep_alive = ctrl_send;
            let _ = read_frame(&mut ctrl_recv).await;
            Err::<(), String>("control stream closed by relay".into())
        };

        let stream_acceptor = async {
            while let Ok((send, recv)) = connection.accept_bi().await {
                let permit = match self.session_limiter.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("maximum concurrent sessions exceeded; dropping incoming stream");
                        continue;
                    }
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

async fn handle_target_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    allowed_targets: &[String],
) {
    let msg = match read_frame(&mut recv).await {
        Ok(m) => m,
        Err(_) => return,
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
        let _ = write_frame(&mut send, &resp).await;
        return;
    }

    let hp = match HostPort::parse(&target_str) {
        Ok(hp) => hp,
        Err(_) => {
            let resp = ControlMessage::OpenResult {
                session_id,
                status: ResultStatus::Err(ErrorCode::TargetNotAllowed),
            };
            let _ = write_frame(&mut send, &resp).await;
            return;
        }
    };

    let dial_res = tokio::time::timeout(
        limits::TARGET_DIAL_TIMEOUT,
        TcpStream::connect(format!("{}:{}", hp.host, hp.port)),
    )
    .await;

    let tcp = match dial_res {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            stream
        }
        _ => {
            warn!(target = %target_str, "target destination unreachable");
            let resp = ControlMessage::OpenResult {
                session_id,
                status: ResultStatus::Err(ErrorCode::TargetUnreachable),
            };
            let _ = write_frame(&mut send, &resp).await;
            return;
        }
    };

    let resp = ControlMessage::OpenResult {
        session_id,
        status: ResultStatus::Ok,
    };
    if write_frame(&mut send, &resp).await.is_err() {
        return;
    }

    let _ = splice_quic_to_tcp(send, recv, tcp).await;
}

fn gethostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| "localhost".into())
}
