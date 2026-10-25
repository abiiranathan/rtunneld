#![forbid(unsafe_code)]

use rtunnel_agent::{AgentConfig, AgentRunner};
use rtunnel_identity::{
    EnrollmentUri, KeyMaterial, PinnedServerVerifier, generate_identity, save_identity,
};
use rtunnel_proto::{ALPN_ENROLL, ALPN_TUNNEL, ControlMessage, ErrorCode, HostPort, ResultStatus};
use rtunnel_relay::{AuditLogger, RelayServer, SqliteStore};
use rtunnel_transport::{create_client_endpoint, make_client_config, read_frame, write_frame};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;

struct TestHarness {
    relay_addr: SocketAddr,
    relay_identity: KeyMaterial,
    store: Arc<SqliteStore>,
    _audit: Arc<AuditLogger>,
    _shutdown_tx: watch::Sender<bool>,
}

impl TestHarness {
    // Not `async`: nothing is awaited here. The relay's run loop is spawned
    // onto the ambient tokio runtime, which every `#[tokio::test]` provides.
    fn start() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temp_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SqliteStore::open(temp_dir.path().join("test.db")).unwrap());
        let audit = Arc::new(AuditLogger::open(temp_dir.path()).unwrap());

        let relay_identity = generate_identity("relay").unwrap();
        save_identity(temp_dir.path(), &relay_identity).unwrap();

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = Arc::new(
            RelayServer::new(
                "127.0.0.1:0".parse().unwrap(),
                &relay_identity,
                Arc::clone(&store),
                Arc::clone(&audit),
                shutdown_rx,
            )
            .unwrap(),
        );

        let relay_addr = server.local_addr();
        tokio::spawn(async move {
            server.run().await;
        });

        Self {
            relay_addr,
            relay_identity,
            store,
            _audit: audit,
            _shutdown_tx: shutdown_tx,
        }
    }

    fn make_token(&self, name: &str, role: &str) -> (String, EnrollmentUri) {
        let token = format!("token-{}", rand::random::<u64>());
        let token_hash = rtunnel_identity::hex_encode(&Sha256::digest(token.as_bytes()));
        // A Unix timestamp plus ten minutes cannot exceed i64::MAX, so the
        // sign reinterpretation is lossless.
        let expires_at = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600)
            .cast_signed();
        self.store
            .store_token(&token_hash, name, role, expires_at)
            .unwrap();
        let uri = EnrollmentUri {
            host: self.relay_addr.ip().to_string(),
            port: self.relay_addr.port(),
            relay_fingerprint: self.relay_identity.fingerprint.clone(),
            token: token.clone(),
        };
        (token, uri)
    }

    async fn enroll_peer(&self, name: &str, role: &str) -> KeyMaterial {
        let (_token, uri) = self.make_token(name, role);
        let id = generate_identity(name).unwrap();

        let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
        let verifier = Arc::new(PinnedServerVerifier::new(&uri.relay_fingerprint));
        let client_config = make_client_config(
            &id.certificate_der,
            &id.private_key_pem,
            verifier,
            vec![ALPN_ENROLL.to_vec()],
        )
        .unwrap();

        let conn = endpoint
            .connect_with(client_config, self.relay_addr, &uri.host)
            .unwrap()
            .await
            .unwrap();

        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        write_frame(&mut send, &ControlMessage::Enroll { token: uri.token })
            .await
            .unwrap();

        match read_frame(&mut recv).await.unwrap() {
            ControlMessage::EnrollAck { name: ack_name, .. } => {
                assert_eq!(ack_name, name);
            }
            other => panic!("expected EnrollAck, got {other:?}"),
        }

        id
    }
}

async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    (addr, handle)
}

#[tokio::test]
async fn test_full_tunnel_data_transfer_and_hash_integrity() {
    let harness = TestHarness::start();
    let (echo_addr, _echo_handle) = start_echo_server().await;

    let agent_id = harness.enroll_peer("agent-1", "agent").await;
    let client_id = harness.enroll_peer("client-1", "client").await;
    harness.store.add_grant("client-1", "agent-1").unwrap();

    let agent_cfg = AgentConfig {
        relay_host: harness.relay_addr.ip().to_string(),
        relay_port: harness.relay_addr.port(),
        relay_fingerprint: harness.relay_identity.fingerprint.clone(),
        agent_name: "agent-1".into(),
        allowed_targets: vec![echo_addr.to_string()],
        max_sessions: 64,
    };
    tokio::spawn(AgentRunner::new(agent_cfg, agent_id).run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect client
    let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
    let verifier = Arc::new(PinnedServerVerifier::new(
        &harness.relay_identity.fingerprint,
    ));
    let client_config = make_client_config(
        &client_id.certificate_der,
        &client_id.private_key_pem,
        verifier,
        vec![ALPN_TUNNEL.to_vec()],
    )
    .unwrap();

    let conn = endpoint
        .connect_with(
            client_config,
            harness.relay_addr,
            &harness.relay_addr.ip().to_string(),
        )
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let req = ControlMessage::ConnectRequest {
        agent: "agent-1".into(),
        target: Some(HostPort::new(echo_addr.ip().to_string(), echo_addr.port()).unwrap()),
    };
    write_frame(&mut send, &req).await.unwrap();

    let resp = read_frame(&mut recv).await.unwrap();
    assert_eq!(
        resp,
        ControlMessage::ConnectResponse {
            session_id: match &resp {
                ControlMessage::ConnectResponse { session_id, .. } => session_id.clone(),
                _ => String::new(),
            },
            status: ResultStatus::Ok,
        }
    );

    // Stream 1 MiB of patterned data through the tunnel and verify SHA-256 integrity.
    // The pattern repeats 0..=250, which avoids a lossy usize -> u8 cast.
    let data_size = 1024 * 1024;
    let payload: Vec<u8> = (0..=250_u8).cycle().take(data_size).collect();
    let expected_hash = Sha256::digest(&payload);

    let sender = async {
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
    };

    let receiver = async {
        let mut received = Vec::with_capacity(data_size);
        let mut buf = vec![0u8; 16 * 1024];
        while let Some(n) = recv.read(&mut buf).await.unwrap() {
            received.extend_from_slice(&buf[..n]);
        }
        received
    };

    let ((), received_data) = tokio::join!(sender, receiver);
    let actual_hash = Sha256::digest(&received_data);
    assert_eq!(actual_hash, expected_hash);
}

#[tokio::test]
async fn test_unauthorized_client_rejected() {
    let harness = TestHarness::start();
    let agent_id = harness.enroll_peer("agent-2", "agent").await;
    let client_id = harness.enroll_peer("client-unauthorized", "client").await;
    // Note: No grant added between client-unauthorized and agent-2

    let agent_cfg = AgentConfig {
        relay_host: harness.relay_addr.ip().to_string(),
        relay_port: harness.relay_addr.port(),
        relay_fingerprint: harness.relay_identity.fingerprint.clone(),
        agent_name: "agent-2".into(),
        allowed_targets: vec!["127.0.0.1:22".into()],
        max_sessions: 64,
    };
    tokio::spawn(AgentRunner::new(agent_cfg, agent_id).run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
    let verifier = Arc::new(PinnedServerVerifier::new(
        &harness.relay_identity.fingerprint,
    ));
    let client_config = make_client_config(
        &client_id.certificate_der,
        &client_id.private_key_pem,
        verifier,
        vec![ALPN_TUNNEL.to_vec()],
    )
    .unwrap();

    let conn = endpoint
        .connect_with(
            client_config,
            harness.relay_addr,
            &harness.relay_addr.ip().to_string(),
        )
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(
        &mut send,
        &ControlMessage::ConnectRequest {
            agent: "agent-2".into(),
            target: None,
        },
    )
    .await
    .unwrap();

    let resp = read_frame(&mut recv).await.unwrap();
    match resp {
        ControlMessage::ConnectResponse { status, .. } => {
            assert_eq!(status, ResultStatus::Err(ErrorCode::Unauthorized));
        }
        other => panic!("expected ConnectResponse::Err(Unauthorized), got {other:?}"),
    }
}

#[tokio::test]
async fn test_disallowed_target_rejected_by_agent() {
    let harness = TestHarness::start();
    let agent_id = harness.enroll_peer("agent-3", "agent").await;
    let client_id = harness.enroll_peer("client-3", "client").await;
    harness.store.add_grant("client-3", "agent-3").unwrap();

    let agent_cfg = AgentConfig {
        relay_host: harness.relay_addr.ip().to_string(),
        relay_port: harness.relay_addr.port(),
        relay_fingerprint: harness.relay_identity.fingerprint.clone(),
        agent_name: "agent-3".into(),
        allowed_targets: vec!["127.0.0.1:22".into()],
        max_sessions: 64,
    };
    tokio::spawn(AgentRunner::new(agent_cfg, agent_id).run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
    let verifier = Arc::new(PinnedServerVerifier::new(
        &harness.relay_identity.fingerprint,
    ));
    let client_config = make_client_config(
        &client_id.certificate_der,
        &client_id.private_key_pem,
        verifier,
        vec![ALPN_TUNNEL.to_vec()],
    )
    .unwrap();

    let conn = endpoint
        .connect_with(
            client_config,
            harness.relay_addr,
            &harness.relay_addr.ip().to_string(),
        )
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    // Request destination 127.0.0.1:9999 which is NOT in agent-3 allowed targets
    write_frame(
        &mut send,
        &ControlMessage::ConnectRequest {
            agent: "agent-3".into(),
            target: Some(HostPort::new("127.0.0.1", 9999).unwrap()),
        },
    )
    .await
    .unwrap();

    let resp = read_frame(&mut recv).await.unwrap();
    match resp {
        ControlMessage::ConnectResponse { status, .. } => {
            assert_eq!(status, ResultStatus::Err(ErrorCode::TargetNotAllowed));
        }
        other => panic!("expected TargetNotAllowed, got {other:?}"),
    }
}

#[tokio::test]
async fn test_revocation_terminates_agent_live_session() {
    let harness = TestHarness::start();
    let agent_id = harness.enroll_peer("agent-rev", "agent").await;
    let client_id = harness.enroll_peer("client-rev", "client").await;
    harness.store.add_grant("client-rev", "agent-rev").unwrap();

    let agent_cfg = AgentConfig {
        relay_host: harness.relay_addr.ip().to_string(),
        relay_port: harness.relay_addr.port(),
        relay_fingerprint: harness.relay_identity.fingerprint.clone(),
        agent_name: "agent-rev".into(),
        allowed_targets: vec!["127.0.0.1:22".into()],
        max_sessions: 64,
    };
    tokio::spawn(AgentRunner::new(agent_cfg, agent_id).run());
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A granted client observes the relay's live agent registry via ListAgents.
    let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
    let verifier = Arc::new(PinnedServerVerifier::new(
        &harness.relay_identity.fingerprint,
    ));
    let client_config = make_client_config(
        &client_id.certificate_der,
        &client_id.private_key_pem,
        verifier,
        vec![ALPN_TUNNEL.to_vec()],
    )
    .unwrap();

    let conn = endpoint
        .connect_with(
            client_config,
            harness.relay_addr,
            &harness.relay_addr.ip().to_string(),
        )
        .unwrap()
        .await
        .unwrap();

    // Each query uses a fresh bidirectional stream on the same client connection.
    // A closure (rather than a helper fn) avoids naming quinn's connection type here.
    let conn_ref = &conn;
    let agent_is_online = || async move {
        let (mut send, mut recv) = conn_ref.open_bi().await.unwrap();
        write_frame(
            &mut send,
            &ControlMessage::ListAgents {
                client_name: "client-rev".into(),
            },
        )
        .await
        .unwrap();
        let ControlMessage::ListAgentsResponse { agents } = read_frame(&mut recv).await.unwrap()
        else {
            panic!("expected ListAgentsResponse");
        };
        agents
            .iter()
            .find(|a| a.name == "agent-rev")
            .expect("granted agent must be listed")
            .online
    };

    // Precondition: the agent is registered and live before revocation.
    assert!(
        agent_is_online().await,
        "agent should be online before revocation"
    );

    // Revoke the agent in the SQLite store.
    assert!(harness.store.revoke_peer("agent-rev").unwrap());

    // The revocation watcher on the relay polls once per second and terminates live
    // connections. The agent's reconnect attempts are rejected because it is revoked.
    tokio::time::sleep(Duration::from_millis(2500)).await;

    // The relay itself must have dropped the live session, not merely the store flag.
    assert!(
        !agent_is_online().await,
        "relay should have dropped the revoked agent's live connection"
    );
}

#[tokio::test]
async fn test_half_close_preservation() {
    let harness = TestHarness::start();
    let (echo_addr, _echo_handle) = start_echo_server().await;

    let agent_id = harness.enroll_peer("agent-half", "agent").await;
    let client_id = harness.enroll_peer("client-half", "client").await;
    harness
        .store
        .add_grant("client-half", "agent-half")
        .unwrap();

    let agent_cfg = AgentConfig {
        relay_host: harness.relay_addr.ip().to_string(),
        relay_port: harness.relay_addr.port(),
        relay_fingerprint: harness.relay_identity.fingerprint.clone(),
        agent_name: "agent-half".into(),
        allowed_targets: vec![echo_addr.to_string()],
        max_sessions: 64,
    };
    tokio::spawn(AgentRunner::new(agent_cfg, agent_id).run());
    tokio::time::sleep(Duration::from_millis(200)).await;

    let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
    let verifier = Arc::new(PinnedServerVerifier::new(
        &harness.relay_identity.fingerprint,
    ));
    let client_config = make_client_config(
        &client_id.certificate_der,
        &client_id.private_key_pem,
        verifier,
        vec![ALPN_TUNNEL.to_vec()],
    )
    .unwrap();

    let conn = endpoint
        .connect_with(
            client_config,
            harness.relay_addr,
            &harness.relay_addr.ip().to_string(),
        )
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(
        &mut send,
        &ControlMessage::ConnectRequest {
            agent: "agent-half".into(),
            target: Some(HostPort::new(echo_addr.ip().to_string(), echo_addr.port()).unwrap()),
        },
    )
    .await
    .unwrap();

    let resp = read_frame(&mut recv).await.unwrap();
    assert!(matches!(
        resp,
        ControlMessage::ConnectResponse {
            status: ResultStatus::Ok,
            ..
        }
    ));

    // Send payload and close write direction (FIN)
    send.write_all(b"ping half close").await.unwrap();
    send.finish().unwrap();

    // The other direction must continue flowing until all echoed bytes are delivered
    let mut echo_buf = vec![0u8; 15];
    recv.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, b"ping half close");

    // The recv stream should report EOF cleanly
    let mut tail = [0u8; 1];
    let end = recv.read(&mut tail).await.unwrap();
    assert_eq!(end, None);
}
