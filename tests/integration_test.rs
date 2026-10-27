#![forbid(unsafe_code)]

use rtunnel_agent::{AgentConfig, AgentRunner};
use rtunnel_identity::{
    EnrollmentUri, KeyMaterial, PinnedServerVerifier, generate_identity, save_identity,
};
use rtunnel_proto::{
    ALPN_ENROLL, ALPN_RENDEZVOUS, ALPN_TUNNEL, ControlMessage, ErrorCode, GrantDuration, HostPort,
    ResultStatus,
};
use rtunnel_relay::{AuditLogger, RelayServer, SqliteStore};
use rtunnel_transport::{create_client_endpoint, make_client_config, read_frame, write_frame};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::watch;

/// Resolves the `rtunnel` binary, building it first if Cargo did not.
///
/// `CARGO_BIN_EXE_rtunnel` is only provided to integration tests in the same
/// package as the bin target, so otherwise we ask Cargo to build it and report
/// the artifact path. The result is cached for the lifetime of the process.
fn rtunnel_binary_path() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();

    BIN.get_or_init(|| {
        // Fast path: same-package integration test.
        if let Some(var) = std::env::var_os("CARGO_BIN_EXE_rtunnel") {
            let p = PathBuf::from(var);
            if p.exists() {
                return p;
            }
        }

        // Reuse the cargo that is running this test; fall back to PATH.
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());

        // Diagnostics go to stderr (inherited), JSON artifacts to stdout.
        // --workspace is required so `--bin` can resolve across member packages.
        let output = Command::new(cargo)
            .args([
                "build",
                "--workspace",
                "--bin",
                "rtunnel",
                "--message-format=json-render-diagnostics",
            ])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .stderr(Stdio::inherit())
            .output()
            .expect("failed to spawn cargo to build rtunnel");
        assert!(output.status.success(), "cargo build of rtunnel failed");

        // Take the last matching artifact message; it carries the exact path,
        // independent of profile, target triple, or CARGO_TARGET_DIR.
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|msg| msg["reason"] == "compiler-artifact")
            .filter(|msg| msg["target"]["name"] == "rtunnel")
            .filter(|msg| {
                msg["target"]["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|v| v == "bin"))
            })
            .filter_map(|msg| msg["executable"].as_str().map(PathBuf::from))
            .next_back()
            .expect("cargo did not report an rtunnel executable")
    })
    .clone()
}

struct TestHarness {
    relay_addr: SocketAddr,
    relay_identity: KeyMaterial,
    store: Arc<SqliteStore>,
    _audit: Arc<AuditLogger>,
    _shutdown_tx: watch::Sender<bool>,
}

impl TestHarness {
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

    /// Opens an authenticated connection offering exactly `alpns`.
    ///
    /// The endpoint is returned so the caller keeps the QUIC driver alive for
    /// the lifetime of the connection.
    async fn connect_as(
        &self,
        id: &KeyMaterial,
        alpns: Vec<Vec<u8>>,
    ) -> (quinn::Endpoint, quinn::Connection) {
        let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
        let verifier = Arc::new(PinnedServerVerifier::new(&self.relay_identity.fingerprint));
        let client_config =
            make_client_config(&id.certificate_der, &id.private_key_pem, verifier, alpns).unwrap();

        let conn = endpoint
            .connect_with(
                client_config,
                self.relay_addr,
                &self.relay_addr.ip().to_string(),
            )
            .unwrap()
            .await
            .unwrap();
        (endpoint, conn)
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

/// Registers a host identity on a rendezvous connection and publishes its
/// pairing code, mirroring what `rtunnel host` does at startup.
async fn start_pairing_host(
    harness: &TestHarness,
    host_id: &KeyMaterial,
    host_device_id: &str,
    code_hash: &str,
) -> (quinn::Endpoint, quinn::Connection) {
    let (endpoint, connection) = harness
        .connect_as(host_id, vec![ALPN_RENDEZVOUS.to_vec()])
        .await;

    let (mut reg_send, mut reg_recv) = connection.open_bi().await.unwrap();
    write_frame(
        &mut reg_send,
        &ControlMessage::RegisterDevice {
            label: "host-pc".into(),
            existing_device_id: None,
        },
    )
    .await
    .unwrap();
    match read_frame(&mut reg_recv).await.unwrap() {
        ControlMessage::RegisterDeviceAck { device_id } => {
            assert_eq!(device_id, host_device_id);
        }
        other => panic!("expected RegisterDeviceAck, got {other:?}"),
    }

    let (mut code_send, _code_recv) = connection.open_bi().await.unwrap();
    write_frame(
        &mut code_send,
        &ControlMessage::SetPairingCode {
            code_hash: code_hash.to_owned(),
            ttl_secs: 300,
        },
    )
    .await
    .unwrap();

    (endpoint, connection)
}

/// Runs the client pairing exchange and answers the host prompt with
/// `Allow Once`. Returns the client connection ready for a tunnel request.
async fn pair_client_with_allow_once(
    harness: &TestHarness,
    client_id: &KeyMaterial,
    host_connection: &quinn::Connection,
    host_device_id: &str,
    code: &str,
) -> (quinn::Endpoint, quinn::Connection) {
    let (endpoint, connection) = harness
        .connect_as(client_id, vec![ALPN_RENDEZVOUS.to_vec()])
        .await;

    let (mut pair_send, mut pair_recv) = connection.open_bi().await.unwrap();
    write_frame(
        &mut pair_send,
        &ControlMessage::PairRequest {
            target_device_id: host_device_id.to_owned(),
            code: code.to_owned(),
            client_label: "test-client".into(),
            ssh_pubkey: None,
        },
    )
    .await
    .unwrap();

    let pending_sas = match read_frame(&mut pair_recv).await.unwrap() {
        ControlMessage::PairPending {
            sas,
            host_device_id: id,
            ..
        } => {
            assert_eq!(id, host_device_id);
            sas
        }
        other => panic!("expected PairPending, got {other:?}"),
    };

    let (mut prompt_send, mut prompt_recv) =
        tokio::time::timeout(Duration::from_secs(5), host_connection.accept_bi())
            .await
            .expect("timed out waiting for the host pairing prompt")
            .unwrap();
    let (prompt_sas, pair_session_id) = match read_frame(&mut prompt_recv).await.unwrap() {
        ControlMessage::IncomingPairPrompt {
            sas,
            pair_session_id,
            ..
        } => (sas, pair_session_id),
        other => panic!("expected IncomingPairPrompt, got {other:?}"),
    };
    assert_eq!(
        prompt_sas, pending_sas,
        "client and host must display the same SAS"
    );

    write_frame(
        &mut prompt_send,
        &ControlMessage::PairPromptResponse {
            pair_session_id,
            approved: true,
            duration: GrantDuration::Once,
            install_ssh_key: false,
        },
    )
    .await
    .unwrap();

    match read_frame(&mut pair_recv).await.unwrap() {
        ControlMessage::PairResult {
            success: true,
            host_device_id: id,
            ..
        } => assert_eq!(id, host_device_id),
        other => panic!("expected successful PairResult, got {other:?}"),
    }

    (endpoint, connection)
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
async fn test_agent_advertises_targets_for_client_discovery() {
    let harness = TestHarness::start();
    let agent_id = harness.enroll_peer("agent-disc", "agent").await;
    let client_id = harness.enroll_peer("client-disc", "client").await;
    harness
        .store
        .add_grant("client-disc", "agent-disc")
        .unwrap();

    let advertised = vec!["winbox:22".to_string(), "nas:445".to_string()];
    let agent_cfg = AgentConfig {
        relay_host: harness.relay_addr.ip().to_string(),
        relay_port: harness.relay_addr.port(),
        relay_fingerprint: harness.relay_identity.fingerprint.clone(),
        agent_name: "agent-disc".into(),
        allowed_targets: advertised.clone(),
        max_sessions: 64,
    };
    tokio::spawn(AgentRunner::new(agent_cfg, agent_id).run());
    tokio::time::sleep(Duration::from_millis(300)).await;

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
        &ControlMessage::ListAgentsDetailed {
            client_name: "client-disc".into(),
        },
    )
    .await
    .unwrap();

    let ControlMessage::AgentsDetailedResponse { agents } = read_frame(&mut recv).await.unwrap()
    else {
        panic!("expected AgentsDetailedResponse");
    };
    let agent = agents
        .iter()
        .find(|a| a.name == "agent-disc")
        .expect("granted agent must be listed");
    assert!(agent.online);
    assert_eq!(agent.targets, advertised);
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

    assert!(
        agent_is_online().await,
        "agent should be online before revocation"
    );

    assert!(harness.store.revoke_peer("agent-rev").unwrap());

    tokio::time::sleep(Duration::from_millis(2500)).await;

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

    send.write_all(b"ping half close").await.unwrap();
    send.finish().unwrap();

    let mut echo_buf = vec![0u8; 15];
    recv.read_exact(&mut echo_buf).await.unwrap();
    assert_eq!(&echo_buf, b"ping half close");

    let mut tail = [0u8; 1];
    let end = recv.read(&mut tail).await.unwrap();
    assert_eq!(end, None);
}

#[tokio::test]
async fn test_anydesk_zero_config_setup_and_pairing() {
    let harness = TestHarness::start();

    let host_id = generate_identity("node-host").unwrap();
    let client_id = generate_identity("node-client").unwrap();

    let host_device_id = harness
        .store
        .get_or_allocate_device_id(&host_id.fingerprint, "host-pc")
        .unwrap();

    let client_device_id = harness
        .store
        .get_or_allocate_device_id(&client_id.fingerprint, "client-pc")
        .unwrap();

    assert_eq!(host_device_id.len(), 9);
    assert_eq!(client_device_id.len(), 9);

    let code = "492184";
    let code_hash = rtunnel_identity::hex_encode(&Sha256::digest(code.as_bytes()));
    harness
        .store
        .set_pairing_code(&host_device_id, &code_hash, 300)
        .unwrap();

    let valid = harness
        .store
        .verify_pairing_code(&host_device_id, &code_hash)
        .unwrap();
    assert!(valid, "Valid pairing code must verify");

    let sas =
        rtunnel_proto::compute_sas(&host_id.fingerprint, &client_id.fingerprint, "session-test");
    assert_eq!(sas.len(), 4);

    harness
        .store
        .add_grant(&client_device_id, &host_device_id)
        .unwrap();
    assert!(
        harness
            .store
            .has_grant(&client_device_id, &host_device_id)
            .unwrap()
    );
}

/// Verifies that the client binary exposes a working `install` subcommand as
/// called by `scripts/install.ps1` and `scripts/install.sh`.
#[test]
fn test_client_cli_install_subcommand() {
    let temp_dir = tempfile::tempdir().unwrap();
    let bin_dir = temp_dir.path().join("bin");

    let binary_path = rtunnel_binary_path();

    let status = std::process::Command::new(&binary_path)
        .args([
            "install",
            "--bin-dir",
            bin_dir.to_str().unwrap(),
            "--no-path",
            "--no-ssh-config",
            "--no-ssh-hosts",
        ])
        .status()
        .expect("failed to execute rtunnel install");

    assert!(
        status.success(),
        "rtunnel install must succeed with exit code 0"
    );

    #[cfg(windows)]
    let installed_binary = bin_dir.join("rtunnel.exe");
    #[cfg(not(windows))]
    let installed_binary = bin_dir.join("rtunnel");

    assert!(
        installed_binary.exists(),
        "installed binary must exist at {}",
        installed_binary.display()
    );

    let help_status = std::process::Command::new(&installed_binary)
        .arg("--help")
        .output()
        .expect("installed binary must execute");
    assert!(help_status.status.success());
    let help_text = String::from_utf8_lossy(&help_status.stdout);
    assert!(help_text.contains("rtunnel"));
}

/// Verifies dynamic device ID allocation over QUIC with `ALPN_RENDEZVOUS`.
#[tokio::test]
async fn test_rendezvous_register_device_over_quic() {
    let harness = TestHarness::start();
    let peer_id = generate_identity("test-node").unwrap();

    let endpoint = create_client_endpoint("0.0.0.0:0".parse().unwrap()).unwrap();
    let verifier = Arc::new(PinnedServerVerifier::new(
        &harness.relay_identity.fingerprint,
    ));
    let client_config = make_client_config(
        &peer_id.certificate_der,
        &peer_id.private_key_pem,
        verifier,
        vec![ALPN_RENDEZVOUS.to_vec()],
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
        &ControlMessage::RegisterDevice {
            label: "my-workstation".into(),
            existing_device_id: None,
        },
    )
    .await
    .unwrap();

    let resp = read_frame(&mut recv).await.unwrap();
    match resp {
        ControlMessage::RegisterDeviceAck { device_id } => {
            assert_eq!(device_id.len(), 9, "Allocated Device ID must be 9 digits");
            assert!(
                device_id.chars().all(|c| c.is_ascii_digit()),
                "Device ID must consist only of ASCII digits"
            );
        }
        other => panic!("expected RegisterDeviceAck, got {other:?}"),
    }
}

/// Verifies that the relay prefers rendezvous when a peer offers both ALPNs.
#[tokio::test]
async fn test_relay_negotiates_rendezvous_when_peer_offers_both_alpns() {
    let harness = TestHarness::start();
    let peer_id = generate_identity("dual-alpn-peer").unwrap();

    // Offer tunnel first, then rendezvous. The relay must apply its own
    // preference (rendezvous) rather than the client's ordering. If tunnel is
    // selected, this unregistered identity is rejected before RegisterDevice.
    let (_endpoint, conn) = harness
        .connect_as(
            &peer_id,
            vec![ALPN_TUNNEL.to_vec(), ALPN_RENDEZVOUS.to_vec()],
        )
        .await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    write_frame(
        &mut send,
        &ControlMessage::RegisterDevice {
            label: "dual-alpn".into(),
            existing_device_id: None,
        },
    )
    .await
    .unwrap();

    match read_frame(&mut recv).await.unwrap() {
        ControlMessage::RegisterDeviceAck { device_id } => {
            assert_eq!(device_id.len(), 9);
        }
        other => panic!("expected rendezvous registration, got {other:?}"),
    }
}

/// Verifies that `rtunnel setup` registers a Device ID over rendezvous and
/// persists the relay fingerprint and assigned ID.
#[tokio::test]
async fn test_cli_setup_registers_device_id_over_rendezvous() {
    let harness = TestHarness::start();
    let temp = tempfile::tempdir().unwrap();
    let state_dir = temp.path().join("client-state");
    let home = temp.path().join("home");
    std::fs::create_dir_all(&home).unwrap();

    let output = tokio::process::Command::new(rtunnel_binary_path())
        .arg("setup")
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--relay-host")
        .arg(harness.relay_addr.ip().to_string())
        .arg("--relay-port")
        .arg(harness.relay_addr.port().to_string())
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .output()
        .await
        .expect("failed to execute rtunnel setup");

    assert!(
        output.status.success(),
        "rtunnel setup failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let config = rtunnel_client::ClientConfig::load(&state_dir).unwrap();
    assert_eq!(config.relay_host, harness.relay_addr.ip().to_string());
    assert_eq!(config.relay_port, harness.relay_addr.port());
    assert_eq!(config.relay_fingerprint, harness.relay_identity.fingerprint);
    assert_eq!(config.client_name.len(), 9);
    assert!(config.client_name.chars().all(|c| c.is_ascii_digit()));

    let peer = harness
        .store
        .get_peer_by_name(&config.client_name)
        .unwrap()
        .expect("setup must register the peer in the relay store");
    assert_eq!(peer.role, "node");
}

/// End-to-end regression: pairing prompts travel over the host's rendezvous
/// connection, "Allow Once" authorizes the following tunnel connect, and the
/// SAS shown to both operators is identical.
#[tokio::test]
async fn test_rendezvous_pairing_allow_once_then_tunnel_connect() {
    let harness = TestHarness::start();
    let (echo_addr, _echo_handle) = start_echo_server().await;

    let host_id = generate_identity("pairing-host").unwrap();
    let host_device_id = harness
        .store
        .get_or_allocate_device_id(&host_id.fingerprint, "host-pc")
        .unwrap();
    let client_id = generate_identity("pairing-client").unwrap();
    let _client_device_id = harness
        .store
        .get_or_allocate_device_id(&client_id.fingerprint, "client-pc")
        .unwrap();

    let code = "834291";
    let code_hash = rtunnel_identity::hex_encode(&Sha256::digest(code.as_bytes()));
    harness
        .store
        .set_pairing_code(&host_device_id, &code_hash, 300)
        .unwrap();

    // The tunnel connection serves target sessions and advertises the allowlist.
    let agent_cfg = AgentConfig {
        relay_host: harness.relay_addr.ip().to_string(),
        relay_port: harness.relay_addr.port(),
        relay_fingerprint: harness.relay_identity.fingerprint.clone(),
        agent_name: host_device_id.clone(),
        allowed_targets: vec![echo_addr.to_string()],
        max_sessions: 8,
    };
    tokio::spawn(AgentRunner::new(agent_cfg, host_id.clone()).run());

    // The host's rendezvous connection registers the Device ID and publishes
    // the pairing code. Pairing prompts must arrive here, not on the tunnel.
    let (_host_endpoint, host_conn) =
        start_pairing_host(&harness, &host_id, &host_device_id, &code_hash).await;

    // Client requests pairing and receives the SAS before the host decides.
    let (_client_endpoint, client_conn) =
        pair_client_with_allow_once(&harness, &client_id, &host_conn, &host_device_id, code).await;

    // The tunnel may still be connecting; retry until the agent is online.
    let target = HostPort::new(echo_addr.ip().to_string(), echo_addr.port()).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut session = None;
    while tokio::time::Instant::now() < deadline {
        let (mut send, mut recv) = client_conn.open_bi().await.unwrap();
        write_frame(
            &mut send,
            &ControlMessage::ConnectRequest {
                agent: host_device_id.clone(),
                target: Some(target.clone()),
            },
        )
        .await
        .unwrap();

        match read_frame(&mut recv).await.unwrap() {
            ControlMessage::ConnectResponse {
                status: ResultStatus::Ok,
                ..
            } => {
                session = Some((send, recv));
                break;
            }
            ControlMessage::ConnectResponse {
                status: ResultStatus::Err(ErrorCode::AgentOffline),
                ..
            } => tokio::time::sleep(Duration::from_millis(100)).await,
            other => panic!("unexpected connect response: {other:?}"),
        }
    }
    let (mut send, mut recv) = session.expect("host tunnel did not come online in time");

    send.write_all(b"paired").await.unwrap();
    let mut echoed = [0u8; 6];
    recv.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"paired");
}

/// Verifies that 5 incorrect pairing attempts trigger progressive lockout.
#[tokio::test]
async fn test_anydesk_pairing_code_lockout_after_failures() {
    let harness = TestHarness::start();
    let host_id = generate_identity("node-lockout-host").unwrap();
    let host_device_id = harness
        .store
        .get_or_allocate_device_id(&host_id.fingerprint, "host-pc")
        .unwrap();

    let correct_code = "777888";
    let correct_hash = rtunnel_identity::hex_encode(&Sha256::digest(correct_code.as_bytes()));
    harness
        .store
        .set_pairing_code(&host_device_id, &correct_hash, 300)
        .unwrap();

    let wrong_hash = rtunnel_identity::hex_encode(&Sha256::digest(b"wrong-code"));

    for _ in 0..5 {
        let valid = harness
            .store
            .verify_pairing_code(&host_device_id, &wrong_hash)
            .unwrap();
        assert!(!valid, "Wrong pairing code must fail verification");
    }

    let valid_after_lockout = harness
        .store
        .verify_pairing_code(&host_device_id, &correct_hash)
        .unwrap();
    assert!(
        !valid_after_lockout,
        "Pairing code must be locked out after 5 consecutive failures"
    );
}
