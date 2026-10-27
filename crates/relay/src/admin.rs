#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
// Mutex guards are held for the whole DB/session operation by design.
#![allow(clippy::significant_drop_tightening)]

//! Read-mostly web console for the relay operator.
//!
//! The console is intentionally limited to inspection and removal operations.
//! It cannot create peers, issue enrollment tokens, or add grants; those flows
//! stay on the host or in the CLI so the relay operator keeps a single, audited
//! enrollment path.

use crate::audit::AuditLogger;
use crate::server::{LiveAgent, RelayServer};
use crate::store::{PeerRecord, SqliteStore, TokenRecord};

use axum::extract::{ConnectInfo, Path as AxumPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use chrono::Utc;
use rand::RngCore;
use rtunnel_identity::constant_time_eq;
use rtunnel_proto::format_device_id;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{error, info};

/// Environment variable that overrides the admin token file.
pub const ADMIN_TOKEN_ENV: &str = "RTUNNEL_ADMIN_TOKEN";

/// Name of the cookie that holds an authenticated admin session.
const SESSION_COOKIE: &str = "rtunnel_admin";

/// Admin session lifetime.
const SESSION_TTL: Duration = Duration::from_hours(12);

/// Failed logins allowed per source IP inside [`LOGIN_WINDOW`].
const MAX_LOGIN_FAILURES: u32 = 5;

/// Window used to rate-limit failed logins.
const LOGIN_WINDOW: Duration = Duration::from_mins(5);

/// How much of the tail of the audit log is read per request.
const AUDIT_TAIL_BYTES: u64 = 512 * 1024;

/// File in the relay state directory that stores the admin token.
const ADMIN_TOKEN_FILE: &str = "admin.token";

/// Configuration for the relay admin web console.
#[derive(Clone)]
pub struct AdminConfig {
    /// Address the console binds to.
    pub listen: SocketAddr,
    /// Token required to create an admin session.
    pub token: String,
    /// Relay state directory, used to read the audit log.
    pub state_dir: PathBuf,
}

/// Runtime state shared by all admin handlers.
#[derive(Clone)]
struct AppState {
    relay: Arc<RelayServer>,
    store: Arc<SqliteStore>,
    audit: Arc<AuditLogger>,
    state_dir: PathBuf,
    token: Arc<String>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    attempts: Arc<Mutex<HashMap<IpAddr, LoginAttempt>>>,
}

/// An authenticated browser session.
#[derive(Clone)]
struct Session {
    csrf: String,
    expires: Instant,
}

/// Failed login counter for one source IP.
struct LoginAttempt {
    failures: u32,
    started: Instant,
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

#[derive(Deserialize)]
struct ActionForm {
    csrf: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditEntry {
    timestamp: String,
    event: String,
    #[serde(default)]
    client: Option<String>,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    bytes_up: Option<u64>,
    #[serde(default)]
    bytes_down: Option<u64>,
    #[serde(default)]
    duration_ms: Option<u128>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default)]
    action: Option<String>,
}

struct WebError {
    status: StatusCode,
    message: &'static str,
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        (self.status, format!("{}\n", self.message)).into_response()
    }
}

type WebResult = Result<Html<String>, WebError>;

/// Loads the admin token from the state directory, creating it when missing.
///
/// The token file is restricted to the relay process user. An explicit
/// [`ADMIN_TOKEN_ENV`] value takes precedence over the file.
///
/// # Errors
///
/// Returns an I/O error when the token file cannot be read or created, or when
/// it exists but is empty and cannot be replaced.
pub fn load_or_create_admin_token(state_dir: &Path) -> std::io::Result<String> {
    if let Ok(token) = std::env::var(ADMIN_TOKEN_ENV) {
        let token = token.trim();
        if !token.is_empty() {
            return Ok(token.to_owned());
        }
    }

    let path = state_dir.join(ADMIN_TOKEN_FILE);
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let token = contents.trim();
            if !token.is_empty() {
                return Ok(token.to_owned());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let token = random_hex(32);
    write_private_file(&path, &token)?;
    Ok(token)
}

/// Runs the relay admin web console until the relay shuts down.
///
/// # Errors
///
/// Returns an I/O error when the listen address cannot be bound or the HTTP
/// server fails.
pub async fn run_admin_server(
    config: AdminConfig,
    relay: Arc<RelayServer>,
    store: Arc<SqliteStore>,
    audit: Arc<AuditLogger>,
    shutdown_rx: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let state = Arc::new(AppState {
        relay,
        store,
        audit,
        state_dir: config.state_dir,
        token: Arc::new(config.token),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        attempts: Arc::new(Mutex::new(HashMap::new())),
    });

    let app = router(Arc::clone(&state));
    let listener = TcpListener::bind(config.listen).await?;
    info!(addr = %config.listen, "relay admin console listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
    .await
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

fn router(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .route("/", get(dashboard))
        .route("/peers", get(peers_page))
        .route("/grants", get(grants_page))
        .route("/tokens", get(tokens_page))
        .route("/audit", get(audit_page))
        .route("/peers/{name}/revoke", post(revoke_peer))
        .route("/grants/{client}/{agent}/remove", post(remove_grant))
        .route("/tokens/{hash}/revoke", post(revoke_token))
        .route("/logout", post(logout))
        .route_layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ));

    Router::new()
        .route("/login", get(login_page).post(login))
        .merge(protected)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; \
             base-uri 'none'; frame-ancestors 'none'",
        ),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    if current_session(&state, request.headers()).is_some() {
        next.run(request).await
    } else {
        Redirect::to("/login").into_response()
    }
}

async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if current_session(&state, &headers).is_some() {
        Redirect::to("/").into_response()
    } else {
        Html(render_login(None)).into_response()
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = remote.ip();
    if !login_allowed(&state, ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Html(render_login(Some(
                "Too many failed attempts. Wait a few minutes and try again.",
            ))),
        )
            .into_response();
    }

    if !constant_time_eq(form.token.trim().as_bytes(), state.token.as_bytes()) {
        record_login_failure(&state, ip);
        return (
            StatusCode::UNAUTHORIZED,
            Html(render_login(Some("Invalid admin token."))),
        )
            .into_response();
    }

    clear_login_failures(&state, ip);
    let (session_id, _csrf) = create_session(&state);
    let cookie = format!(
        "{SESSION_COOKIE}={session_id}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        SESSION_TTL.as_secs()
    );
    let mut response = Redirect::to("/").into_response();
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    let Some((session_id, csrf)) = current_session(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if !constant_time_eq(csrf.as_bytes(), form.csrf.as_bytes()) {
        return forbidden();
    }
    state
        .sessions
        .lock()
        .expect("session lock acquired")
        .remove(&session_id);

    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("rtunnel_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
    );
    response
}

async fn dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> WebResult {
    let csrf = csrf_for(&state, &headers)?;
    let peers = state.store.list_peers().map_err(|error| db_error(&error))?;
    let grants = state
        .store
        .list_grants(None)
        .map_err(|error| db_error(&error))?;
    let tokens = state
        .store
        .list_tokens()
        .map_err(|error| db_error(&error))?;
    let agents = state.relay.live_agents().await;
    let pairing_hosts = state.relay.live_pairing_hosts().await;
    let audit = tail_audit(&state.state_dir, 8);

    let content = render_dashboard(&peers, &agents, &pairing_hosts, &grants, &tokens, &audit);
    Ok(Html(shell("Overview", "overview", &content, &csrf)))
}

async fn peers_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> WebResult {
    let csrf = csrf_for(&state, &headers)?;
    let peers = state.store.list_peers().map_err(|error| db_error(&error))?;
    let online: HashSet<String> = state
        .relay
        .live_agents()
        .await
        .into_iter()
        .map(|agent| agent.name)
        .collect();

    let content = render_peers(&peers, &online, &csrf);
    Ok(Html(shell("Peers", "peers", &content, &csrf)))
}

async fn grants_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> WebResult {
    let csrf = csrf_for(&state, &headers)?;
    let grants = state
        .store
        .list_grants(None)
        .map_err(|error| db_error(&error))?;
    let online: HashSet<String> = state
        .relay
        .live_agents()
        .await
        .into_iter()
        .map(|agent| agent.name)
        .collect();

    let content = render_grants(&grants, &online, &csrf);
    Ok(Html(shell("Grants", "grants", &content, &csrf)))
}

async fn tokens_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> WebResult {
    let csrf = csrf_for(&state, &headers)?;
    let tokens = state
        .store
        .list_tokens()
        .map_err(|error| db_error(&error))?;
    let content = render_tokens(&tokens, &csrf);
    Ok(Html(shell("Tokens", "tokens", &content, &csrf)))
}

async fn audit_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> WebResult {
    let csrf = csrf_for(&state, &headers)?;
    let audit = tail_audit(&state.state_dir, 200);
    let content = render_audit_page(&audit);
    Ok(Html(shell("Audit log", "audit", &content, &csrf)))
}

async fn revoke_peer(
    State(state): State<Arc<AppState>>,
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    if !valid_csrf(&state, &headers, &form.csrf) {
        return forbidden();
    }
    match state.store.revoke_peer(&name) {
        Ok(true) => {
            state.audit.log_revoke(&name);
            Redirect::to("/peers").into_response()
        }
        Ok(false) => plain_error(StatusCode::NOT_FOUND, "Peer not found."),
        Err(error) => db_response(&error),
    }
}

async fn remove_grant(
    State(state): State<Arc<AppState>>,
    AxumPath((client, agent)): AxumPath<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    if !valid_csrf(&state, &headers, &form.csrf) {
        return forbidden();
    }
    match state.store.remove_grant(&client, &agent) {
        Ok(true) => {
            state.audit.log_grant_change("remove", &client, &agent);
            Redirect::to("/grants").into_response()
        }
        Ok(false) => plain_error(StatusCode::NOT_FOUND, "Grant not found."),
        Err(error) => db_response(&error),
    }
}

async fn revoke_token(
    State(state): State<Arc<AppState>>,
    AxumPath(hash): AxumPath<String>,
    headers: HeaderMap,
    Form(form): Form<ActionForm>,
) -> Response {
    if !valid_csrf(&state, &headers, &form.csrf) {
        return forbidden();
    }
    match state.store.revoke_token(&hash) {
        Ok(true) => {
            state.audit.log_token_revoke(&hash);
            Redirect::to("/tokens").into_response()
        }
        Ok(false) => plain_error(StatusCode::NOT_FOUND, "Token not found."),
        Err(error) => db_response(&error),
    }
}

fn csrf_for(state: &AppState, headers: &HeaderMap) -> Result<String, WebError> {
    current_session(state, headers)
        .map(|(_, csrf)| csrf)
        .ok_or(WebError {
            status: StatusCode::UNAUTHORIZED,
            message: "Not authenticated.",
        })
}

fn valid_csrf(state: &AppState, headers: &HeaderMap, submitted: &str) -> bool {
    current_session(state, headers)
        .is_some_and(|(_, csrf)| constant_time_eq(csrf.as_bytes(), submitted.as_bytes()))
}

fn current_session(state: &AppState, headers: &HeaderMap) -> Option<(String, String)> {
    let session_id = cookie_value(headers, SESSION_COOKIE)?.to_owned();
    let now = Instant::now();
    let mut sessions = state.sessions.lock().expect("session lock acquired");
    sessions.retain(|_, session| session.expires > now);
    let session = sessions.get(&session_id)?;
    Some((session_id, session.csrf.clone()))
}

fn create_session(state: &AppState) -> (String, String) {
    let session_id = random_hex(32);
    let csrf = random_hex(32);
    let now = Instant::now();
    let mut sessions = state.sessions.lock().expect("session lock acquired");
    sessions.retain(|_, session| session.expires > now);
    sessions.insert(
        session_id.clone(),
        Session {
            csrf: csrf.clone(),
            expires: now + SESSION_TTL,
        },
    );
    (session_id, csrf)
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

fn login_allowed(state: &AppState, ip: IpAddr) -> bool {
    let now = Instant::now();
    let mut attempts = state.attempts.lock().expect("login attempt lock acquired");
    attempts.retain(|_, attempt| now.duration_since(attempt.started) < LOGIN_WINDOW);
    attempts
        .get(&ip)
        .is_none_or(|attempt| attempt.failures < MAX_LOGIN_FAILURES)
}

fn record_login_failure(state: &AppState, ip: IpAddr) {
    let now = Instant::now();
    let mut attempts = state.attempts.lock().expect("login attempt lock acquired");
    attempts.retain(|_, attempt| now.duration_since(attempt.started) < LOGIN_WINDOW);
    let attempt = attempts.entry(ip).or_insert(LoginAttempt {
        failures: 0,
        started: now,
    });
    attempt.failures = attempt.failures.saturating_add(1);
}

fn clear_login_failures(state: &AppState, ip: IpAddr) {
    state
        .attempts
        .lock()
        .expect("login attempt lock acquired")
        .remove(&ip);
}

fn db_error(error: &rusqlite::Error) -> WebError {
    error!(%error, "admin database query failed");
    WebError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        message: "Database error.",
    }
}

fn db_response(error: &rusqlite::Error) -> Response {
    db_error(error).into_response()
}

fn forbidden() -> Response {
    plain_error(StatusCode::FORBIDDEN, "Invalid request token.")
}

fn plain_error(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buffer);
    rtunnel_identity::hex_encode(&buffer)
}

fn write_private_file(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(())
}

fn tail_audit(state_dir: &Path, limit: usize) -> Vec<AuditEntry> {
    let Ok(mut file) = fs::File::open(state_dir.join("audit.log")) else {
        return Vec::new();
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return Vec::new();
    };
    let start = length.saturating_sub(AUDIT_TAIL_BYTES);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut contents = String::new();
    if file.read_to_string(&mut contents).is_err() {
        return Vec::new();
    }
    let mut lines: Vec<&str> = contents.lines().collect();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    lines
        .iter()
        .rev()
        .filter_map(|line| serde_json::from_str(line).ok())
        .take(limit)
        .collect()
}

fn render_login(error: Option<&str>) -> String {
    let alert = error.map_or_else(String::new, |message| {
        format!(r#"<div class="alert">{}</div>"#, esc(message))
    });
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · rtunnel relay</title>
<style>{STYLE}</style>
</head>
<body>
<main class="login-wrap">
  <section class="card login-card">
    <div class="brand"><span class="logo">rt</span><span>rtunnel relay<small>admin console</small></span></div>
    <h1>Operator sign-in</h1>
    <p>Enter the admin token from the relay state directory. The default file is <code>admin.token</code>.</p>
    {alert}
    <form method="post" action="/login">
      <div class="field">
        <label for="token">Admin token</label>
        <input id="token" name="token" type="password" autocomplete="current-password" autofocus required>
      </div>
      <button class="btn btn-primary" type="submit" style="width:100%;padding:11px">Sign in</button>
    </form>
    <p class="footer-note">Sessions expire after 12 hours. Failed attempts are rate-limited.</p>
  </section>
</main>
</body>
</html>"#
    )
}

fn shell(title: &str, active: &str, content: &str, csrf: &str) -> String {
    let nav = nav_html(active);
    let title = esc(title);
    let csrf = esc(csrf);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · rtunnel relay</title>
<style>{STYLE}</style>
</head>
<body>
<div class="shell">
  <header class="topbar">
    <div class="brand"><span class="logo">rt</span><span>rtunnel relay<small>admin console</small></span></div>
    <nav>
      {nav}
      <form class="logout" method="post" action="/logout">
        <input type="hidden" name="csrf" value="{csrf}">
        <button class="btn btn-ghost" type="submit">Sign out</button>
      </form>
    </nav>
  </header>
  {content}
</div>
</body>
</html>"#
    )
}

fn nav_html(active: &str) -> String {
    let items = [
        ("overview", "/", "Overview"),
        ("peers", "/peers", "Peers"),
        ("grants", "/grants", "Grants"),
        ("tokens", "/tokens", "Tokens"),
        ("audit", "/audit", "Audit"),
    ];
    let mut nav = String::new();
    for (id, href, label) in items {
        let class = if id == active {
            "nav-link active"
        } else {
            "nav-link"
        };
        let _ = write!(nav, r#"<a class="{class}" href="{href}">{label}</a>"#);
    }
    nav
}

fn page_head(title: &str, subtitle: &str) -> String {
    format!(
        r#"<div class="page-head"><div><h1>{}</h1><p class="subtitle">{}</p></div></div>"#,
        esc(title),
        esc(subtitle)
    )
}

fn stat_card(label: &str, value: &str, hint: &str) -> String {
    format!(
        r#"<div class="card stat"><div class="stat-label">{}</div><div class="stat-value">{}</div><div class="stat-hint">{}</div></div>"#,
        esc(label),
        esc(value),
        esc(hint)
    )
}

fn count_label(count: usize, singular: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {singular}s")
    }
}

fn render_dashboard(
    peers: &[PeerRecord],
    agents: &[LiveAgent],
    pairing_hosts: &[String],
    grants: &[(String, String)],
    tokens: &[TokenRecord],
    audit: &[AuditEntry],
) -> String {
    let clients = peers.iter().filter(|peer| peer.role == "client").count();
    let agents_total = peers.iter().filter(|peer| peer.role == "agent").count();
    let revoked = peers.iter().filter(|peer| peer.revoked).count();
    let head = page_head(
        "Relay overview",
        "Live state, access rules, and the most recent security events.",
    );
    let stats = format!(
        r#"<div class="grid stats">
{}
{}
{}
{}</div>"#,
        stat_card(
            "Peers",
            &peers.len().to_string(),
            &format!(
                "{} · {} · {revoked} revoked",
                count_label(clients, "client"),
                count_label(agents_total, "agent")
            )
        ),
        stat_card(
            "Online agents",
            &agents.len().to_string(),
            &format!(
                "{} ready for pairing",
                count_label(pairing_hosts.len(), "host")
            )
        ),
        stat_card(
            "Grants",
            &grants.len().to_string(),
            "client → agent access rules"
        ),
        stat_card(
            "Active tokens",
            &tokens.len().to_string(),
            "single-use enrollment links"
        ),
    );

    let mut left = render_live_agents(agents);
    if !pairing_hosts.is_empty() {
        left.push_str(&render_pairing_hosts(pairing_hosts));
    }
    let right = render_recent_events(audit);
    format!(
        r#"{head}{stats}<div class="grid two-col"><div class="stack">{left}</div>{right}</div>"#
    )
}

fn render_live_agents(agents: &[LiveAgent]) -> String {
    if agents.is_empty() {
        return r#"<div class="card"><div class="panel-title"><h2>Connected agents</h2><span class="muted">0 online</span></div><div class="empty">No agents are connected right now.</div></div>"#.to_owned();
    }

    let mut rows = String::new();
    for agent in agents {
        let name = esc(&format_device_id(&agent.name));
        let fingerprint = esc(&agent.fingerprint);
        let short = esc(&fingerprint_short(&agent.fingerprint));
        let address = esc(&agent.remote_addr.to_string());
        let connected = esc(&format_duration(agent.connected_secs));
        let targets = targets_html(&agent.targets);
        let _ = write!(
            rows,
            r#"<tr>
<td><div class="agent-name">{name}</div><div class="fp mono" title="{fingerprint}">{short}</div></td>
<td>{targets}</td>
<td class="mono">{address}</td>
<td>{connected}</td>
</tr>"#
        );
    }

    format!(
        r#"<div class="card"><div class="panel-title"><h2>Connected agents</h2><span class="muted">{} online</span></div>
<table><thead><tr><th>Agent</th><th>Targets</th><th>Address</th><th>Connected</th></tr></thead><tbody>{rows}</tbody></table></div>"#,
        agents.len()
    )
}

fn render_pairing_hosts(hosts: &[String]) -> String {
    let mut items = String::new();
    for host in hosts {
        let _ = write!(
            items,
            r#"<span class="badge online">{}</span>"#,
            esc(&format_device_id(host))
        );
    }
    format!(
        r#"<div class="card"><div class="panel-title"><h2>Awaiting pairing prompts</h2><span class="muted">{} ready</span></div><div class="targets">{items}</div></div>"#,
        hosts.len()
    )
}

fn render_recent_events(audit: &[AuditEntry]) -> String {
    if audit.is_empty() {
        return r#"<div class="card"><div class="panel-title"><h2>Recent events</h2></div><div class="empty">The audit log is empty.</div></div>"#.to_owned();
    }
    let mut items = String::new();
    for entry in audit {
        let _ = write!(
            items,
            r#"<li><span class="event">{}</span><div class="event-body"><div>{}</div><div class="event-time">{}</div></div></li>"#,
            esc(&entry.event),
            audit_detail(entry),
            esc(&format_audit_time(&entry.timestamp))
        );
    }
    format!(
        r#"<div class="card"><div class="panel-title"><h2>Recent events</h2><a href="/audit">View all</a></div><ul class="events">{items}</ul></div>"#
    )
}

fn render_peers(peers: &[PeerRecord], online: &HashSet<String>, csrf: &str) -> String {
    let head = page_head(
        "Peers",
        "Revoking a peer blocks future handshakes and closes live sessions within 5 seconds.",
    );
    if peers.is_empty() {
        return format!(
            r#"{head}<div class="card"><div class="empty">No peers have enrolled yet.</div></div>"#
        );
    }

    let mut rows = String::new();
    for peer in peers {
        let name = esc(&format_device_id(&peer.name));
        let fingerprint = esc(&peer.fingerprint);
        let short = esc(&fingerprint_short(&peer.fingerprint));
        let status = if peer.revoked {
            r#"<span class="badge revoked">revoked</span>"#.to_owned()
        } else if online.contains(&peer.name) {
            r#"<span class="badge online">online</span>"#.to_owned()
        } else {
            r#"<span class="badge offline">offline</span>"#.to_owned()
        };
        let action = if peer.revoked {
            r#"<span class="muted">disenrolled</span>"#.to_owned()
        } else {
            format!(
                r#"<form method="post" action="/peers/{}/revoke"><input type="hidden" name="csrf" value="{}"><button class="btn btn-danger" type="submit">Revoke</button></form>"#,
                esc(&peer.name),
                esc(csrf)
            )
        };
        let _ = write!(
            rows,
            r#"<tr><td><div class="agent-name">{name}</div><div class="fp mono" title="{fingerprint}">{short}</div></td><td>{}</td><td>{status}</td><td>{action}</td></tr>"#,
            role_badge(&peer.role)
        );
    }

    format!(
        r#"{head}<div class="card"><table><thead><tr><th>Peer</th><th>Role</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div>"#
    )
}

fn render_grants(grants: &[(String, String)], online: &HashSet<String>, csrf: &str) -> String {
    let head = page_head(
        "Access grants",
        "Grants are created by host pairing or from the relay CLI. Remove a grant to stop future connections.",
    );
    if grants.is_empty() {
        return format!(
            r#"{head}<div class="card"><div class="empty">No client-to-agent grants are configured.</div></div>"#
        );
    }

    let mut rows = String::new();
    for (client, agent) in grants {
        let agent_status = if online.contains(agent) {
            r#"<span class="badge online">online</span>"#.to_owned()
        } else {
            r#"<span class="badge offline">offline</span>"#.to_owned()
        };
        let action = format!("/grants/{}/{}/remove", esc(client), esc(agent));
        let _ = write!(
            rows,
            r#"<tr><td class="mono">{}</td><td class="arrow">→</td><td><div class="agent-name">{}</div>{agent_status}</td><td><form method="post" action="{action}"><input type="hidden" name="csrf" value="{}"><button class="btn btn-danger" type="submit">Remove</button></form></td></tr>"#,
            esc(&format_device_id(client)),
            esc(&format_device_id(agent)),
            esc(csrf)
        );
    }

    format!(
        r#"{head}<div class="card"><table><thead><tr><th>Client</th><th></th><th>Agent</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div>"#
    )
}

fn render_tokens(tokens: &[TokenRecord], csrf: &str) -> String {
    let head = page_head(
        "Enrollment tokens",
        "Active single-use tokens. Creating tokens stays in the relay CLI; the console can only revoke them.",
    );
    if tokens.is_empty() {
        return format!(
            r#"{head}<div class="card"><div class="empty">No active enrollment tokens.</div></div>"#
        );
    }

    let mut rows = String::new();
    for token in tokens {
        let short = esc(&fingerprint_short(&token.token_hash));
        let full = esc(&token.token_hash);
        let _ = write!(
            rows,
            r#"<tr><td class="mono" title="{full}">{short}</td><td>{}</td><td>{}</td><td>{}</td><td><form method="post" action="/tokens/{}/revoke"><input type="hidden" name="csrf" value="{}"><button class="btn btn-danger" type="submit">Revoke</button></form></td></tr>"#,
            esc(&format_device_id(&token.name)),
            role_badge(&token.role),
            esc(&format_epoch(token.expires_at)),
            esc(&token.token_hash),
            esc(csrf)
        );
    }

    format!(
        r#"{head}<div class="card"><table><thead><tr><th>Token</th><th>Name</th><th>Role</th><th>Expires</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div>"#
    )
}

fn render_audit_page(audit: &[AuditEntry]) -> String {
    let head = page_head(
        "Audit log",
        "Newest security events first. The log is append-only on the relay.",
    );
    if audit.is_empty() {
        return format!(
            r#"{head}<div class="card"><div class="empty">No audit events have been recorded yet.</div></div>"#
        );
    }

    let mut rows = String::new();
    for entry in audit {
        let fingerprint = entry
            .fingerprint
            .as_deref()
            .map_or_else(String::new, |value| {
                format!(
                    r#"<div class="fp mono" title="{}">{}</div>"#,
                    esc(value),
                    esc(&fingerprint_short(value))
                )
            });
        let _ = write!(
            rows,
            r#"<tr><td class="mono nowrap">{}</td><td><span class="event">{}</span></td><td>{}</td><td>{fingerprint}</td></tr>"#,
            esc(&format_audit_time(&entry.timestamp)),
            esc(&entry.event),
            audit_detail(entry)
        );
    }

    format!(
        r#"{head}<div class="card"><table><thead><tr><th>Time</th><th>Event</th><th>Details</th><th>Fingerprint</th></tr></thead><tbody>{rows}</tbody></table></div>"#
    )
}

fn role_badge(role: &str) -> String {
    let class = match role {
        "agent" => "agent",
        "client" => "client",
        _ => "node",
    };
    format!(r#"<span class="badge {class}">{}</span>"#, esc(role))
}

fn targets_html(targets: &[String]) -> String {
    if targets.is_empty() {
        return r#"<span class="muted">none advertised</span>"#.to_owned();
    }
    let mut html = String::new();
    for target in targets {
        if !html.is_empty() {
            html.push(' ');
        }
        let _ = write!(html, r"<code>{}</code>", esc(target));
    }
    html
}

fn audit_detail(entry: &AuditEntry) -> String {
    let mut parts = Vec::new();
    if let Some(client) = &entry.client {
        parts.push(format!("client <b>{}</b>", esc(client)));
    }
    if let Some(agent) = &entry.agent {
        parts.push(format!("agent <b>{}</b>", esc(agent)));
    }
    if let Some(target) = &entry.target {
        parts.push(format!("target <b>{}</b>", esc(&fingerprint_short(target))));
    }
    if let Some(session_id) = &entry.session_id {
        parts.push(format!(
            r#"session <span class="mono">{}</span>"#,
            esc(&fingerprint_short(session_id))
        ));
    }
    if let Some(action) = &entry.action {
        parts.push(format!("action <b>{}</b>", esc(action)));
    }
    if let Some(reason) = &entry.reason {
        parts.push(format!("reason <b>{}</b>", esc(reason)));
    }
    if let (Some(up), Some(down)) = (entry.bytes_up, entry.bytes_down) {
        parts.push(format!(
            "{} up / {} down",
            human_bytes(up),
            human_bytes(down)
        ));
    }
    if let Some(duration_ms) = entry.duration_ms {
        parts.push(format!("{duration_ms} ms"));
    }
    if parts.is_empty() {
        r#"<span class="muted">—</span>"#.to_owned()
    } else {
        parts.join(" · ")
    }
}

fn format_epoch(seconds: i64) -> String {
    chrono::DateTime::from_timestamp(seconds, 0).map_or_else(
        || seconds.to_string(),
        |datetime| datetime.format("%Y-%m-%d %H:%M UTC").to_string(),
    )
}

fn format_audit_time(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value).map_or_else(
        |_| value.to_owned(),
        |datetime| {
            datetime
                .with_timezone(&Utc)
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string()
        },
    )
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {}s", seconds / 60, seconds % 60)
    } else if seconds < 86_400 {
        format!("{}h {}m", seconds / 3600, (seconds % 3600) / 60)
    } else {
        format!("{}d {}h", seconds / 86_400, (seconds % 86_400) / 3600)
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes;
    let mut unit = 0;
    while value >= 1024 && unit < UNITS.len() - 1 {
        value /= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value} {}", UNITS[unit])
    }
}

fn fingerprint_short(value: &str) -> String {
    if value.len() <= 20 {
        value.to_owned()
    } else {
        format!("{}…{}", &value[..10], &value[value.len() - 8..])
    }
}

fn esc(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

const STYLE: &str = r#"
:root {
  color-scheme: dark;
  --bg: #070b16;
  --bg-2: #0d1426;
  --panel: rgba(18, 27, 48, .78);
  --line: rgba(148, 163, 184, .16);
  --text: #e8eefc;
  --muted: #94a3b8;
  --accent: #34d399;
  --accent-2: #60a5fa;
  --danger: #fb7185;
  --radius: 16px;
}
* { box-sizing: border-box; }
html { min-height: 100%; }
body {
  margin: 0;
  min-height: 100vh;
  color: var(--text);
  background:
    radial-gradient(900px 500px at 12% -8%, rgba(52, 211, 153, .16), transparent 60%),
    radial-gradient(1000px 600px at 100% 0%, rgba(96, 165, 250, .16), transparent 55%),
    linear-gradient(180deg, var(--bg-2), var(--bg) 55%);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
  line-height: 1.5;
}
a { color: var(--accent-2); text-decoration: none; }
a:hover { text-decoration: underline; }
.shell { width: min(1240px, calc(100% - 40px)); margin: 0 auto; padding: 28px 0 64px; }
.topbar { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 14px 0 22px; }
.brand { display: flex; align-items: center; gap: 12px; font-weight: 700; letter-spacing: -.02em; font-size: 1.15rem; }
.logo { width: 36px; height: 36px; border-radius: 11px; display: grid; place-items: center; background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: #06111f; font-weight: 800; }
.brand small { display: block; color: var(--muted); font-weight: 500; font-size: .76rem; letter-spacing: .08em; text-transform: uppercase; }
nav { display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.nav-link { color: var(--muted); padding: 8px 12px; border-radius: 10px; font-size: .92rem; }
.nav-link:hover { color: var(--text); background: rgba(148, 163, 184, .1); text-decoration: none; }
.nav-link.active { color: var(--text); background: rgba(148, 163, 184, .14); box-shadow: inset 0 0 0 1px var(--line); }
.logout { display: inline; margin-left: 8px; }
.page-head { display: flex; align-items: end; justify-content: space-between; gap: 16px; margin: 18px 0 22px; flex-wrap: wrap; }
h1 { font-size: clamp(1.6rem, 3vw, 2.2rem); margin: 0; letter-spacing: -.03em; }
.subtitle { color: var(--muted); margin: 6px 0 0; }
.grid { display: grid; gap: 16px; }
.stats { grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); margin-bottom: 22px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: var(--radius); padding: 18px; backdrop-filter: blur(10px); box-shadow: 0 10px 40px rgba(0, 0, 0, .18); min-width: 0; overflow-x: auto; }
.stat-label { color: var(--muted); font-size: .78rem; text-transform: uppercase; letter-spacing: .1em; }
.stat-value { font-size: 1.9rem; font-weight: 750; letter-spacing: -.04em; margin-top: 4px; }
.stat-hint { color: var(--muted); font-size: .82rem; }
.panel-title { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 14px; }
.panel-title h2 { font-size: 1.02rem; margin: 0; letter-spacing: -.01em; }
.muted { color: var(--muted); }
.mono, code { font-family: ui-monospace, "JetBrains Mono", SFMono-Regular, Menlo, monospace; }
code { background: rgba(148, 163, 184, .1); padding: 2px 6px; border-radius: 6px; font-size: .85em; }
.nowrap { white-space: nowrap; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .09em; padding: 10px 12px; border-bottom: 1px solid var(--line); }
td { padding: 12px; border-bottom: 1px solid rgba(148, 163, 184, .08); vertical-align: middle; }
tr:last-child td { border-bottom: 0; }
tbody tr:hover { background: rgba(148, 163, 184, .04); }
.agent-name { font-weight: 650; }
.arrow { color: var(--muted); }
.badge { display: inline-flex; align-items: center; gap: 6px; padding: 3px 9px; border-radius: 999px; font-size: .74rem; font-weight: 650; border: 1px solid transparent; white-space: nowrap; }
.badge.online { color: #6ee7b7; background: rgba(52, 211, 153, .12); border-color: rgba(52, 211, 153, .25); }
.badge.offline { color: var(--muted); background: rgba(148, 163, 184, .1); border-color: var(--line); }
.badge.revoked { color: var(--danger); background: rgba(251, 113, 133, .12); border-color: rgba(251, 113, 133, .25); }
.badge.agent { color: #93c5fd; background: rgba(96, 165, 250, .12); border-color: rgba(96, 165, 250, .25); }
.badge.client { color: #c4b5fd; background: rgba(167, 139, 250, .12); border-color: rgba(167, 139, 250, .25); }
.badge.node { color: #fcd34d; background: rgba(251, 191, 36, .12); border-color: rgba(251, 191, 36, .25); }
.btn { appearance: none; cursor: pointer; border: 1px solid var(--line); background: rgba(148, 163, 184, .1); color: var(--text); border-radius: 9px; padding: 7px 11px; font-size: .82rem; font-weight: 600; font-family: inherit; }
.btn:hover { background: rgba(148, 163, 184, .18); }
.btn-danger { color: var(--danger); border-color: rgba(251, 113, 133, .3); background: rgba(251, 113, 133, .1); }
.btn-danger:hover { background: rgba(251, 113, 133, .2); }
.btn-ghost { background: transparent; color: var(--muted); }
.btn-primary { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: #06111f; border: 0; }
.empty { padding: 28px 12px; text-align: center; color: var(--muted); }
.stack { display: grid; gap: 16px; }
.two-col { grid-template-columns: minmax(0, 1.35fr) minmax(0, 1fr); align-items: start; }
.targets { display: flex; flex-wrap: wrap; gap: 6px; }
.events { list-style: none; margin: 0; padding: 0; display: grid; gap: 10px; }
.events li { display: flex; gap: 10px; align-items: flex-start; padding: 10px; border: 1px solid var(--line); border-radius: 10px; background: rgba(7, 11, 22, .3); min-width: 0; }
.event { display: inline-flex; align-items: center; padding: 2px 8px; border-radius: 999px; background: rgba(96, 165, 250, .12); color: #93c5fd; font-size: .7rem; font-weight: 700; white-space: nowrap; }
.event-body { min-width: 0; overflow-wrap: anywhere; }
.event-time { color: var(--muted); font-size: .74rem; margin-top: 2px; }
.login-wrap { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
.login-card { width: min(420px, 100%); padding: 30px; }
.login-card h1 { font-size: 1.55rem; margin-top: 22px; }
.login-card p { color: var(--muted); }
.field { display: grid; gap: 7px; margin: 18px 0; }
.field label { font-size: .82rem; color: var(--muted); }
input[type=password] { width: 100%; padding: 12px 13px; border-radius: 10px; border: 1px solid var(--line); background: rgba(7, 11, 22, .7); color: var(--text); font: inherit; }
input[type=password]:focus { outline: 2px solid rgba(96, 165, 250, .35); border-color: rgba(96, 165, 250, .5); }
.alert { border: 1px solid rgba(251, 113, 133, .3); background: rgba(251, 113, 133, .1); color: #fecdd3; padding: 10px 12px; border-radius: 10px; font-size: .88rem; margin: 14px 0; }
.footer-note { color: var(--muted); font-size: .78rem; margin-top: 18px; text-align: center; }
@media (max-width: 900px) {
  .two-col { grid-template-columns: 1fr; }
  .shell { width: min(100% - 24px, 1240px); }
  .topbar { align-items: flex-start; flex-direction: column; }
}
"#;

#[cfg(test)]
mod tests {
    use super::{count_label, esc, fingerprint_short, format_duration, human_bytes, tail_audit};
    use std::fs;

    #[test]
    fn escapes_html_metacharacters() {
        assert_eq!(
            esc(r#"<script>"x"&'y'"#),
            "&lt;script&gt;&quot;x&quot;&amp;&#39;y&#39;"
        );
    }

    #[test]
    fn shortens_fingerprints() {
        assert_eq!(fingerprint_short("short"), "short");
        let long = "0123456789abcdef0123456789abcdef";
        assert_eq!(fingerprint_short(long), "0123456789…89abcdef");
    }

    #[test]
    fn pluralizes_counts() {
        assert_eq!(count_label(1, "client"), "1 client");
        assert_eq!(count_label(2, "host"), "2 hosts");
        assert_eq!(count_label(0, "agent"), "0 agents");
    }

    #[test]
    fn formats_durations_and_bytes() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(125), "2m 5s");
        assert_eq!(format_duration(7_265), "2h 1m");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2_048), "2 KiB");
    }

    #[test]
    fn reads_newest_audit_entries() {
        let dir = tempfile::tempdir().expect("temporary state directory");
        let log = dir.path().join("audit.log");
        fs::write(
            &log,
            concat!(
                "{\"timestamp\":\"2026-10-27T09:00:00Z\",\"event\":\"enroll\"}\n",
                "{\"timestamp\":\"2026-10-27T09:01:00Z\",\"event\":\"revoke\",\"target\":\"clinic-a\"}\n",
                "not json\n"
            ),
        )
        .expect("write audit log");

        let entries = tail_audit(dir.path(), 10);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].event, "revoke");
        assert_eq!(entries[1].event, "enroll");
    }
}
