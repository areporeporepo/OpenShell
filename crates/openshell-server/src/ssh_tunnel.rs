// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! SSH tunnel handler for the multiplexed gateway.

use axum::{Router, extract::State, http::Method, response::IntoResponse, routing::any};
use http::StatusCode;
use hyper::Request;
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use openshell_core::net::enable_tcp_keepalive;
use openshell_core::proto::{Sandbox, SandboxPhase, SshSession};
use prost::Message;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};
use uuid::Uuid;

use crate::ServerState;
use crate::persistence::{ObjectId, ObjectName, ObjectType, Store};

const HEADER_SANDBOX_ID: &str = "x-sandbox-id";
const HEADER_TOKEN: &str = "x-sandbox-token";
const PREFACE_MAGIC: &str = "NSSH1";

/// Maximum concurrent SSH tunnel connections per session token.
const MAX_CONNECTIONS_PER_TOKEN: u32 = 3;

/// Maximum concurrent SSH tunnel connections per sandbox.
const MAX_CONNECTIONS_PER_SANDBOX: u32 = 20;
const SSH_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SSH_UPSTREAM_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn router(state: Arc<ServerState>) -> Router {
    Router::new()
        .route("/connect/ssh", any(ssh_connect))
        .with_state(state)
}

async fn ssh_connect(
    State(state): State<Arc<ServerState>>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    if req.method() != Method::CONNECT {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let sandbox_id = match header_value(req.headers(), HEADER_SANDBOX_ID) {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };
    let token = match header_value(req.headers(), HEADER_TOKEN) {
        Ok(value) => value,
        Err(status) => return status.into_response(),
    };

    let session = match state.store.get_message::<SshSession>(&token).await {
        Ok(Some(session)) => session,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(err) => {
            warn!(error = %err, "Failed to fetch SSH session");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if session.revoked || session.sandbox_id != sandbox_id {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Check token expiry (0 means no expiry for backward compatibility).
    if session.expires_at_ms > 0 {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        if now_ms > session.expires_at_ms {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let sandbox = match state.store.get_message::<Sandbox>(&sandbox_id).await {
        Ok(Some(sandbox)) => sandbox,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            warn!(error = %err, "Failed to fetch sandbox");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if SandboxPhase::try_from(sandbox.phase).ok() != Some(SandboxPhase::Ready) {
        return StatusCode::PRECONDITION_FAILED.into_response();
    }

    let connect_target = if let Some(status) = sandbox.status.as_ref()
        && !status.agent_pod.is_empty()
    {
        match state.sandbox_client.agent_pod_ip(&status.agent_pod).await {
            Ok(Some(ip)) => ConnectTarget::Ip(SocketAddr::new(ip, state.config.sandbox_ssh_port)),
            Ok(None) => return StatusCode::BAD_GATEWAY.into_response(),
            Err(err) => {
                warn!(error = %err, "Failed to resolve agent pod IP");
                return StatusCode::BAD_GATEWAY.into_response();
            }
        }
    } else if !sandbox.name.is_empty() {
        let service_host = format!(
            "{}.{}.svc.cluster.local",
            sandbox.name, state.config.sandbox_namespace
        );
        ConnectTarget::Host(service_host, state.config.sandbox_ssh_port)
    } else {
        return StatusCode::PRECONDITION_FAILED.into_response();
    };
    // Enforce per-token concurrent connection limit.
    {
        let mut counts = state.ssh_connections_by_token.lock().unwrap();
        let count = counts.entry(token.clone()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_TOKEN {
            warn!(sandbox_id = %sandbox_id, active_connections = *count, limit = MAX_CONNECTIONS_PER_TOKEN, "SSH tunnel: per-token connection limit reached");
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        *count += 1;
    }

    // Enforce per-sandbox concurrent connection limit.
    {
        let mut counts = state.ssh_connections_by_sandbox.lock().unwrap();
        let count = counts.entry(sandbox_id.clone()).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_SANDBOX {
            // Roll back the per-token increment.
            let mut token_counts = state.ssh_connections_by_token.lock().unwrap();
            if let Some(c) = token_counts.get_mut(&token) {
                *c = c.saturating_sub(1);
                if *c == 0 {
                    token_counts.remove(&token);
                }
            }
            warn!(sandbox_id = %sandbox_id, active_connections = *count, limit = MAX_CONNECTIONS_PER_SANDBOX, "SSH tunnel: per-sandbox connection limit reached");
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        *count += 1;
    }

    let upgrade = hyper::upgrade::on(req);
    let handshake_secret = state.config.ssh_handshake_secret.clone();
    let sandbox_id_clone = sandbox_id.clone();
    let token_clone = token.clone();
    let state_clone = state.clone();
    let upstream =
        match establish_upstream(&connect_target, &token, &handshake_secret, &sandbox_id).await {
            Ok(upstream) => upstream,
            Err(err) => {
                warn!(sandbox_id = %sandbox_id, error = %err, "SSH tunnel setup failed");
                decrement_connection_count(&state.ssh_connections_by_token, &token);
                decrement_connection_count(&state.ssh_connections_by_sandbox, &sandbox_id);
                return err.status_code().into_response();
            }
        };

    tokio::spawn(async move {
        match upgrade.await {
            Ok(mut upgraded) => {
                if let Err(err) = bridge_tunnel(&mut upgraded, upstream, &sandbox_id_clone).await {
                    warn!(error = %err, "SSH tunnel failure");
                }
            }
            Err(err) => {
                warn!(error = %err, "SSH upgrade failed");
            }
        }

        // Decrement connection counts on tunnel completion.
        decrement_connection_count(&state_clone.ssh_connections_by_token, &token_clone);
        decrement_connection_count(&state_clone.ssh_connections_by_sandbox, &sandbox_id_clone);
    });

    StatusCode::OK.into_response()
}

async fn establish_upstream(
    target: &ConnectTarget,
    token: &str,
    secret: &str,
    sandbox_id: &str,
) -> Result<TcpStream, TunnelSetupError> {
    // The sandbox pod may not be network-reachable immediately after the CRD
    // reports Ready (DNS propagation, pod IP assignment, SSH server startup).
    // Retry the TCP connection with exponential backoff.
    let delays = [
        Duration::from_millis(100),
        Duration::from_millis(250),
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(5),
        Duration::from_secs(10),
        Duration::from_secs(15),
    ];
    let target_desc = match &target {
        ConnectTarget::Ip(addr) => format!("{addr}"),
        ConnectTarget::Host(host, port) => format!("{host}:{port}"),
    };
    info!(sandbox_id = %sandbox_id, target = %target_desc, "SSH tunnel: connecting to sandbox");
    establish_upstream_with_timeouts(
        target,
        token,
        secret,
        sandbox_id,
        SSH_UPSTREAM_CONNECT_TIMEOUT,
        SSH_UPSTREAM_HANDSHAKE_TIMEOUT,
        &delays,
    )
    .await
}

async fn establish_upstream_with_timeouts(
    target: &ConnectTarget,
    token: &str,
    secret: &str,
    sandbox_id: &str,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    delays: &[Duration],
) -> Result<TcpStream, TunnelSetupError> {
    let mut upstream = None;
    let mut last_err = None;
    let target_desc = match target {
        ConnectTarget::Ip(addr) => format!("{addr}"),
        ConnectTarget::Host(host, port) => format!("{host}:{port}"),
    };
    for (attempt, delay) in std::iter::once(&Duration::ZERO)
        .chain(delays.iter())
        .enumerate()
    {
        if !delay.is_zero() {
            info!(sandbox_id = %sandbox_id, attempt = attempt + 1, delay_ms = delay.as_millis() as u64, "SSH tunnel: retrying TCP connect");
            tokio::time::sleep(*delay).await;
        }
        let result = connect_target_with_timeout(target, connect_timeout).await;
        match result {
            Ok(stream) => {
                info!(
                    sandbox_id = %sandbox_id,
                    attempts = attempt + 1,
                    "SSH tunnel: TCP connected to sandbox"
                );
                upstream = Some(stream);
                break;
            }
            Err(err) => {
                info!(sandbox_id = %sandbox_id, attempt = attempt + 1, error = %err, "SSH tunnel: TCP connect failed");
                last_err = Some(err);
            }
        }
    }
    let mut upstream = upstream.ok_or_else(|| {
        last_err.unwrap_or_else(|| {
            TunnelSetupError::Other(format!(
                "failed to connect to sandbox after retries: {target_desc}"
            ))
        })
    })?;
    upstream
        .set_nodelay(true)
        .map_err(|err| TunnelSetupError::Other(err.to_string()))?;
    if let Err(err) = enable_tcp_keepalive(&upstream) {
        warn!(sandbox_id = %sandbox_id, error = %err, "SSH tunnel: failed to enable upstream TCP keepalive");
    }
    info!(sandbox_id = %sandbox_id, "SSH tunnel: sending NSSH1 handshake preface");
    let preface =
        build_preface(token, secret).map_err(|err| TunnelSetupError::Other(err.to_string()))?;
    tokio::time::timeout(handshake_timeout, upstream.write_all(preface.as_bytes()))
        .await
        .map_err(|_| TunnelSetupError::Timeout("timed out sending sandbox handshake preface"))?
        .map_err(|err| TunnelSetupError::Other(err.to_string()))?;

    info!(sandbox_id = %sandbox_id, "SSH tunnel: waiting for handshake response");
    let mut response = String::new();
    tokio::time::timeout(handshake_timeout, read_line(&mut upstream, &mut response))
        .await
        .map_err(|_| TunnelSetupError::Timeout("timed out waiting for sandbox handshake response"))?
        .map_err(|err| TunnelSetupError::Other(err.to_string()))?;
    info!(sandbox_id = %sandbox_id, response = %response.trim(), "SSH tunnel: handshake response received");
    if response.trim() != "OK" {
        return Err(TunnelSetupError::Other(
            "sandbox handshake rejected".to_string(),
        ));
    }

    Ok(upstream)
}

async fn bridge_tunnel(
    upgraded: &mut Upgraded,
    mut upstream: TcpStream,
    sandbox_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!(sandbox_id = %sandbox_id, "SSH tunnel established");
    let mut upgraded = TokioIo::new(upgraded);
    match tokio::io::copy_bidirectional(&mut upgraded, &mut upstream).await {
        Ok((client_to_sandbox, sandbox_to_client)) => {
            info!(sandbox_id = %sandbox_id, client_to_sandbox_bytes = client_to_sandbox, sandbox_to_client_bytes = sandbox_to_client, "SSH tunnel closed");
        }
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            info!(sandbox_id = %sandbox_id, error = %err, "SSH tunnel closed during shutdown");
        }
        Err(err) => {
            warn!(sandbox_id = %sandbox_id, error = %err, "SSH tunnel I/O failure");
        }
    }
    // Gracefully shut down the write-half of the upgraded connection so the
    // client receives a clean EOF instead of a TCP RST.  This gives SSH time
    // to read any remaining protocol data (e.g. exit-status) from its buffer.
    let _ = AsyncWriteExt::shutdown(&mut upgraded).await;
    Ok(())
}

async fn connect_target_with_timeout(
    target: &ConnectTarget,
    timeout: Duration,
) -> Result<TcpStream, TunnelSetupError> {
    let connect = match target {
        ConnectTarget::Ip(addr) => tokio::time::timeout(timeout, TcpStream::connect(addr)).await,
        ConnectTarget::Host(host, port) => {
            tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), *port))).await
        }
    };

    match connect {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(err)) => Err(TunnelSetupError::Other(err.to_string())),
        Err(_) => Err(TunnelSetupError::Timeout("timed out connecting to sandbox")),
    }
}

fn header_value(headers: &http::HeaderMap, name: &str) -> Result<String, StatusCode> {
    let value = headers
        .get(name)
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .trim()
        .to_string();
    if value.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(value)
}

fn build_preface(
    token: &str,
    secret: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let timestamp = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "time error")?
            .as_secs(),
    )
    .map_err(|_| "time error")?;
    let nonce = Uuid::new_v4().to_string();
    let payload = format!("{token}|{timestamp}|{nonce}");
    let signature = hmac_sha256(secret.as_bytes(), payload.as_bytes());
    Ok(format!(
        "{PREFACE_MAGIC} {token} {timestamp} {nonce} {signature}\n"
    ))
}

async fn read_line(
    stream: &mut TcpStream,
    buf: &mut String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() > 1024 {
            break;
        }
    }
    *buf = String::from_utf8_lossy(&bytes).to_string();
    Ok(())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

impl ObjectType for SshSession {
    fn object_type() -> &'static str {
        "ssh_session"
    }
}

impl ObjectId for SshSession {
    fn object_id(&self) -> &str {
        &self.id
    }
}

impl ObjectName for SshSession {
    fn object_name(&self) -> &str {
        &self.name
    }
}

enum ConnectTarget {
    Ip(SocketAddr),
    Host(String, u16),
}

#[derive(Debug, Clone)]
enum TunnelSetupError {
    Timeout(&'static str),
    Other(String),
}

impl TunnelSetupError {
    const fn status_code(&self) -> StatusCode {
        match self {
            Self::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
            Self::Other(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl std::fmt::Display for TunnelSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout(msg) => write!(f, "{msg}"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

/// Decrement a connection count entry, removing it if it reaches zero.
fn decrement_connection_count(
    counts: &std::sync::Mutex<std::collections::HashMap<String, u32>>,
    key: &str,
) {
    let mut map = counts.lock().unwrap();
    if let Some(count) = map.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            map.remove(key);
        }
    }
}

/// Spawn a background task that periodically reaps expired and revoked SSH sessions.
pub fn spawn_session_reaper(store: Arc<Store>, interval: Duration) {
    tokio::spawn(async move {
        // Initial delay to let startup settle.
        tokio::time::sleep(interval).await;

        loop {
            if let Err(e) = reap_expired_sessions(&store).await {
                warn!(error = %e, "SSH session reaper sweep failed");
            }
            tokio::time::sleep(interval).await;
        }
    });
}

async fn reap_expired_sessions(store: &Store) -> Result<(), String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let records = store
        .list(SshSession::object_type(), 1000, 0)
        .await
        .map_err(|e| e.to_string())?;

    let mut reaped = 0u32;
    for record in records {
        let session: SshSession = match Message::decode(record.payload.as_slice()) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let should_delete =
            // Expired sessions (expires_at_ms > 0 means expiry is set).
            (session.expires_at_ms > 0 && now_ms > session.expires_at_ms)
            // Revoked sessions — already invalidated, just cleaning up storage.
            || session.revoked;

        if should_delete {
            if let Err(e) = store.delete(SshSession::object_type(), &session.id).await {
                warn!(session_id = %session.id, error = %e, "Failed to reap SSH session");
            } else {
                reaped += 1;
            }
        }
    }

    if reaped > 0 {
        info!(count = reaped, "SSH session reaper: cleaned up sessions");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::Store;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    fn make_session(id: &str, sandbox_id: &str, expires_at_ms: i64, revoked: bool) -> SshSession {
        SshSession {
            id: id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            token: id.to_string(),
            created_at_ms: 1000,
            revoked,
            name: format!("session-{id}"),
            expires_at_ms,
        }
    }

    fn now_ms() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    // ---- Connection limit tests ----

    #[test]
    fn decrement_removes_entry_at_zero() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts.lock().unwrap().insert("tok1".to_string(), 1);
        decrement_connection_count(&counts, "tok1");
        assert!(counts.lock().unwrap().is_empty());
    }

    #[test]
    fn decrement_reduces_count() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts.lock().unwrap().insert("tok1".to_string(), 5);
        decrement_connection_count(&counts, "tok1");
        assert_eq!(*counts.lock().unwrap().get("tok1").unwrap(), 4);
    }

    #[test]
    fn decrement_missing_key_is_noop() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        decrement_connection_count(&counts, "nonexistent");
        assert!(counts.lock().unwrap().is_empty());
    }

    #[test]
    fn per_token_connection_limit_enforced() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts
            .lock()
            .unwrap()
            .insert("tok1".to_string(), MAX_CONNECTIONS_PER_TOKEN);
        let current = *counts.lock().unwrap().get("tok1").unwrap();
        assert!(current >= MAX_CONNECTIONS_PER_TOKEN);
    }

    #[test]
    fn per_sandbox_connection_limit_enforced() {
        let counts: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
        counts
            .lock()
            .unwrap()
            .insert("sbx1".to_string(), MAX_CONNECTIONS_PER_SANDBOX);
        let current = *counts.lock().unwrap().get("sbx1").unwrap();
        assert!(current >= MAX_CONNECTIONS_PER_SANDBOX);
    }

    // ---- Session reaper tests ----

    #[tokio::test]
    async fn reaper_deletes_expired_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let expired = make_session("expired1", "sbx1", now_ms() - 60_000, false);
        store.put_message(&expired).await.unwrap();

        let valid = make_session("valid1", "sbx1", now_ms() + 3_600_000, false);
        store.put_message(&valid).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("expired1")
                .await
                .unwrap()
                .is_none(),
            "expired session should be reaped"
        );
        assert!(
            store
                .get_message::<SshSession>("valid1")
                .await
                .unwrap()
                .is_some(),
            "valid session should be kept"
        );
    }

    #[tokio::test]
    async fn reaper_deletes_revoked_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        let revoked = make_session("revoked1", "sbx1", 0, true);
        store.put_message(&revoked).await.unwrap();

        let active = make_session("active1", "sbx1", 0, false);
        store.put_message(&active).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("revoked1")
                .await
                .unwrap()
                .is_none(),
            "revoked session should be reaped"
        );
        assert!(
            store
                .get_message::<SshSession>("active1")
                .await
                .unwrap()
                .is_some(),
            "active session should be kept"
        );
    }

    #[tokio::test]
    async fn reaper_preserves_zero_expiry_sessions() {
        let store = Store::connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();

        // expires_at_ms = 0 means no expiry (backward compatible).
        let no_expiry = make_session("noexpiry1", "sbx1", 0, false);
        store.put_message(&no_expiry).await.unwrap();

        reap_expired_sessions(&store).await.unwrap();

        assert!(
            store
                .get_message::<SshSession>("noexpiry1")
                .await
                .unwrap()
                .is_some(),
            "session with no expiry should be preserved"
        );
    }

    // ---- Expiry validation logic tests ----

    #[test]
    fn expired_session_is_detected() {
        let session = make_session("tok1", "sbx1", now_ms() - 1000, false);
        let is_expired = session.expires_at_ms > 0 && now_ms() > session.expires_at_ms;
        assert!(is_expired, "session in the past should be expired");
    }

    #[test]
    fn future_session_is_not_expired() {
        let session = make_session("tok1", "sbx1", now_ms() + 3_600_000, false);
        let is_expired = session.expires_at_ms > 0 && now_ms() > session.expires_at_ms;
        assert!(!is_expired, "session in the future should not be expired");
    }

    #[test]
    fn zero_expiry_is_not_expired() {
        let session = make_session("tok1", "sbx1", 0, false);
        let is_expired = session.expires_at_ms > 0 && now_ms() > session.expires_at_ms;
        assert!(
            !is_expired,
            "session with zero expiry should never be expired"
        );
    }

    #[tokio::test]
    async fn establish_upstream_times_out_waiting_for_handshake_response() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });

        let err = establish_upstream_with_timeouts(
            &ConnectTarget::Ip(addr),
            "token",
            "secret",
            "sandbox-1",
            Duration::from_millis(20),
            Duration::from_millis(20),
            &[],
        )
        .await
        .unwrap_err();

        assert!(matches!(err, TunnelSetupError::Timeout(_)));
        let _ = server.await;
    }

    #[tokio::test]
    async fn establish_upstream_rejects_non_ok_handshake_response() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 256];
            let _ = stream.read(&mut buf).await.unwrap();
            stream.write_all(b"ERR\n").await.unwrap();
        });

        let err = establish_upstream_with_timeouts(
            &ConnectTarget::Ip(addr),
            "token",
            "secret",
            "sandbox-1",
            Duration::from_millis(20),
            Duration::from_millis(20),
            &[],
        )
        .await
        .unwrap_err();

        assert!(matches!(err, TunnelSetupError::Other(_)));
        let _ = server.await;
    }
}
