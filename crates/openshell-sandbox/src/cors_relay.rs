// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CORS-aware relay for port-forwarded sandbox services.
//!
//! When a sandbox policy configures CORS for a given port, the SSH
//! `direct-tcpip` handler uses this module instead of a raw
//! `copy_bidirectional`. The relay:
//!
//! 1. Peeks at the first bytes to detect HTTP traffic.
//! 2. For HTTP requests: injects CORS response headers and handles
//!    `OPTIONS` preflight requests.
//! 3. For WebSocket upgrade requests: validates the `Origin` header and
//!    rejects unauthorized upgrades with 403.
//! 4. For non-HTTP traffic: falls back to raw bidirectional copy.

use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::RwLock;
use tracing::debug;

use crate::l7::rest::looks_like_http;

/// Maximum header size we'll buffer before giving up.
const MAX_HEADER_BYTES: usize = 16384;

/// Relay buffer size for raw body/response forwarding.
const RELAY_BUF_SIZE: usize = 8192;

/// CORS configuration for a single port-forwarded service, extracted from
/// the sandbox policy at startup. Only `allowed_origins` is user-configurable;
/// all other CORS headers use hardcoded defaults.
#[derive(Debug, Clone)]
pub struct IngressCorsConfig {
    pub allowed_origins: Vec<String>,
}

impl IngressCorsConfig {
    /// Check if a given origin is allowed by this CORS config.
    ///
    /// Returns the origin string to use in `Access-Control-Allow-Origin`, or
    /// `None` if the origin is not allowed.
    fn match_origin(&self, origin: &str) -> Option<String> {
        if self.allowed_origins.iter().any(|o| o == "*") {
            return Some("*".to_string());
        }
        if self.allowed_origins.iter().any(|o| o == origin) {
            return Some(origin.to_string());
        }
        None
    }

    /// Build CORS response headers for a matched origin.
    fn build_cors_headers(&self, matched_origin: &str) -> String {
        format!(
            "Access-Control-Allow-Origin: {matched_origin}\r\n\
             Vary: Origin\r\n"
        )
    }

    /// Build CORS preflight response headers for a matched origin.
    fn build_preflight_headers(&self, matched_origin: &str) -> String {
        format!(
            "Access-Control-Allow-Origin: {matched_origin}\r\n\
             Vary: Origin\r\n\
             Access-Control-Allow-Methods: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS\r\n\
             Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
             Access-Control-Max-Age: 3600\r\n"
        )
    }
}

/// Shared, hot-reloadable CORS config map keyed by port number.
pub type CorsConfigMap = Arc<RwLock<HashMap<u16, IngressCorsConfig>>>;

/// Create a new empty CORS config map.
pub fn new_cors_config_map() -> CorsConfigMap {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Extract port -> CORS config from a proto sandbox policy.
pub fn extract_cors_configs(
    proto: &openshell_core::proto::SandboxPolicy,
) -> HashMap<u16, IngressCorsConfig> {
    let mut map = HashMap::new();
    for rule in proto.network_policies.values() {
        for ep in &rule.endpoints {
            if let Some(ref cors) = ep.cors {
                let ports = if !ep.ports.is_empty() {
                    ep.ports.clone()
                } else if ep.port > 0 {
                    vec![ep.port]
                } else {
                    continue;
                };
                let config = IngressCorsConfig {
                    allowed_origins: cors.allowed_origins.clone(),
                };
                for port in ports {
                    #[allow(clippy::cast_possible_truncation)]
                    map.insert(port as u16, config.clone());
                }
            }
        }
    }
    map
}

/// Run the CORS-aware relay between client (SSH channel) and upstream
/// (sandbox loopback service).
///
/// Detects HTTP traffic, injects CORS headers on responses, handles
/// preflight requests, and validates WebSocket upgrade origins. Falls
/// back to raw bidirectional copy for non-HTTP traffic.
pub async fn relay_with_cors<C, U>(
    client: &mut C,
    upstream: &mut U,
    cors: &IngressCorsConfig,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    // Peek at first bytes to detect HTTP.
    let mut peek_buf = [0u8; 16];
    let peek_n = client.read(&mut peek_buf).await?;
    if peek_n == 0 {
        return Ok(());
    }

    if !looks_like_http(&peek_buf[..peek_n]) {
        // Not HTTP — forward the peeked bytes and switch to raw relay.
        upstream.write_all(&peek_buf[..peek_n]).await?;
        tokio::io::copy_bidirectional(client, upstream).await?;
        return Ok(());
    }

    // HTTP detected — enter the request/response relay loop.
    // Seed the header buffer with the peeked bytes.
    let mut header_buf = Vec::with_capacity(4096);
    header_buf.extend_from_slice(&peek_buf[..peek_n]);

    loop {
        // Read request headers until \r\n\r\n.
        loop {
            if header_buf.len() > MAX_HEADER_BYTES {
                // Header too large — bail and let the upstream deal with it.
                upstream.write_all(&header_buf).await?;
                tokio::io::copy_bidirectional(client, upstream).await?;
                return Ok(());
            }
            if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
            let mut tmp = [0u8; 1024];
            let n = client.read(&mut tmp).await?;
            if n == 0 {
                // Client closed mid-headers — forward what we have.
                if !header_buf.is_empty() {
                    upstream.write_all(&header_buf).await?;
                }
                return Ok(());
            }
            header_buf.extend_from_slice(&tmp[..n]);
        }

        let header_end = header_buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap()
            + 4;
        let header_str = String::from_utf8_lossy(&header_buf[..header_end]);

        // Parse request line.
        let request_line = header_str.lines().next().unwrap_or_default();
        let method = request_line
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();

        // Extract Origin header.
        let origin = extract_header(&header_str, "origin");

        // Check for WebSocket upgrade.
        let is_websocket_upgrade = has_header_value(&header_str, "upgrade", "websocket");

        // --- Handle OPTIONS preflight ---
        if method == "OPTIONS" {
            if let Some(ref origin_val) = origin {
                if let Some(matched) = cors.match_origin(origin_val) {
                    let preflight_headers = cors.build_preflight_headers(&matched);
                    let response = format!("HTTP/1.1 204 No Content\r\n{preflight_headers}\r\n");
                    client.write_all(response.as_bytes()).await?;
                    client.flush().await?;
                } else {
                    // Origin not allowed — send 204 without CORS headers.
                    client.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
                    client.flush().await?;
                }
            } else {
                // No Origin header — might be a non-CORS OPTIONS request.
                // Forward to upstream and inject CORS headers on response.
                upstream.write_all(&header_buf[..header_end]).await?;
                forward_and_inject_cors(upstream, client, &method, cors, None).await?;
            }

            // Drain any overflow bytes past the headers for the next request.
            let overflow = header_buf[header_end..].to_vec();
            header_buf.clear();
            header_buf.extend_from_slice(&overflow);

            if header_buf.is_empty() {
                // Read next request start.
                let mut tmp = [0u8; 1024];
                let n = client.read(&mut tmp).await?;
                if n == 0 {
                    return Ok(());
                }
                header_buf.extend_from_slice(&tmp[..n]);
            }
            continue;
        }

        // --- Handle WebSocket upgrade ---
        if is_websocket_upgrade {
            if let Some(ref origin_val) = origin {
                if cors.match_origin(origin_val).is_none() {
                    // Origin not allowed — reject with 403.
                    let body = r#"{"error":"cors_origin_denied","detail":"WebSocket upgrade rejected: origin not allowed"}"#;
                    let response = format!(
                        "HTTP/1.1 403 Forbidden\r\n\
                         Content-Type: application/json\r\n\
                         Content-Length: {}\r\n\
                         Connection: close\r\n\
                         \r\n\
                         {body}",
                        body.len(),
                    );
                    client.write_all(response.as_bytes()).await?;
                    client.flush().await?;
                    debug!(
                        origin = origin_val,
                        "WebSocket upgrade rejected: origin not in allowed_origins"
                    );
                    return Ok(());
                }
            }
            // Origin allowed (or no Origin header) — forward the upgrade to
            // upstream, then switch to raw bidirectional copy for WS frames.
            upstream.write_all(&header_buf).await?;
            header_buf.clear();
            tokio::io::copy_bidirectional(client, upstream).await?;
            return Ok(());
        }

        // --- Handle normal HTTP request ---
        // Forward request headers + any overflow body to upstream.
        upstream.write_all(&header_buf[..header_end]).await?;

        // Relay request body.
        let body_length = parse_body_length(&header_str);
        let overflow = &header_buf[header_end..];
        let overflow_len = overflow.len() as u64;

        match body_length {
            BodyLength::ContentLength(len) => {
                if !overflow.is_empty() {
                    upstream.write_all(overflow).await?;
                }
                let remaining = len.saturating_sub(overflow_len);
                if remaining > 0 {
                    relay_fixed(client, upstream, remaining).await?;
                }
            }
            BodyLength::Chunked => {
                if !overflow.is_empty() {
                    upstream.write_all(overflow).await?;
                }
                relay_chunked_body(client, upstream).await?;
            }
            BodyLength::None => {
                if !overflow.is_empty() {
                    upstream.write_all(overflow).await?;
                }
            }
        }
        upstream.flush().await?;

        // Relay response with CORS header injection.
        let reusable =
            forward_and_inject_cors(upstream, client, &method, cors, origin.as_deref()).await?;

        if !reusable {
            return Ok(());
        }

        // Prepare for next request on this keep-alive connection.
        header_buf.clear();
        let mut tmp = [0u8; 1024];
        let n = client.read(&mut tmp).await?;
        if n == 0 {
            return Ok(());
        }
        header_buf.extend_from_slice(&tmp[..n]);
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum BodyLength {
    ContentLength(u64),
    Chunked,
    None,
}

fn parse_body_length(headers: &str) -> BodyLength {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            if val.contains("chunked") {
                return BodyLength::Chunked;
            }
        }
        if let Some(val) = lower.strip_prefix("content-length:").map(str::trim) {
            if let Ok(len) = val.parse::<u64>() {
                return BodyLength::ContentLength(len);
            }
        }
    }
    BodyLength::None
}

/// Extract a specific header value (case-insensitive key match).
fn extract_header(headers: &str, name: &str) -> Option<String> {
    let prefix = format!("{}:", name);
    for line in headers.lines().skip(1) {
        if line.to_ascii_lowercase().starts_with(&prefix) {
            return line.split_once(':').map(|(_, v)| v.trim().to_string());
        }
    }
    None
}

/// Check if a header exists with a specific value (case-insensitive).
fn has_header_value(headers: &str, name: &str, value: &str) -> bool {
    extract_header(headers, name)
        .is_some_and(|v| v.to_ascii_lowercase().contains(&value.to_ascii_lowercase()))
}

/// Relay exactly `len` bytes from reader to writer.
async fn relay_fixed<R, W>(reader: &mut R, writer: &mut W, len: u64) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut remaining = len;
    let mut buf = [0u8; RELAY_BUF_SIZE];
    while remaining > 0 {
        let to_read = usize::try_from(remaining)
            .unwrap_or(buf.len())
            .min(buf.len());
        let n = reader.read(&mut buf[..to_read]).await?;
        if n == 0 {
            return Err(std::io::Error::other(format!(
                "connection closed with {remaining} bytes remaining"
            )));
        }
        writer.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }
    Ok(())
}

/// Relay chunked transfer-encoded body from reader to writer.
///
/// Simplified version: forward bytes verbatim until we see the terminal
/// `0\r\n\r\n` sequence.
async fn relay_chunked_body<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; RELAY_BUF_SIZE];
    let mut tail = Vec::new();
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;

        tail.extend_from_slice(&buf[..n]);
        if tail.len() > 5 {
            let drain_to = tail.len() - 5;
            tail.drain(..drain_to);
        }
        if tail.ends_with(b"0\r\n\r\n") {
            return Ok(());
        }
    }
}

/// Read the upstream response, inject CORS headers, and forward to client.
///
/// Returns `true` if the connection is reusable (keep-alive).
async fn forward_and_inject_cors<U, C>(
    upstream: &mut U,
    client: &mut C,
    request_method: &str,
    cors: &IngressCorsConfig,
    origin: Option<&str>,
) -> std::io::Result<bool>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    // Read response headers.
    loop {
        if buf.len() > MAX_HEADER_BYTES {
            client.write_all(&buf).await?;
            return Ok(false);
        }
        let n = upstream.read(&mut tmp).await?;
        if n == 0 {
            if !buf.is_empty() {
                client.write_all(&buf).await?;
            }
            return Ok(false);
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let status_code = parse_status_code(&header_str).unwrap_or(200);
    let server_wants_close = parse_connection_close(&header_str);
    let resp_body_length = parse_body_length(&header_str);

    // Build CORS headers to inject.
    let cors_headers = if let Some(origin_val) = origin {
        cors.match_origin(origin_val)
            .map(|matched| cors.build_cors_headers(&matched))
            .unwrap_or_default()
    } else {
        String::new()
    };

    // Inject CORS headers before the final \r\n\r\n.
    let headers_before_end = &buf[..header_end - 2];
    client.write_all(headers_before_end).await?;
    if !cors_headers.is_empty() {
        client.write_all(cors_headers.as_bytes()).await?;
    }
    client.write_all(b"\r\n").await?;

    // Forward overflow bytes (part of the body that arrived with headers).
    let overflow = &buf[header_end..];
    if !overflow.is_empty() {
        client.write_all(overflow).await?;
    }
    let overflow_len = overflow.len() as u64;

    // Bodiless responses: HEAD, 1xx, 204, 304.
    if is_bodiless_response(request_method, status_code) {
        client.flush().await?;
        return Ok(!server_wants_close);
    }

    if matches!(resp_body_length, BodyLength::None) && server_wants_close {
        relay_until_eof(upstream, client).await?;
        client.flush().await?;
        return Ok(false);
    }

    if matches!(resp_body_length, BodyLength::None) {
        client.flush().await?;
        return Ok(true);
    }

    match resp_body_length {
        BodyLength::ContentLength(len) => {
            let remaining = len.saturating_sub(overflow_len);
            if remaining > 0 {
                relay_fixed(upstream, client, remaining).await?;
            }
        }
        BodyLength::Chunked => {
            relay_chunked_body(upstream, client).await?;
        }
        BodyLength::None => unreachable!(),
    }
    client.flush().await?;
    Ok(true)
}

fn parse_status_code(headers: &str) -> Option<u16> {
    let status_line = headers.lines().next()?;
    let code_str = status_line.split_whitespace().nth(1)?;
    code_str.parse().ok()
}

fn parse_connection_close(headers: &str) -> bool {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("connection:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            return val.contains("close");
        }
    }
    false
}

fn is_bodiless_response(request_method: &str, status_code: u16) -> bool {
    request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&status_code)
        || status_code == 204
        || status_code == 304
}

async fn relay_until_eof<R, W>(reader: &mut R, writer: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; RELAY_BUF_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn test_cors_config() -> IngressCorsConfig {
        IngressCorsConfig {
            allowed_origins: vec![
                "https://app.example.com".to_string(),
                "https://dashboard.example.com".to_string(),
            ],
        }
    }

    fn wildcard_cors_config() -> IngressCorsConfig {
        IngressCorsConfig {
            allowed_origins: vec!["*".to_string()],
        }
    }

    #[test]
    fn match_origin_exact() {
        let cors = test_cors_config();
        assert_eq!(
            cors.match_origin("https://app.example.com"),
            Some("https://app.example.com".to_string())
        );
        assert_eq!(cors.match_origin("https://evil.com"), None);
    }

    #[test]
    fn match_origin_wildcard() {
        let cors = wildcard_cors_config();
        assert_eq!(
            cors.match_origin("https://anything.com"),
            Some("*".to_string())
        );
    }

    #[test]
    fn extract_header_case_insensitive() {
        let headers =
            "GET / HTTP/1.1\r\nOrigin: https://app.example.com\r\nHost: localhost\r\n\r\n";
        assert_eq!(
            extract_header(headers, "origin"),
            Some("https://app.example.com".to_string())
        );
        let headers2 = "GET / HTTP/1.1\r\nORIGIN: https://app.example.com\r\n\r\n";
        assert_eq!(
            extract_header(headers2, "origin"),
            Some("https://app.example.com".to_string())
        );
    }

    #[test]
    fn has_header_value_detects_websocket() {
        let headers = "GET / HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(has_header_value(headers, "upgrade", "websocket"));
        let headers2 = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert!(!has_header_value(headers2, "upgrade", "websocket"));
    }

    #[tokio::test]
    async fn relay_injects_cors_headers_on_response() {
        let cors = test_cors_config();

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (mut upstream_side, mut upstream_write_side) = duplex(8192);
        let (mut client_read_side, mut client_side) = duplex(8192);

        tokio::spawn(async move {
            upstream_write_side.write_all(response).await.unwrap();
            upstream_write_side.shutdown().await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            forward_and_inject_cors(
                &mut upstream_side,
                &mut client_side,
                "GET",
                &cors,
                Some("https://app.example.com"),
            ),
        )
        .await
        .expect("should not timeout");
        result.expect("should succeed");

        client_side.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read_side.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);

        assert!(
            received_str.contains("Access-Control-Allow-Origin: https://app.example.com"),
            "CORS origin header missing in: {received_str}"
        );
        assert!(
            received_str.contains("Vary: Origin"),
            "Vary header missing in: {received_str}"
        );
        assert!(
            received_str.contains("hello"),
            "Body missing in: {received_str}"
        );
    }

    #[tokio::test]
    async fn relay_omits_cors_for_unmatched_origin() {
        let cors = test_cors_config();

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (mut upstream_side, mut upstream_write_side) = duplex(8192);
        let (mut client_read_side, mut client_side) = duplex(8192);

        tokio::spawn(async move {
            upstream_write_side.write_all(response).await.unwrap();
            upstream_write_side.shutdown().await.unwrap();
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            forward_and_inject_cors(
                &mut upstream_side,
                &mut client_side,
                "GET",
                &cors,
                Some("https://evil.com"),
            ),
        )
        .await
        .expect("should not timeout");
        result.expect("should succeed");

        client_side.shutdown().await.unwrap();
        let mut received = Vec::new();
        client_read_side.read_to_end(&mut received).await.unwrap();
        let received_str = String::from_utf8_lossy(&received);

        assert!(
            !received_str.contains("Access-Control-Allow-Origin"),
            "CORS headers should NOT be present for unmatched origin: {received_str}"
        );
        assert!(
            received_str.contains("hello"),
            "Body should still be forwarded: {received_str}"
        );
    }

    #[tokio::test]
    async fn non_http_traffic_falls_back_to_raw_relay() {
        let cors = test_cors_config();

        let (mut client_side, mut client_write) = duplex(8192);
        let (mut upstream_read, mut upstream_side) = duplex(8192);

        tokio::spawn(async move {
            client_write
                .write_all(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
                .await
                .unwrap();
            client_write.shutdown().await.unwrap();
        });

        let upstream_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let n = upstream_read.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        });

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            relay_with_cors(&mut client_side, &mut upstream_side, &cors),
        )
        .await
        .expect("should not timeout");
        result.expect("should succeed");

        upstream_task.await.unwrap();
    }

    #[test]
    fn extract_cors_configs_from_proto() {
        let proto = openshell_core::proto::SandboxPolicy {
            version: 1,
            filesystem: None,
            landlock: None,
            process: None,
            network_policies: {
                let mut map = HashMap::new();
                map.insert(
                    "web".to_string(),
                    openshell_core::proto::NetworkPolicyRule {
                        name: "web".to_string(),
                        endpoints: vec![openshell_core::proto::NetworkEndpoint {
                            host: "localhost".to_string(),
                            port: 8080,
                            ports: vec![8080],
                            cors: Some(openshell_core::proto::CorsConfig {
                                allowed_origins: vec!["https://app.example.com".to_string()],
                            }),
                            ..Default::default()
                        }],
                        binaries: vec![],
                    },
                );
                map
            },
        };

        let configs = extract_cors_configs(&proto);
        assert!(configs.contains_key(&8080));
        let cfg = &configs[&8080];
        assert_eq!(cfg.allowed_origins, vec!["https://app.example.com"]);
    }
}
