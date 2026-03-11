// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Shared socket configuration helpers.

use socket2::{SockRef, TcpKeepalive};
use std::io;
use std::time::Duration;

/// Idle time before TCP keepalive probes start.
pub const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);

/// Interval between TCP keepalive probes on supported platforms.
pub const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

fn default_keepalive() -> TcpKeepalive {
    let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_IDLE);
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
        target_os = "cygwin",
    ))]
    let keepalive = keepalive.with_interval(TCP_KEEPALIVE_INTERVAL);
    keepalive
}

/// Enable aggressive TCP keepalive on a socket.
#[cfg(unix)]
pub fn enable_tcp_keepalive<S>(socket: &S) -> io::Result<()>
where
    S: std::os::fd::AsFd,
{
    SockRef::from(socket).set_tcp_keepalive(&default_keepalive())
}

/// Enable aggressive TCP keepalive on a socket.
#[cfg(windows)]
pub fn enable_tcp_keepalive<S>(socket: &S) -> io::Result<()>
where
    S: std::os::windows::io::AsSocket,
{
    SockRef::from(socket).set_tcp_keepalive(&default_keepalive())
}

/// Enable aggressive TCP keepalive on a socket.
#[cfg(not(any(unix, windows)))]
pub fn enable_tcp_keepalive<S>(_socket: &S) -> io::Result<()> {
    Ok(())
}
