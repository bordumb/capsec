//! Capability-gated network operations.
//!
//! Drop-in replacements for `std::net` functions that require a capability token.

use capsec_core::cap::Cap;
use capsec_core::cap_provider::CapProvider;
use capsec_core::error::CapSecError;
use capsec_core::permission::{NetBind, NetConnect};
use std::net::{TcpListener, TcpStream, UdpSocket};

/// Opens a TCP connection to the given address.
/// Requires [`NetConnect`] permission.
pub fn tcp_connect(
    addr: &str,
    cap: &impl CapProvider<NetConnect>,
) -> Result<TcpStream, CapSecError> {
    let _proof: Cap<NetConnect> = cap.provide_cap(addr)?;
    Ok(TcpStream::connect(addr)?)
}

/// Binds a TCP listener to the given address.
/// Requires [`NetBind`] permission.
pub fn tcp_bind(addr: &str, cap: &impl CapProvider<NetBind>) -> Result<TcpListener, CapSecError> {
    let _proof: Cap<NetBind> = cap.provide_cap(addr)?;
    Ok(TcpListener::bind(addr)?)
}

/// Binds a UDP socket to the given address.
/// Requires [`NetBind`] permission.
pub fn udp_bind(addr: &str, cap: &impl CapProvider<NetBind>) -> Result<UdpSocket, CapSecError> {
    let _proof: Cap<NetBind> = cap.provide_cap(addr)?;
    Ok(UdpSocket::bind(addr)?)
}
