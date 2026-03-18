//! Capability-gated network operations.
//!
//! Drop-in replacements for `std::net` functions that require a capability token.

use capsec_core::cap::Cap;
use capsec_core::error::CapSecError;
use capsec_core::has::Has;
use capsec_core::permission::{NetBind, NetConnect};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};

/// Opens a TCP connection to the given address.
/// Requires [`NetConnect`] permission.
pub fn tcp_connect(
    addr: impl ToSocketAddrs,
    cap: &impl Has<NetConnect>,
) -> Result<TcpStream, CapSecError> {
    let _proof: Cap<NetConnect> = cap.cap_ref();
    Ok(TcpStream::connect(addr)?)
}

/// Binds a TCP listener to the given address.
/// Requires [`NetBind`] permission.
pub fn tcp_bind(
    addr: impl ToSocketAddrs,
    cap: &impl Has<NetBind>,
) -> Result<TcpListener, CapSecError> {
    let _proof: Cap<NetBind> = cap.cap_ref();
    Ok(TcpListener::bind(addr)?)
}

/// Binds a UDP socket to the given address.
/// Requires [`NetBind`] permission.
pub fn udp_bind(
    addr: impl ToSocketAddrs,
    cap: &impl Has<NetBind>,
) -> Result<UdpSocket, CapSecError> {
    let _proof: Cap<NetBind> = cap.cap_ref();
    Ok(UdpSocket::bind(addr)?)
}
