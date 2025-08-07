// Copyright (c) 2025 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.

use std::{io::ErrorKind, net::IpAddr, num::NonZeroU16, str::FromStr};
use pvpnclient::pvpnclient::{NanoSecTimestamp, Peer, PeerAddr, SocketErr};
use crate::api::connection::PeerInfo;

pub(crate) fn now() -> NanoSecTimestamp {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

pub(crate) fn error_kind_to_socket_err(error_kind: ErrorKind) -> SocketErr {
    match error_kind {
        ErrorKind::ConnectionRefused => SocketErr::ConnectionRefused,
        ErrorKind::TimedOut => SocketErr::Timeout,
        ErrorKind::HostUnreachable => SocketErr::HostUnreachable,
        ErrorKind::NetworkUnreachable => SocketErr::NetworkUnreachable,
        ErrorKind::AddrInUse => SocketErr::AddressInUse,
        ErrorKind::ConnectionAborted => SocketErr::ConnectionAborted,
        ErrorKind::ConnectionReset => SocketErr::ConnectionReset,
        ErrorKind::NotConnected => SocketErr::NotConnected,
        _ => SocketErr::Unknown,
    }
}

impl PeerInfo {

    pub(crate) fn as_peer(&self) -> Peer {
        let addr = IpAddr::from_str(&self.server_ip).expect("not a valid IP");
        let peer_ip = match addr {
            IpAddr::V4(addr) => (Some(addr), None),
            IpAddr::V6(addr) => (None, Some(addr)),
        };
        let peer_addr = PeerAddr::try_from(peer_ip).expect("not a valid IP");
        Peer::builder(peer_addr, self.server_public_key.clone().into())
            .with_tag(&self.peer_id)
            .udp_ports(&Self::to_non_zero_vec(&self.udp_ports))
            .tcp_ports(&Self::to_non_zero_vec(&self.tcp_ports))
            .tls_ports(&Self::to_non_zero_vec(&self.tls_ports))
            .priority(self.priority as i16)
            .build()
    }

    fn to_non_zero_vec(ports: &Vec<u16>) -> Vec<NonZeroU16> {
        ports
            .iter()
            .map(|&x| x.try_into().expect("not a valid port"))
            .collect::<Vec<_>>()
    }

    pub(crate) fn addr(&self) -> PeerAddr {
        let addr = IpAddr::from_str(&self.server_ip).expect("not a valid IP");
        let peer_ip = match addr {
            IpAddr::V4(addr) => (Some(addr), None),
            IpAddr::V6(addr) => (None, Some(addr)),
        };
        PeerAddr::try_from(peer_ip).expect("not a valid IP")
    }
}
