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

use std::{io::ErrorKind, net::IpAddr, num::NonZeroU16};
use pvpnclient::{os_interface::error::SystemError, peer::{Peer, PeerAddr}};
use crate::api::connection::PeerInfo;

pub(crate) fn error_kind_to_socket_err(error_kind: ErrorKind) -> SystemError {
    match error_kind {
        ErrorKind::AddrInUse => SystemError::AddressInUse,
        ErrorKind::AddrNotAvailable => SystemError::AddrNotAvailable,
        ErrorKind::AlreadyExists => SystemError::AlreadyExists,
        ErrorKind::BrokenPipe => SystemError::BrokenPipe,
        ErrorKind::ConnectionAborted => SystemError::ConnectionAborted,
        ErrorKind::ConnectionRefused => SystemError::ConnectionRefused,
        ErrorKind::ConnectionReset => SystemError::ConnectionReset,
        ErrorKind::HostUnreachable => SystemError::HostUnreachable,
        ErrorKind::Interrupted => SystemError::Interrupted,
        ErrorKind::InvalidData => SystemError::InvalidData,
        ErrorKind::InvalidInput => SystemError::InvalidInput,
        ErrorKind::NetworkDown => SystemError::NetworkDown,
        ErrorKind::NetworkUnreachable => SystemError::NetworkUnreachable,
        ErrorKind::NotConnected => SystemError::NotConnected,
        ErrorKind::NotFound => SystemError::NotFound,
        ErrorKind::PermissionDenied => SystemError::PermissionDenied,
        ErrorKind::QuotaExceeded => SystemError::QuotaExceeded,
        ErrorKind::ResourceBusy => SystemError::ResourceBusy,
        ErrorKind::TimedOut => SystemError::Timeout,
        ErrorKind::UnexpectedEof => SystemError::UnexpectedEof,
        ErrorKind::WouldBlock => SystemError::WouldBlock,
        ErrorKind::WriteZero => SystemError::WriteZero,
        _ => SystemError::Unknown(None),
    }
}

impl PeerInfo {

    pub(crate) fn as_peer(&self) -> Peer {
        let peer_addr = self.addr();
        let builder = Peer::builder(peer_addr, self.server_public_key.clone().into())
            .with_tag(&self.peer_id)
            .udp_ports(&Self::to_non_zero_vec(&self.udp_ports))
            .tcp_ports(&Self::to_non_zero_vec(&self.tcp_ports))
            .tls_ports(&Self::to_non_zero_vec(&self.tls_ports))
            .priority(self.priority as i16);
        #[cfg(feature = "local-agent")]
        if let Some(label) = &self.exit_label {
            builder
                .with_bouncing_labels(vec![label.clone()])
                .build()
        } else {
            builder.build()
        }
        #[cfg(not(feature = "local-agent"))]
        builder.build()
    }

    fn to_non_zero_vec(ports: &Vec<u16>) -> Vec<NonZeroU16> {
        ports
            .iter()
            .filter(|&x| *x != 0)
            .map(|&x| x.try_into().unwrap())
            .collect::<Vec<_>>()
    }

    pub(crate) fn addr(&self) -> PeerAddr {
        let peer_ip = match self.server_ip.0 {
            IpAddr::V4(addr) => (Some(addr), None),
            IpAddr::V6(addr) => (None, Some(addr)),
        };
        PeerAddr::try_from(peer_ip).expect("shouldn't happen")
    }
}
