// Copyright (c) 2026 Proton AG
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

use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::fmt::{Display, Formatter, Result};
use std::sync::Arc;

use crate::connection::windows::helpers::internet_interface_finder::{Ipv4InternetInterface, Ipv6InternetInterface};
use crate::connection::windows::helpers::wintun::wintun_session::WinTunSession;
use crate::utils::windows::luid::Luid;

#[derive(Clone)]
pub(crate) struct SocketInterface {
    pub(crate) address: SocketAddr,
    pub(crate) interface_luid: Luid,
    pub(crate) interface_index: u32,
    pub(crate) _next_hop: IpAddr,
}

impl SocketInterface {
    pub(crate) fn new_ipv4(interface: &Ipv4InternetInterface) -> Self {
        let socket_addr_v4: SocketAddrV4 = SocketAddrV4::new(interface.local_ip, 0);

        SocketInterface {
            address: SocketAddr::V4(socket_addr_v4),
            interface_luid: interface.interface_luid,
            interface_index: interface.interface_index,
            _next_hop: IpAddr::V4(interface.next_hop)
        }          
    }

    pub(crate) fn new_ipv6(interface: &Ipv6InternetInterface) -> Self {
        let socket_addr_v6: SocketAddrV6 = SocketAddrV6::new(interface.local_ip, 0, 0, 0);

        SocketInterface {
            address: SocketAddr::V6(socket_addr_v6),
            interface_luid: interface.interface_luid,
            interface_index: interface.interface_index,
            _next_hop: IpAddr::V6(interface.next_hop)
        }          
    }

    pub(crate) fn new_tun(tun_session: &Arc<WinTunSession>) -> Self {
        SocketInterface {
            address: SocketAddr::V4(SocketAddrV4::new(tun_session.client_ipv4_addr, 0)),
            interface_luid: tun_session.interface_luid,
            interface_index: tun_session.interface_index,
            _next_hop: IpAddr::V4(tun_session.server_ipv4_addr)
        }          
    }
}

impl Display for SocketInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{} (Interface - LUID: {}, Index: {})", self.address, self.interface_luid, self.interface_index)
    }
}