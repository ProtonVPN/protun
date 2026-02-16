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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{CreateUnicastIpAddressEntry, InitializeUnicastIpAddressEntry, MIB_UNICASTIPADDRESS_ROW};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, NldsPreferred};

pub(crate) fn set_adapter_ipv4_address(
    interface_index: u32,
    address: Ipv4Addr,
    prefix_length: u8,
) -> Result<(), WIN32_ERROR> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = create_row(interface_index, prefix_length);
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_addr = IN_ADDR {
        S_un: IN_ADDR_0 {
            S_addr: u32::from_le_bytes(address.octets()),
        },
    };
    set_adapter_ip(&row, interface_index, IpAddr::V4(address), prefix_length)
}

fn create_row(interface_index: u32, prefix_length: u8) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row: MIB_UNICASTIPADDRESS_ROW = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };

    row.InterfaceIndex = interface_index;
    row.DadState = NldsPreferred;
    row.ValidLifetime = 0xffffffff;
    row.PreferredLifetime = 0xffffffff;
    row.OnLinkPrefixLength = prefix_length;

    row
}

fn set_adapter_ip(row: &MIB_UNICASTIPADDRESS_ROW, interface_index: u32, address: IpAddr, prefix_length: u8) -> Result<(), WIN32_ERROR> {
    let status: WIN32_ERROR = unsafe { CreateUnicastIpAddressEntry(row) };
    if status == NO_ERROR {
        log::info!("IP {address}/{prefix_length} set successfully for adapter with index {interface_index}");
        Ok(())
    } else {
        log::error!("IP {address}/{prefix_length} failed to be set for adapter with index {interface_index}. Error status: {}", status.0);
        Err(status)
    }
}

pub(crate) fn set_adapter_ipv6_address(
    interface_index: u32,
    address: Ipv6Addr,
    prefix_length: u8,
) -> Result<(), WIN32_ERROR> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = create_row(interface_index, prefix_length);
    row.Address.si_family = AF_INET6;
    row.Address.Ipv6.sin6_addr = IN6_ADDR {
        u: IN6_ADDR_0 {
            Byte: address.octets(),
        },
    };
    set_adapter_ip(&row, interface_index, IpAddr::V6(address), prefix_length)
}