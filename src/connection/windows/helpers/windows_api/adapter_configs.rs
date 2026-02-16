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

use windows::Win32::Foundation::{NO_ERROR, WIN32_ERROR};
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, RouterDiscoveryDisabled};
use windows::Win32::NetworkManagement::IpHelper::{GetIpInterfaceEntry, MIB_IPINTERFACE_ROW, SetIpInterfaceEntry};

pub const MINIMUM_MTU: u16 = 576;
pub const DEFAULT_MTU: u16 = 1420;

pub(crate) fn set_ipv4_adapter_configurations(interface_index: u32, mtu: u16) -> Result<(), WIN32_ERROR> {
    let mut row: MIB_IPINTERFACE_ROW = create_row(interface_index, mtu, AF_INET)?;

    // Documentation says: "However for IPv4, an application must not try to modify the SitePrefixLength member of the MIB_IPINTERFACE_ROW structure. For IPv4, the SitePrefixLength member must be set to 0."
    // Source: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry
    // If this parameter is not set to zero, the API call to SetIpInterfaceEntry() will fail with the error ERROR_INVALID_PARAMETER
    row.SitePrefixLength = 0;

    set_adapter_configurations(&mut row)
}

fn create_row(interface_index: u32, mtu: u16, ip_family: ADDRESS_FAMILY) -> Result<MIB_IPINTERFACE_ROW, WIN32_ERROR> {
    let mut row: MIB_IPINTERFACE_ROW = MIB_IPINTERFACE_ROW::default();
    row.Family = ip_family;
    row.InterfaceIndex = interface_index;

    // Get current configurations to preserve the other fields
    let status: WIN32_ERROR = unsafe { GetIpInterfaceEntry(&mut row) };
    if status.0 != 0 {
        return Err(status);
    }

    row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
    row.DadTransmits = 0;
    row.ManagedAddressConfigurationSupported = false;
    row.OtherStatefulConfigurationSupported = false;
    row.NlMtu = get_valid_mtu(mtu).into();
    row.UseAutomaticMetric = false;
    row.Metric = 0;

    Ok(row)
}

fn get_valid_mtu(mtu: u16) -> u16 {
    if mtu < MINIMUM_MTU {
        DEFAULT_MTU
    } else {
        mtu
    }
}

fn set_adapter_configurations(row: &mut MIB_IPINTERFACE_ROW) -> Result<(), WIN32_ERROR> {
    let status: WIN32_ERROR = unsafe { SetIpInterfaceEntry(row) };
    if status == NO_ERROR {
        log::info!("IP interface configurations set successfully");
        Ok(())
    } else {
        log::error!("Setting IP interface configurations failed with error status: {}", status.0);
        Err(status)
    }
}

pub(crate) fn set_ipv6_adapter_configurations(interface_index: u32, mtu: u16) -> Result<(), WIN32_ERROR> {
    let mut row: MIB_IPINTERFACE_ROW = create_row(interface_index, mtu, AF_INET6)?;
    set_adapter_configurations(&mut row)
}