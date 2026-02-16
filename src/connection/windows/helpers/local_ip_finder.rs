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

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP};
use windows::core::{Error, GUID};
use windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceLuidToGuid, FreeMibTable, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressTable, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE};
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

use crate::api::windows::protun_error::ProTunFatalError;
use crate::connection::windows::helpers::wintun::constants::ADAPTER_GUID;

#[derive(Eq, Hash, PartialEq)]
struct InterfaceLuid(u64);

#[derive(Clone)]
pub(crate) enum InternetInterface {
    V4(Ipv4InternetInterface),
    V6(Ipv6InternetInterface),
}

#[derive(Clone)]
pub(crate) struct Ipv4InternetInterface {
    interface_metric: u32,
    pub(crate) local_ip: Ipv4Addr,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv4Addr,
}

impl Display for Ipv4InternetInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPv4 address {} -> Next hop {} (Interface {}) (Metric {})", self.local_ip, self.next_hop, self.interface_index, self.interface_metric)
    }
}

#[derive(Clone)]
pub(crate) struct Ipv6InternetInterface {
    interface_metric: u32,
    pub(crate) local_ip: Ipv6Addr,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv6Addr,
}

impl Display for Ipv6InternetInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPv6 address {} -> Next hop {} (Interface {}) (Metric {})", self.local_ip, self.next_hop, self.interface_index, self.interface_metric)
    }
}

pub(crate) fn get_ipv4_internet_interface() -> core::result::Result<Option<Ipv4InternetInterface>, ProTunFatalError> {
    let (result, _) = get_internet_interfaces()?;
    if let Some(ipv4interface) = &result {
        log::info!("Internet IPv4 interface: {ipv4interface}");
    }
    Ok(result)
}

pub(crate) fn get_ipv6_internet_interface() -> core::result::Result<Option<Ipv6InternetInterface>, ProTunFatalError> {
    let (_, result) = get_internet_interfaces()?;
    if let Some(ipv6interface) = &result {
        log::info!("Internet IPv6 interface: {ipv6interface}");
    }
    Ok(result)
}

pub(crate) fn get_internet_interfaces() -> core::result::Result<(Option<Ipv4InternetInterface>, Option<Ipv6InternetInterface>), ProTunFatalError> {
    let interfaces: Vec<InternetInterface> = get_potential_internet_interfaces()?;

    let (ipv4_result, ipv6_result) = (interfaces.iter().find_map(|i| {
        if let InternetInterface::V4(v4) = i { Some(v4) } else { None }
    }).cloned(),
    interfaces.iter().find_map(|i| {
        if let InternetInterface::V6(v6) = i { Some(v6) } else { None }
    }).cloned());

    if let Some(ipv4interface) = &ipv4_result {
        log::info!("Internet IPv4 interface: {ipv4interface}");
    }
    if let Some(ipv6interface) = &ipv6_result {
        log::info!("Internet IPv6 interface: {ipv6interface}");
    }    
    
    Ok((ipv4_result, ipv6_result))
}

fn get_potential_internet_interfaces() -> core::result::Result<Vec<InternetInterface>, ProTunFatalError> {
    unsafe {
        let mut routing_table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        GetIpForwardTable2(AF_UNSPEC, &mut routing_table).ok()
            .map_err(|e| ProTunFatalError::NoLocalIp(format!("Error when getting the routing table. Win32 error code: {}", e.code())))?;
        let routes: &[MIB_IPFORWARD_ROW2] = std::slice::from_raw_parts((*routing_table).Table.as_ptr(), (*routing_table).NumEntries as usize);

        let mut ip_addresses_table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        GetUnicastIpAddressTable(AF_UNSPEC, &mut ip_addresses_table).ok()
            .map_err(|e| ProTunFatalError::NoLocalIp(format!("Error when getting the unicast IP address table. Win32 error code: {}", e.code())))?;
        let ip_addresses: &[MIB_UNICASTIPADDRESS_ROW] = std::slice::from_raw_parts((*ip_addresses_table).Table.as_ptr(), (*ip_addresses_table).NumEntries as usize);

        let mut ip_addresses_by_interface_luid: HashMap<InterfaceLuid, Vec<IpAddr>> = HashMap::new();
        for ip_address in ip_addresses {
            if let Ok(ip) = sockaddr_inet_to_ip_addr(&ip_address.Address) {
                ip_addresses_by_interface_luid.entry(InterfaceLuid(ip_address.InterfaceLuid.Value)).or_default().push(ip);
            }
        }

        let mut valid_internet_interfaces: Vec<InternetInterface> = get_internet_interfaces_from_routes(routes, &ip_addresses_by_interface_luid);
        valid_internet_interfaces.sort_by_key(|i| match i { // Sort first by protocol (IPv4 > IPv6) and then by metric (lowest first)
            InternetInterface::V4(iv4) => (4, iv4.interface_metric),
            InternetInterface::V6(iv6) => (6, iv6.interface_metric),
        });

        print_addresses(&valid_internet_interfaces);

        FreeMibTable(routing_table as _);
        FreeMibTable(ip_addresses_table as _);

        if valid_internet_interfaces.is_empty() {
            Err(ProTunFatalError::NoLocalIp("No valid local internet IP addresses".to_string()))
        } else {
            Ok(valid_internet_interfaces)
        }
    }
}

fn print_addresses(valid_internet_interfaces: &[InternetInterface]) {
    for ipvalid_internet_interface in valid_internet_interfaces {
        let (ipaddr, metric) = match ipvalid_internet_interface {
            InternetInterface::V4(ipv4_internet_interface) => (IpAddr::V4(ipv4_internet_interface.local_ip), ipv4_internet_interface.interface_metric),
            InternetInterface::V6(ipv6_internet_interface) => (IpAddr::V6(ipv6_internet_interface.local_ip), ipv6_internet_interface.interface_metric),
        };
        log::info!("- Found IP address {ipaddr} with route metric {metric}");
    }
}

fn get_internet_interfaces_from_routes(routes: &[MIB_IPFORWARD_ROW2], ip_addresses_by_interface_luid: &HashMap<InterfaceLuid, Vec<IpAddr>>) -> Vec<InternetInterface> {
    let mut potential_interfaces: Vec<InternetInterface> = Vec::new();

    for route in routes.iter().filter(|r| r.DestinationPrefix.PrefixLength == 0) {
        let mut route_interface_guid: GUID = GUID::default();
        match unsafe { ConvertInterfaceLuidToGuid(&route.InterfaceLuid, &mut route_interface_guid).ok() } {
            Ok(_) => {
                if route_interface_guid != ADAPTER_GUID {
                    potential_interfaces = [potential_interfaces, get_internet_interfaces_from_route(route, &ip_addresses_by_interface_luid)].concat();
                }
            },
            Err(err) => log::error!("Error when converting interface LUID to GUID: {}", err),
        }
    }

    potential_interfaces
}

fn get_internet_interfaces_from_route(route: &MIB_IPFORWARD_ROW2, ip_addresses_by_interface_luid: &HashMap<InterfaceLuid, Vec<IpAddr>>) -> Vec<InternetInterface> {
    let mut potential_interfaces: Vec<InternetInterface> = Vec::new();

    if let Ok(true) = is_route_interface_up(route) {
        if let Some(ip_addresses) = ip_addresses_by_interface_luid.get(&InterfaceLuid(unsafe { route.InterfaceLuid.Value })) {
            for ip_address in ip_addresses {
                if let Some(interface) = create_internet_interface(route, ip_address) {
                    potential_interfaces.push(interface);
                }
            }
        }
    }

    potential_interfaces
}

fn is_route_interface_up(route: &MIB_IPFORWARD_ROW2) -> windows::core::Result<bool> {
    unsafe {
        let mut row: MIB_IF_ROW2 = MIB_IF_ROW2::default();
        row.InterfaceLuid = route.InterfaceLuid;
        let status: WIN32_ERROR = GetIfEntry2(&mut row);
        if status == NO_ERROR {
            log::info!("Status of the interface with index {} (AdminStatus: {}) (OperStatus: {}) (MediaConnectState: {})",
                route.InterfaceIndex, row.AdminStatus.0, row.OperStatus.0, row.MediaConnectState.0);
            Ok(row.AdminStatus == NET_IF_ADMIN_STATUS_UP && 
               row.OperStatus == IfOperStatusUp && 
               row.MediaConnectState == MediaConnectStateConnected)
        } else {
            log::error!("Error when fetching the status of the interface with index {}", route.InterfaceIndex);
            Err(windows::core::Error::from_win32())
        } 
    }
}

fn create_internet_interface(route: &MIB_IPFORWARD_ROW2, ip_address: &IpAddr) -> Option<InternetInterface> {
    match ip_address {
        IpAddr::V4(ipv4addr) => {
            let next_hop_result = sockaddr_inet_to_ip_addr(&route.NextHop);
            match next_hop_result {
                Ok(IpAddr::V6(_)) => (), // Ignore the IPv6 next hop for an IPv4 interface
                Ok(IpAddr::V4(ipv4_next_hop)) => {
                    if let Ok(interface_metric) = get_ipv4_interface_metric(route) {
                        return Some(InternetInterface::V4(Ipv4InternetInterface {
                            interface_metric,
                            local_ip: *ipv4addr,
                            interface_index: route.InterfaceIndex,
                            next_hop: ipv4_next_hop
                        }));
                    }
                },
                Err(_) => log::warn!("The IPv4 interface {} ({}) does not have a valid Next Hop (Gateway). Next hop result: {:?}", route.InterfaceIndex, ipv4addr, next_hop_result),
            }
        },
        IpAddr::V6(ipv6addr) => {
            let next_hop_result = sockaddr_inet_to_ip_addr(&route.NextHop);
            match next_hop_result {
                Ok(IpAddr::V4(_))=> (), // Ignore the IPv4 next hop for an IPv6 interface
                Ok(IpAddr::V6(ipv6_next_hop)) => {
                    if let Ok(interface_metric) = get_ipv6_interface_metric(route) {
                        return Some(InternetInterface::V6(Ipv6InternetInterface {
                            interface_metric,
                            local_ip: *ipv6addr,
                            interface_index: route.InterfaceIndex,
                            next_hop: ipv6_next_hop
                        }));
                    }
                },
                Err(_) => log::warn!("The IPv6 interface {} ({}) does not have a valid Next Hop (Gateway). Next hop result: {:?}", route.InterfaceIndex, ipv6addr, next_hop_result),
            }
        },
    };

    None
}

fn sockaddr_inet_to_ip_addr(sa: &SOCKADDR_INET) -> windows::core::Result<IpAddr> {
    unsafe {
        match sa.si_family {
            AF_INET => {
                let p = *(sa as *const _ as *const windows::Win32::Networking::WinSock::SOCKADDR_IN);
                Ok(IpAddr::V4(Ipv4Addr::from(u32::from_be(p.sin_addr.S_un.S_addr))))
            }
            AF_INET6 => {
                let p = *(sa as *const _ as *const windows::Win32::Networking::WinSock::SOCKADDR_IN6);
                Ok(IpAddr::V6(Ipv6Addr::from(p.sin6_addr.u.Byte)))
            }
            _ => Err(Error::from_win32()),
        }
    }
}

fn get_ipv4_interface_metric(route: &MIB_IPFORWARD_ROW2) -> windows::core::Result<u32> {
    get_interface_metric(route, AF_INET)
}

fn get_ipv6_interface_metric(route: &MIB_IPFORWARD_ROW2) -> windows::core::Result<u32> {
    get_interface_metric(route, AF_INET6)
}

fn get_interface_metric(route: &MIB_IPFORWARD_ROW2, address_family: ADDRESS_FAMILY) -> windows::core::Result<u32> {
    unsafe {
        let mut row: MIB_IPINTERFACE_ROW = MIB_IPINTERFACE_ROW::default();
        row.Family = address_family;
        row.InterfaceLuid = route.InterfaceLuid;
        let status: WIN32_ERROR = GetIpInterfaceEntry(&mut row);
        if status == NO_ERROR {
            Ok(row.Metric)
        } else {
            log::error!("Error when fetching the interface metric for the interface with index {}", route.InterfaceIndex);
            Err(windows::core::Error::from_win32())
        }
    }
}