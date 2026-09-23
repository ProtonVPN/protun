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
use std::fmt::{Display, Formatter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows::Win32::Foundation::{NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP};
use windows::core::{Error, GUID};
use windows::Win32::NetworkManagement::IpHelper::{ConvertInterfaceLuidToGuid, FreeMibTable, GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressTable, IF_TYPE_PROP_VIRTUAL, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE};
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IpDadStatePreferred, SOCKADDR_INET};

use crate::connection::windows::helpers::wintun::constants::ADAPTER_GUID;
use crate::utils::windows::luid::Luid;

#[derive(Eq, Hash, PartialEq)]
struct InterfaceLuid(u64);

#[derive(Clone)]
pub(crate) struct InternetInterfaces {
    pub(crate) v4: Option<Ipv4InternetInterface>,
    pub(crate) v6: Option<Ipv6InternetInterface>
}

impl InternetInterfaces {
    pub fn new() -> InternetInterfaces {
        InternetInterfaces { v4: None, v6: None }
    }

    pub fn is_up(&self) -> bool {
        self.v4.is_some() || self.v6.is_some()
    }

    pub fn is_down(&self) -> bool {
        self.v4.is_none() && self.v6.is_none()
    }

    pub fn get_state_as_string(&self) -> String {
        if self.is_up() { "up" } else { "down" }.to_string()
    }
}

impl Display for InternetInterfaces {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let v4_interface_string: String = match &self.v4 {
            Some(v4) => format!("{v4}"),
            None => "None".to_string(),
        };
        let v6_interface_string: String = match &self.v6 {
            Some(v6) => format!("{v6}"),
            None => "None".to_string(),
        };

        write!(f, "(IPv4: {v4_interface_string}, IPv6: {v6_interface_string})")
    }
}

#[derive(Clone)]
pub(crate) enum InternetInterface {
    V4(Ipv4InternetInterface),
    V6(Ipv6InternetInterface),
}

impl Display for InternetInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InternetInterface::V4(ipv4_internet_interface) => write!(f, "{ipv4_internet_interface}"),
            InternetInterface::V6(ipv6_internet_interface) => write!(f, "{ipv6_internet_interface}"),
        }
    }
}

#[derive(Clone)]
pub(crate) struct Ipv4InternetInterface {
    interface_metric: u32,
    default_route_metric: u32,
    pub(crate) local_ip: Ipv4Addr,
    pub(crate) interface_luid: Luid,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv4Addr,
    is_virtual: bool
}

impl Ipv4InternetInterface {
    fn effective_metric(&self) -> u32 {
        self.interface_metric + self.default_route_metric
    }
}

impl Display for Ipv4InternetInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPv4 address {} -> Next hop {} (Interface - LUID: {}, Index: {}) (Effective Metric {} = Interface Metric {} + Default Route Metric {}) Virtual: {}",
            self.local_ip, self.next_hop, self.interface_luid, self.interface_index,
            self.effective_metric(), self.interface_metric, self.default_route_metric, self.is_virtual)
    }
}

#[derive(Clone)]
pub(crate) struct Ipv6InternetInterface {
    interface_metric: u32,
    default_route_metric: u32,
    pub(crate) local_ip: Ipv6Addr,
    pub(crate) interface_luid: Luid,
    pub(crate) interface_index: u32,
    pub(crate) next_hop: Ipv6Addr,
    is_virtual: bool
}

impl Ipv6InternetInterface {
    fn effective_metric(&self) -> u32 {
        self.interface_metric + self.default_route_metric
    }
}

impl Display for Ipv6InternetInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "IPv6 address {} -> Next hop {} (Interface - LUID: {}, Index: {}) (Effective Metric {} = Interface Metric {} + Default Route Metric {}) Virtual: {}",
            self.local_ip, self.next_hop, self.interface_luid, self.interface_index,
            self.effective_metric(), self.interface_metric, self.default_route_metric, self.is_virtual)
    }
}

pub enum InterfaceFinderLogMode {
    ErrorsOnly,
    Verbose { caller_name: String },
}

impl InterfaceFinderLogMode {
    pub fn create_verbose(caller_name: &str) -> Self {
        InterfaceFinderLogMode::Verbose { caller_name: caller_name.to_string() }
    }
}

pub(crate) fn get_internet_interfaces(log_mode: &InterfaceFinderLogMode) -> InternetInterfaces {
    match get_potential_internet_interfaces(log_mode) {
        Some(interfaces) => {
            let (ipv4_result, ipv6_result) = (
                interfaces.iter().find_map(|i| {
                    if let InternetInterface::V4(v4) = i { Some(v4) } else { None }
                }).cloned(),
                interfaces.iter().find_map(|i| {
                    if let InternetInterface::V6(v6) = i { Some(v6) } else { None }
                }).cloned()
            ); 
            
            InternetInterfaces { v4: ipv4_result, v6: ipv6_result }
        },
        None => InternetInterfaces::new(),
    }
}

fn get_potential_internet_interfaces(log_mode: &InterfaceFinderLogMode) -> Option<Vec<InternetInterface>> {
    unsafe {
        let mut routing_table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
        if let Err(e) = GetIpForwardTable2(AF_UNSPEC, &mut routing_table).ok() {
            log::error!("Error when getting the routing table. Win32 error code: {}", e.code());
            return None;
        }
        let routes: &[MIB_IPFORWARD_ROW2] = std::slice::from_raw_parts((*routing_table).Table.as_ptr(), (*routing_table).NumEntries as usize);

        let mut ip_addresses_table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
        if let Err(e) = GetUnicastIpAddressTable(AF_UNSPEC, &mut ip_addresses_table).ok() {
            log::error!("Error when getting the unicast IP address table. Win32 error code: {}", e.code());
            return None;
        }
        let ip_addresses: &[MIB_UNICASTIPADDRESS_ROW] = std::slice::from_raw_parts((*ip_addresses_table).Table.as_ptr(), (*ip_addresses_table).NumEntries as usize);

        let mut ip_addresses_by_interface_luid: HashMap<InterfaceLuid, Vec<IpAddr>> = HashMap::new();
        for ip_address in ip_addresses {
            if ip_address.DadState != IpDadStatePreferred {
                continue;
            }
            if let Ok(ip) = sockaddr_inet_to_ip_addr(&ip_address.Address) {
                ip_addresses_by_interface_luid.entry(InterfaceLuid(ip_address.InterfaceLuid.Value)).or_default().push(ip);
            }
        }

        let mut valid_internet_interfaces: Vec<InternetInterface> = get_internet_interfaces_from_routes(routes, &ip_addresses_by_interface_luid);

        // Sort first by protocol (IPv4 > IPv6), then by if virtual (preferrence goes to non-virtual), and then by metric (lowest first)
        valid_internet_interfaces.sort_by_key(|i| match i {
            InternetInterface::V4(v4if) => (4, v4if.is_virtual, v4if.effective_metric()),
            InternetInterface::V6(v6if) => (6, v6if.is_virtual, v6if.effective_metric()),
        });

        print_addresses(log_mode, &valid_internet_interfaces);

        FreeMibTable(routing_table as _);
        FreeMibTable(ip_addresses_table as _);

        if valid_internet_interfaces.is_empty() {
            None
        } else {
            Some(valid_internet_interfaces)
        }
    }
}

fn print_addresses(log_mode: &InterfaceFinderLogMode, valid_internet_interfaces: &[InternetInterface]) {
    if let InterfaceFinderLogMode::Verbose { caller_name } = log_mode {
        let log_message: String = match valid_internet_interfaces.is_empty() {
            true => format!("No available internet interfaces as requested by '{caller_name}'."),
            false => {
                let mut log_message: String = format!("Available internet interfaces as requested by '{caller_name}':");

                for ipvalid_internet_interface in valid_internet_interfaces {
                    let (ipaddr, interface_luid, interface_index, is_virtual, interface_metric, 
                        default_route_metric, effective_metric) = match ipvalid_internet_interface {
                        InternetInterface::V4(ipv4_internet_interface) => (
                            IpAddr::V4(ipv4_internet_interface.local_ip),
                            ipv4_internet_interface.interface_luid,
                            ipv4_internet_interface.interface_index,
                            ipv4_internet_interface.is_virtual,
                            ipv4_internet_interface.interface_metric,
                            ipv4_internet_interface.default_route_metric,
                            ipv4_internet_interface.effective_metric()),
                        InternetInterface::V6(ipv6_internet_interface) => (
                            IpAddr::V6(ipv6_internet_interface.local_ip),
                            ipv6_internet_interface.interface_luid,
                            ipv6_internet_interface.interface_index,
                            ipv6_internet_interface.is_virtual,
                            ipv6_internet_interface.interface_metric,
                            ipv6_internet_interface.default_route_metric,
                            ipv6_internet_interface.effective_metric()),
                    };

                    _ = write!(log_message, "\n- Interface (LUID: {interface_luid}, Index: {interface_index}), IP: {ipaddr}, Is virtual: {is_virtual}, \
                        Effective Metric {effective_metric} (Interface Metric {interface_metric} + Default Route Metric {default_route_metric})");
                }

                log_message
            }
        };
        
        log::info!("{log_message}");
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

    if let Ok(interface_metadata) = get_route_interface_metadata(route) && interface_metadata.is_up {
        if let Some(ip_addresses) = ip_addresses_by_interface_luid.get(&InterfaceLuid(unsafe { route.InterfaceLuid.Value })) {
            for ip_address in ip_addresses {
                if let Some(interface) = create_internet_interface(route, ip_address, &interface_metadata) {
                    potential_interfaces.push(interface);
                }
            }
        }
    }

    potential_interfaces
}

struct InterfaceMetadata {
    is_up: bool,
    is_virtual: bool
}

fn get_route_interface_metadata(route: &MIB_IPFORWARD_ROW2) -> windows::core::Result<InterfaceMetadata> {
    unsafe {
        let mut row: MIB_IF_ROW2 = MIB_IF_ROW2::default();
        row.InterfaceLuid = route.InterfaceLuid;
        let status: WIN32_ERROR = GetIfEntry2(&mut row);
        if status == NO_ERROR {
            log::debug!("Status of the interface with index {} (AdminStatus: {}) (OperStatus: {}) (MediaConnectState: {})",
                route.InterfaceIndex, row.AdminStatus.0, row.OperStatus.0, row.MediaConnectState.0);
            Ok(InterfaceMetadata {
                is_up: row.AdminStatus == NET_IF_ADMIN_STATUS_UP && row.OperStatus == IfOperStatusUp && row.MediaConnectState == MediaConnectStateConnected,
                is_virtual: row.Type == IF_TYPE_PROP_VIRTUAL })
        } else {
            log::error!("Error when fetching the status of the interface with index {}", route.InterfaceIndex);
            Err(windows::core::Error::from_win32())
        } 
    }
}

fn create_internet_interface(route: &MIB_IPFORWARD_ROW2, ip_address: &IpAddr, interface_metadata: &InterfaceMetadata) -> Option<InternetInterface> {
    match ip_address {
        IpAddr::V4(ipv4addr) => {
            let next_hop_result = sockaddr_inet_to_ip_addr(&route.NextHop);
            match next_hop_result {
                Ok(IpAddr::V6(_)) => (), // Ignore the IPv6 next hop for an IPv4 interface
                Ok(IpAddr::V4(ipv4_next_hop)) => {
                    if let Ok(interface_metric) = get_ipv4_interface_metric(route) {
                        return Some(InternetInterface::V4(Ipv4InternetInterface {
                            interface_metric,
                            default_route_metric: route.Metric,
                            local_ip: *ipv4addr,
                            interface_luid: route.InterfaceLuid.into(),
                            interface_index: route.InterfaceIndex,
                            next_hop: ipv4_next_hop,
                            is_virtual: interface_metadata.is_virtual
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
                            default_route_metric: route.Metric,
                            local_ip: *ipv6addr,
                            interface_luid: route.InterfaceLuid.into(),
                            interface_index: route.InterfaceIndex,
                            next_hop: ipv6_next_hop,
                            is_virtual: interface_metadata.is_virtual
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