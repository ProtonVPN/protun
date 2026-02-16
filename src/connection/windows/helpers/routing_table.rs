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

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_OBJECT_NOT_FOUND, NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{CreateIpForwardEntry2, DeleteIpForwardEntry2, FreeMibTable, GetIpForwardTable2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2};
use windows::Win32::Networking::WinSock::{ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_INET};

#[derive(Serialize, Deserialize, Clone)]
pub(crate) enum Route {
    V4(Ipv4Route),
    V6(Ipv6Route),
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Ipv4Route {
    pub(crate) destination_ip_addr: Ipv4Addr,
    pub(crate) destination_prefix_length: u8,
    pub(crate) next_hop_address: Option<Ipv4Addr>,
    pub(crate) interface_index: u32,
}

impl fmt::Display for Ipv4Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let next_hop_address: String = match self.next_hop_address {
            Some(next_hop_address) => next_hop_address.to_string(),
            None => "On-link".to_string(),
        };
        write!(f, "{}/{} -> {} interface {}", self.destination_ip_addr, self.destination_prefix_length, next_hop_address, self.interface_index)
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct Ipv6Route {
    pub(crate) destination_ip_addr: Ipv6Addr,
    pub(crate) destination_prefix_length: u8,
    pub(crate) next_hop_address: Option<Ipv6Addr>,
    pub(crate) interface_index: u32,
}

impl fmt::Display for Ipv6Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let next_hop_address: String = match self.next_hop_address {
            Some(next_hop_address) => next_hop_address.to_string(),
            None => "On-link".to_string(),
        };
        write!(f, "{}/{} -> {} interface {}", self.destination_ip_addr, self.destination_prefix_length, next_hop_address, self.interface_index)
    }
}

pub(crate) enum RouteCreationError {
    AlreadyExists,
    ProtocolDisabled,
    Unknown { _message: String }
}

pub(crate) enum RouteDeletionSuccess {
    Deleted,
    NotFound,
}

pub fn add_route(route: &Route) -> Result<(), RouteCreationError> {
    match route {
        Route::V4(ipv4_route) => add_v4_route(ipv4_route),
        Route::V6(ipv6_route) => add_v6_route(ipv6_route),
    }
}

pub fn add_v4_route(route: &Ipv4Route) -> Result<(), RouteCreationError> {
    let row: MIB_IPFORWARD_ROW2 = create_ipv4_mib_ipforward_row(&route);
    let result: WIN32_ERROR = unsafe { CreateIpForwardEntry2(&row) };

    match result {
        NO_ERROR => {
            log::info!("IPv4 Route added successfully: {}", &route.to_string());
            Ok(())
        },
        ERROR_OBJECT_ALREADY_EXISTS => {
            log::info!("IPv4 Route not added because it already exists: {}", route);
            Err(RouteCreationError::AlreadyExists)
        },
        _ => {
            log::error!("Error '{}' when adding IPv4 route: {}", result.0, route);
            Err(RouteCreationError::Unknown { _message: result.0.to_string() })
        },
    }
}

fn create_ipv4_mib_ipforward_row(route: &Ipv4Route) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.DestinationPrefix.PrefixLength = route.destination_prefix_length;
    row.DestinationPrefix.Prefix.si_family = ADDRESS_FAMILY(AF_INET.0 as u16);
    row.DestinationPrefix.Prefix.Ipv4.sin_addr = IN_ADDR {
        S_un: IN_ADDR_0 {
            S_addr: u32::from_le_bytes(route.destination_ip_addr.octets()),
        },
    };
    
    if let Some(next_hop_address) = route.next_hop_address {
        row.NextHop.Ipv4.sin_family = ADDRESS_FAMILY(AF_INET.0 as u16);
        row.NextHop.Ipv4.sin_addr = IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from_le_bytes(next_hop_address.octets()),
            },
        };
    }

    row.InterfaceIndex = route.interface_index;
    row.Metric = 1;

    row
}

pub fn add_v6_route(route: &Ipv6Route) -> Result<(), RouteCreationError> {
    let row: MIB_IPFORWARD_ROW2 = create_ipv6_mib_ipforward_row(&route);
    let result: WIN32_ERROR = unsafe { CreateIpForwardEntry2(&row) };

    match result {
        NO_ERROR => {
            log::info!("IPv6 Route added successfully: {}", route);
            Ok(())
        },
        ERROR_OBJECT_ALREADY_EXISTS => {
            log::info!("IPv6 Route not added because it already exists: {}", route);
            Err(RouteCreationError::AlreadyExists)
        },
        ERROR_NOT_FOUND => {
            log::warn!("IPv6 Route not added because IPv6 is disabled: {}", route);
            Err(RouteCreationError::ProtocolDisabled)
        },
        _ => {
            log::error!("Error '{}' when adding IPv6 route: {}", result.0, route);
            Err(RouteCreationError::Unknown { _message: result.0.to_string() })
        },
    }
}

fn create_ipv6_mib_ipforward_row(route: &Ipv6Route) -> MIB_IPFORWARD_ROW2 {
    let mut row: MIB_IPFORWARD_ROW2 = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };

    row.DestinationPrefix.PrefixLength = route.destination_prefix_length;
    row.DestinationPrefix.Prefix.si_family = ADDRESS_FAMILY(AF_INET6.0 as u16);
    row.DestinationPrefix.Prefix.Ipv6.sin6_addr = IN6_ADDR {
        u: IN6_ADDR_0 {
            Byte: route.destination_ip_addr.octets(),
        },
    };

    if let Some(next_hop_address) = route.next_hop_address {
        row.NextHop.Ipv6.sin6_family = ADDRESS_FAMILY(AF_INET6.0 as u16);
        row.NextHop.Ipv6.sin6_addr = IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: next_hop_address.octets(),
            },
        };
    }

    row.InterfaceIndex = route.interface_index;
    row.Metric = 1;

    row
}

pub fn delete_route(route: &Route) -> Result<RouteDeletionSuccess, String> {
    match route {
        Route::V4(ipv4_route) => delete_v4_route(ipv4_route),
        Route::V6(ipv6_route) => delete_v6_route(ipv6_route),
    }
}

pub fn delete_v4_route(route: &Ipv4Route) -> Result<RouteDeletionSuccess, String> {
    let row: MIB_IPFORWARD_ROW2 = create_ipv4_mib_ipforward_row(&route);
    let result: WIN32_ERROR = unsafe { DeleteIpForwardEntry2(&row) };

    match result {
        WIN32_ERROR(0) => {
            log::info!("IPv4 route deleted successfully: {}", route);
            Ok(RouteDeletionSuccess::Deleted)
        },
        ERROR_OBJECT_NOT_FOUND => {
            log::info!("IPv4 route already doesn't exist: {}", route);
            Ok(RouteDeletionSuccess::NotFound)
        },
        _ => {
            log::error!("Error '{}' when deleting IPv4 route: {}", result.0, route);
            Err(result.0.to_string())
        },
    }
}

pub fn delete_v6_route(route: &Ipv6Route) -> Result<RouteDeletionSuccess, String> {
    let row: MIB_IPFORWARD_ROW2 = create_ipv6_mib_ipforward_row(&route);
    let result: WIN32_ERROR = unsafe { DeleteIpForwardEntry2(&row) };

    match result {
        WIN32_ERROR(0) => {
            log::info!("IPv6 route deleted successfully: {}", route);
            Ok(RouteDeletionSuccess::Deleted)
        },
        ERROR_OBJECT_NOT_FOUND => {
            log::info!("IPv6 route already doesn't exist: {}", route);
            Ok(RouteDeletionSuccess::NotFound)
        },
        _ => {
            log::error!("Error '{}' when deleting IPv6 route: {}", result.0, route);
            Err(result.0.to_string())
        },
    }
}

pub fn delete_routes(interface_index: u32) -> Vec<Result<RouteDeletionSuccess, String>> {
    let interface_rows: Vec<MIB_IPFORWARD_ROW2> = get_interface_rows(interface_index);
    let mut results: Vec<Result<RouteDeletionSuccess, String>> = vec![];
    
    for row in interface_rows {
        let result: WIN32_ERROR = unsafe { DeleteIpForwardEntry2(&row) };
        results.push(match result {
            WIN32_ERROR(0) => {
                log::info!("Route of interface {interface_index} deleted successfully: {}", row_to_string(&row));
                Ok(RouteDeletionSuccess::Deleted)
            },
            ERROR_OBJECT_NOT_FOUND => {
                log::info!("Route of interface {interface_index} already doesn't exist: {}", row_to_string(&row));
                Ok(RouteDeletionSuccess::NotFound)
            },
            _ => {
                log::error!("Error '{}' when deleting route of interface {interface_index}: {}", result.0, row_to_string(&row));
                Err(result.0.to_string())
            },
        });
    }
    results
}

fn get_interface_rows(interface_index: u32) -> Vec<MIB_IPFORWARD_ROW2> {
    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();

    let error: WIN32_ERROR = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table_ptr) };
    if error != NO_ERROR || table_ptr.is_null() {
        log::error!("Failed to get the routing table: {}", windows::core::Error::from_win32());
        return vec![];
    }

    let table: &MIB_IPFORWARD_TABLE2 = unsafe { &*table_ptr };
    let count: usize = table.NumEntries as usize;
    let first_row: *const MIB_IPFORWARD_ROW2 = table.Table.as_ptr();
    let rows: &[MIB_IPFORWARD_ROW2] = unsafe { std::slice::from_raw_parts(first_row, count) };

    let filtered: Vec<MIB_IPFORWARD_ROW2> = rows
        .iter()
        .cloned()
        .filter(|r| r.InterfaceIndex == interface_index)
        .collect();

    unsafe { FreeMibTable(table_ptr as _) };

    filtered
}

fn row_to_string(row: &MIB_IPFORWARD_ROW2) -> String {
    format!("{}/{} -> {} interface {} (Metric {})",
        sockaddr_to_string(row.DestinationPrefix.Prefix),
        row.DestinationPrefix.PrefixLength,
        sockaddr_to_string(row.NextHop),
        row.InterfaceIndex,
        row.Metric)
}

fn sockaddr_to_string(ip: SOCKADDR_INET) -> String {
    unsafe {
        match ip.si_family {
            AF_INET => {
                let octets: [u8; _] = ip.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes();
                let ipv4: Ipv4Addr = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
                ipv4.to_string()
            },
            AF_INET6 => {
                let words: [u16; 8] = ip.Ipv6.sin6_addr.u.Word;
                let ipv6: Ipv6Addr = Ipv6Addr::new(words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7]);
                ipv6.to_string()
            },
            _ => "".to_string(),
        }
    }
}