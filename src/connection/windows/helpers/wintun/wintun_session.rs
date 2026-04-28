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
use std::sync::Arc;
use windows::Win32::Foundation::WIN32_ERROR;
use wintun::{Adapter, Session, Wintun};
use crate::api::connection::IpAddress;
use crate::api::windows::connection_windows::AdapterConfig;
use crate::api::windows::protun_error::ProTunFatalError;
use crate::connection::windows::helpers::windows_api::adapter_configs::{set_ipv4_adapter_configurations, set_ipv6_adapter_configurations};
use crate::connection::windows::helpers::windows_api::dns::{set_adapter_ipv4_dns_servers, set_adapter_ipv6_dns_servers};
use crate::connection::windows::helpers::windows_api::ipv6::{disable_adapter_ipv6, enable_adapter_ipv6};
use crate::connection::windows::helpers::windows_api::local_address::{set_adapter_ipv4_address, set_adapter_ipv6_address};
use crate::connection::windows::helpers::routes::Routes;
use crate::connection::windows::helpers::wintun::constants::{ADAPTER_DESCRIPTION, ADAPTER_GUID, ADAPTER_GUID_U128, ADAPTER_NAME, WINTUN_FILE_NAME};
use crate::utils::common::option_ipv6addr_to_string;
use crate::utils::vector::VecIpAddress;

pub struct WinTunSession {
    adapter: Arc<Adapter>,
    pub(crate) session: Arc<Session>,
    pub interface_index: u32,
    pub client_ipv4_addr: Ipv4Addr,
    pub server_ipv4_addr: Ipv4Addr,
    pub client_ipv6_addr: Option<Ipv6Addr>,
    pub server_ipv6_addr: Option<Ipv6Addr>,
    routes: Routes,
}

impl WinTunSession {
    pub fn create(server_ips: Vec<IpAddr>, adapter_config: AdapterConfig) -> Result<Self, ProTunFatalError> {
        let buffer_size_bytes: u32 = Self::get_valid_wintun_buffer_size(adapter_config.buffer_size_bytes);

        log::info!("Creating WinTUN adapter (Buffer size: {} bytes)", buffer_size_bytes);
        let adapter: Arc<Adapter> = Self::create_wintun_adapter()?;
        let interface_index: u32 = adapter.get_adapter_index()
            .map_err(|e| ProTunFatalError::WintunAdapterIndexFetchFailed(format!("Failed to get the Wintun adapter index. Error: {e}")))?;
        
        log::info!("WinTUN uses interface with index {interface_index}");

        _ = set_ipv4_adapter_configurations(interface_index, adapter_config.mtu);
        if adapter_config.is_ipv6_enabled {
            _ = enable_adapter_ipv6();
            _ = set_ipv6_adapter_configurations(interface_index, adapter_config.mtu);
        } else {
            _ = disable_adapter_ipv6();
        };
        
        let (client_ipv4_addr, client_ipv6_addr) = set_adapter_ip_addresses(interface_index)?;
        let (server_ipv4_addr, server_ipv6_addr) = calculate_and_set_dns_servers(adapter_config.custom_dns_server_ips, client_ipv4_addr, client_ipv6_addr);

        let routes: Routes = Routes::create(server_ipv4_addr, server_ipv6_addr, interface_index, server_ips)?;

        let session: Arc<Session> = Arc::new(adapter.start_session(buffer_size_bytes)
            .map_err(|e| ProTunFatalError::WintunSessionCreationFailed(format!("Failed to create the Wintun session. Error: {e}")))?);
        
        log::info!("WinTUN initialization complete");
        Ok(WinTunSession {
            adapter: adapter,
            session: session,
            interface_index: interface_index,
            client_ipv4_addr: client_ipv4_addr,
            server_ipv4_addr: server_ipv4_addr,
            client_ipv6_addr: client_ipv6_addr,
            server_ipv6_addr: server_ipv6_addr,
            routes: routes
        })
    }
    
    fn get_valid_wintun_buffer_size(proposed_size: u32) -> u32 {
        let valid_size: u32 = proposed_size
            .checked_next_power_of_two()
            .unwrap_or(wintun::MAX_RING_CAPACITY)
            .clamp(wintun::MIN_RING_CAPACITY, wintun::MAX_RING_CAPACITY);

        if valid_size != proposed_size {
            log::error!("The provided WinTUN ring capacity of {proposed_size} is invalid as it is either below the minimum, 
                above the maximum, or not a power of two. The value is going to be set for the best closest value: {valid_size}");
        }

        valid_size
    }

    fn create_wintun_adapter() -> Result<Arc<Adapter>, ProTunFatalError> {
        let wintun: Wintun = unsafe { wintun::load_from_path(WINTUN_FILE_NAME) }
            .map_err(|e| ProTunFatalError::WintunLibraryLoadingFailed(format!("Failed to load WinTUN DLL. Error: {e}")))?;

        match Adapter::open(&wintun, ADAPTER_NAME) {
            Ok(a) => Ok(a),
            Err(_) => {
                match Adapter::create(
                    &wintun,
                    ADAPTER_NAME,
                    ADAPTER_DESCRIPTION,
                    Some(ADAPTER_GUID_U128),
                ) {
                    Ok(adapter) => Ok(adapter),
                    Err(e) => {
                        log::error!("Could not create the WinTUN adapter. {e}");
                        Err(ProTunFatalError::WintunInterfaceCreationFailed(format!("Could not create the WinTUN adapter. Error: {}", e)))
                    }
                }
            }
        }
    }
    
    pub fn disable_ipv6(&self) -> Result<(), String> {
        disable_adapter_ipv6()
    }

    pub fn enable_ipv6(&self) -> Result<(), String> {
        enable_adapter_ipv6()
    }
    
    pub fn set_dns_servers(&self, custom_dns_server_ips: Vec<IpAddress>) -> Result<(), WIN32_ERROR> {
        set_dns_servers(custom_dns_server_ips, self.server_ipv4_addr, self.server_ipv6_addr)
    }
}

fn set_adapter_ip_addresses(interface_index: u32) -> Result<(Ipv4Addr, Option<Ipv6Addr>), ProTunFatalError> {
    log::info!("Setting adapter IP addresses");

    // Attempts to set the Wintun network interface with IP 10.2.0.2, if it fails, will try 10.3.0.2, and so on...
    for i in 2..=255 {
        let client_ipv4_addr: Ipv4Addr = Ipv4Addr::new(10, i, 0, 2);
        match set_adapter_ipv4_address(interface_index, client_ipv4_addr, 32) {
            Ok(_) => (),
            Err(_) => continue,
        }

        let client_ipv6_addr: Ipv6Addr = Ipv6Addr::new(0x2a07, 0xb944, 0, 0, 0, 0, i.into(), 0x2);
        let client_ipv6_addr_result: Option<Ipv6Addr> = match set_adapter_ipv6_address(interface_index, client_ipv6_addr, 128) {
            Ok(_) => Some(client_ipv6_addr),
            Err(_) => None,
        };

        log::info!("Adapter IP addresses set successfully (IPv4 '{client_ipv4_addr}') (IPv6 '{}')", option_ipv6addr_to_string(&client_ipv6_addr_result));
        return Ok((client_ipv4_addr, client_ipv6_addr_result));
    }

    const ERR_MSG: &str = "Could not set valid IP addresses for the WinTUN adapter.";
    log::error!("{ERR_MSG}");
    Err(ProTunFatalError::WintunIpAddressSetupFailed(format!("{ERR_MSG}")))
}

fn calculate_and_set_dns_servers(custom_dns_server_ips: Vec<IpAddress>, client_ipv4_addr: Ipv4Addr, client_ipv6_addr: Option<Ipv6Addr>) -> (Ipv4Addr, Option<Ipv6Addr>) {
    let server_ipv4_addr: Ipv4Addr = Ipv4Addr::new(10, client_ipv4_addr.octets()[1], 0, 1);
    
    let server_ipv6_addr: Option<Ipv6Addr> = match client_ipv6_addr {
        Some(ipv6addr) => Some(Ipv6Addr::new(0x2a07, 0xb944, 0, 0, 0, 0, ipv6addr.segments()[6], 0x1)),
        None => None,
    };
    _ = set_dns_servers(custom_dns_server_ips, server_ipv4_addr, server_ipv6_addr);

    (server_ipv4_addr, server_ipv6_addr)
}

fn set_dns_servers(custom_dns_server_ips: Vec<IpAddress>, server_ipv4_addr: Ipv4Addr, server_ipv6_addr_option: Option<Ipv6Addr>) -> Result<(), WIN32_ERROR> {
    let (mut ipv4_dns_servers, mut ipv6_dns_servers) = custom_dns_server_ips.split_ips_by_protocol();

    set_ipv4_dns_servers(&mut ipv4_dns_servers, server_ipv4_addr)?;

    if let Some(server_ipv6_addr) = server_ipv6_addr_option {
        set_ipv6_dns_servers(&mut ipv6_dns_servers, server_ipv6_addr)?;
        log::info!("Successfully set adapter IPv4 and IPv6 DNS servers (IPv4: '{:?}') (IPv6 '{:?}')", &ipv4_dns_servers, &ipv6_dns_servers);
    } else {
        log::info!("Successfully set adapter IPv4 DNS servers ('{:?}')", &ipv4_dns_servers);
    };
    Ok(())
}

fn set_ipv4_dns_servers(dns_server_ips: &mut Vec<Ipv4Addr>, server_addr: Ipv4Addr) -> Result<(), WIN32_ERROR> {
    dns_server_ips.push(server_addr);
    set_adapter_ipv4_dns_servers(ADAPTER_GUID, dns_server_ips)?;
    Ok(())
}

fn set_ipv6_dns_servers(dns_server_ips: &mut Vec<Ipv6Addr>, server_addr: Ipv6Addr) -> Result<(), WIN32_ERROR> {
    dns_server_ips.push(server_addr);
    set_adapter_ipv6_dns_servers(ADAPTER_GUID, dns_server_ips)?;
    Ok(())
}

impl Drop for WinTunSession {
    fn drop(&mut self) {
        log::info!("Dropping WinTun");
        self.routes.delete();
        log::info!("Shutting down WinTun sessions");
        shutdown_session(&self.session);
    }
}

fn shutdown_session(session: &Arc<Session>) {
    match session.shutdown() {
        Ok(_) => log::info!("Successfully shutdown Wintun session"),
        Err(e) => log::error!("Failed to shutdown Wintun session: {e}"),
    }
}