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

use crate::api::windows::protun_error::ProTunFatalError;
use crate::connection::windows::helpers::local_ip_finder::get_internet_interfaces;
use crate::connection::windows::helpers::routing_table::{self, Ipv4Route, Ipv6Route, Route, add_route, add_v4_route, add_v6_route, delete_route};
use crate::utils::windows::registry_editor::{get_created_routes, set_created_routes};

#[derive(Clone)]
pub(crate) struct Routes {
    interface_index: u32
}

impl Routes {
    /// Creates the following routes:
    /// - Any routes: Mandatory to route all traffic to the ProTUN interface [0.0.0.0/0 => ProTUN]
    /// - Local agent routes: Necessary to route Local Agent traffic correctly in case the device has a 10.0.0.0/8 or 10.X.0.0/16 network that could interfere [10.2.0.1/32 => ProTUN]
    /// - Server routes: Necessary to prevent routing loops when interface forwarding is enabled (ex.: Mobile Hotspot is enabled), routing the VPN server traffic to the internet interface [1.2.3.4/32 => Internet]
    ///   - This last one doesn't leak because our WFP rules only allow our own processes to communicate with the VPN server, everyone else will get their packets dropped
    pub(crate) fn create(server_ipv4_addr: Ipv4Addr, server_ipv6_addr: Option<Ipv6Addr>, interface_index: u32, server_ips: Vec<IpAddr>) -> Result<Self, ProTunFatalError> {
        log::info!("Creating routes");

        _ = add_v4_route(&create_ipv4_local_agent_route(server_ipv4_addr, interface_index));
        _ = add_v4_route(&create_ipv4_any_route(interface_index));

        if let Some(server_ipv6_addr) = server_ipv6_addr {
            _ = add_v6_route(&create_ipv6_local_agent_route(server_ipv6_addr, interface_index));
            _ = add_v6_route(&create_ipv6_any_route(interface_index));
        }

        let mut created_routes: Vec<String> = get_created_routes();
        for route in create_server_routes(server_ips)? {
            if let Ok(_) = add_route(&route) {
                match serde_json::to_string(&route) {
                    Ok(json_route) => created_routes.push(json_route),
                    Err(err) => log::error!("Failed to serialize the route to string. Error: {}", err),
                }
            }
        }
        set_created_routes(created_routes);

        Ok(Routes { interface_index })
    }

    pub(crate) fn delete(&self) {
        log::info!("Deleting routes of interface {} (Step 1 of 2)", self.interface_index);
        routing_table::delete_routes(self.interface_index);

        log::info!("Deleting created routes of internet interface (Step 2 of 2)");
        delete_created_routes();
    }
}

pub fn delete_created_routes() {
    let created_routes: Vec<String> = get_created_routes();
    log::info!("Deleting {} created routes of internet interface", created_routes.len());
    let mut routes_to_reinsert: Vec<String> = vec![];
    for created_route in created_routes {
        match serde_json::from_str::<Route>(&created_route) {
            Ok(route) => {
                if let Err(_) = delete_route(&route) {
                    routes_to_reinsert.push(created_route);
                }
            },
            Err(err) => { // If we failed to deserialize, there is no need to re-insert this route to be deleted later as it will probably fail again
                log::error!("Failed to deserialize the string into a route. Error: {}", err);
            },
        }
    }

    set_created_routes(routes_to_reinsert);
}

fn create_ipv4_local_agent_route(server_ip: Ipv4Addr, interface_index: u32) -> Ipv4Route {
    create_ipv4_host_route(server_ip, None, interface_index)
}

fn create_ipv4_host_route(server_ip: Ipv4Addr, next_hop: Option<Ipv4Addr>, interface_index: u32) -> Ipv4Route {
    Ipv4Route {
        destination_ip_addr: server_ip,
        destination_prefix_length: 32,
        next_hop_address: next_hop,
        interface_index: interface_index
    }
}

fn create_ipv4_any_route(interface_index: u32) -> Ipv4Route {
    Ipv4Route {
        destination_ip_addr: Ipv4Addr::new(0,0,0,0),
        destination_prefix_length: 0,
        next_hop_address: None,
        interface_index: interface_index
    }
}

fn create_ipv6_local_agent_route(server_ip: Ipv6Addr, interface_index: u32) -> Ipv6Route {
    create_ipv6_host_route(server_ip, None, interface_index)
}

fn create_ipv6_host_route(server_ip: Ipv6Addr, next_hop: Option<Ipv6Addr>, interface_index: u32) -> Ipv6Route {
    Ipv6Route {
        destination_ip_addr: server_ip,
        destination_prefix_length: 128,
        next_hop_address: next_hop,
        interface_index: interface_index
    }
}

fn create_ipv6_any_route(interface_index: u32) -> Ipv6Route {
    return Ipv6Route {
        destination_ip_addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        destination_prefix_length: 0,
        next_hop_address: None,
        interface_index: interface_index
    };
}
    
fn create_server_routes(server_ips: Vec<IpAddr>) -> Result<Vec<Route>, ProTunFatalError> {
    let mut result: Vec<Route> = vec![];

    let (ipv4_internet_interface, ipv6_internet_interface) = get_internet_interfaces()?;

    for server_ip in server_ips {
        match server_ip {
            IpAddr::V4(ipv4_server_ip) =>
                if let Some(ref internet_interface) = ipv4_internet_interface {
                    result.push(Route::V4(create_ipv4_host_route(ipv4_server_ip, Some(internet_interface.next_hop), internet_interface.interface_index)))
                },
            IpAddr::V6(ipv6_server_ip) =>
                if let Some(ref internet_interface) = ipv6_internet_interface {
                    result.push(Route::V6(create_ipv6_host_route(ipv6_server_ip, Some(internet_interface.next_hop), internet_interface.interface_index)))
                },
        }
    }

    Ok(result)
}