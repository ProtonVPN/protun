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
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, Weak};
use crate::connection::windows::helpers::internet_interface_finder::{Ipv4InternetInterface, Ipv6InternetInterface};
use crate::connection::windows::helpers::windows_api::routing_table::{self, Ipv4Route, Ipv6Route, Route, add_route, add_v4_route, add_v6_route, delete_route};
use crate::utils::windows::luid::Luid;
use crate::utils::windows::registry_editor::{get_stored_routes, set_stored_routes};

// The VpnServerRouteManager and VpnServerRouteGuard exist because it should be possible to create multiple sockets to
// the same VPN server, but we can only have one route in the routing table for a given IP address. Without this, we
// could have the following issue: Creating two sockets for the same VPN server, then dropping one of those socket
// which would trigger a route deletion, which would affect negatively the other socket that was not deleted.
// A Mutex exists to ensure the create and delete operations occur atomically.
type RoutesHashMap = Mutex<HashMap<IpAddr, Weak<VpnServerRoute>>>;

#[derive(Clone)]
pub(crate) struct VpnServerRouteManager {
    routes: Arc<RoutesHashMap>,
}

pub(crate) struct VpnServerRouteGuard {
    key: IpAddr,
    route: Option<Arc<VpnServerRoute>>, // Option so we can drop the Arc while holding the lock inside Drop
    routes: Weak<RoutesHashMap>, // Weak so a VpnServerRouteGuard doesn't keep the RoutesHashMap of VpnServerRouteManager alive
}

impl fmt::Display for VpnServerRouteGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let route: String = match &self.route {
            Some(route) => route.route.to_string(),
            None => "None".to_string(),
        };
        write!(f, "Route guard for IP {} (Route: {})", self.key, route)
    }
}

impl VpnServerRouteManager {
    pub(crate) fn new() -> Self {
        Self { routes: Arc::new(Mutex::new(HashMap::new())) }
    }

    pub(crate) fn create_ipv4(&self, server_ip: Ipv4Addr, internet_interface: Ipv4InternetInterface) -> std::io::Result<VpnServerRouteGuard> {
        self.acquire(IpAddr::V4(server_ip), || VpnServerRoute::create_ipv4(server_ip, internet_interface))
    }

    pub(crate) fn create_ipv6(&self, server_ip: Ipv6Addr, internet_interface: Ipv6InternetInterface) -> std::io::Result<VpnServerRouteGuard> {
        self.acquire(IpAddr::V6(server_ip), || VpnServerRoute::create_ipv6(server_ip, internet_interface))
    }

    fn acquire(&self, ip_addr: IpAddr, route_creator: impl FnOnce() -> VpnServerRoute) -> std::io::Result<VpnServerRouteGuard> {
        let mut routes = self.routes.lock().map_err(|err| on_lock_acquisition_error(&ip_addr, err.to_string()))?;

        let route: Arc<VpnServerRoute> = match routes.get(&ip_addr).and_then(Weak::upgrade) {
            Some(route) => {
                log::info!("Cloned existing VpnServerRoute for IP {ip_addr}");
                route
            },
            None => {
                log::info!("Creating new VpnServerRoute for IP {ip_addr}");
                let route: Arc<VpnServerRoute> = Arc::new(route_creator());
                routes.insert(ip_addr, Arc::downgrade(&route));
                route
            }
        };

        Ok(VpnServerRouteGuard {
            key: ip_addr,
            route: Some(route),
            routes: Arc::downgrade(&self.routes),
        })
    }
}

fn on_lock_acquisition_error(ip_addr: &IpAddr, err: String) -> std::io::Error {
    let msg = format!("Failed to obtain lock of the route manager hash map when acquiring for IP {ip_addr}: {err}");
    log::error!("{msg}");
    std::io::Error::new(std::io::ErrorKind::Other, msg)
}

impl Drop for VpnServerRouteGuard {
    fn drop(&mut self) {
        let Some(routes) = self.routes.upgrade() else { 
            // When upgrade fails, it means the manager was already dropped, and:
            // 1) We don't need to sync the code with a Mutex as there is no HashMap to keep in sync,
            // 2) We don't need to remove the route from the HashMap as there is no HashMap,
            // 3) The route will get dropped, unsynced, on this return (If it's the last instance of the Arc)
            log::info!("VpnServerRouteManager already dropped. Dropping VpnServerRouteGuard without a lock. {self}");
            return
        };

        let mut map = match routes.lock() {
            Ok(map) => map,
            Err(err) => {
                log::error!("{self} failed to obtain lock of the route manager hash map when releasing for : {err}");
                return;
            }
        };

        log::info!("Dropping VpnServerRouteGuard while holding the lock. {self}");

        let Some(route) = self.route.take() else { return }; // Take the Arc of the route, so we can manually drop it while holding the Mutex lock

        if Arc::strong_count(&route) == 1 {
            log::info!("This is last instance of the Route, removing it from the HashMap. Route guard for IP {} (Route: {})", self.key, route.route);
            map.remove(&self.key);
        }

        drop(route); // Manually drop the route while holding the Mutex lock
    }
}

pub(crate) struct TunRoutes {
    interface_luid: Luid
}

pub(crate) struct VpnServerRoute {
    route: Route
}

impl Drop for VpnServerRoute {
    fn drop(&mut self) {
        self.delete();
    }
}

pub(crate) fn delete_all_stored_routes() {
    log::info!("Deleting stored routes of internet interface");
    delete_stored_routes();
}

impl TunRoutes {
    /// Creates the following routes, all forwarded to the TUN interface:
    /// - Any routes: Mandatory to route all traffic to the ProTUN interface \[0.0.0.0/0 => ProTUN\]
    /// - Local agent routes: Necessary to route Local Agent traffic correctly in case the device has a 10.0.0.0/8 or 10.X.0.0/16 network that could interfere \[10.2.0.1/32 => ProTUN\]
    pub(crate) fn create(server_tunnel_ipv4_addr: Ipv4Addr, server_tunnel_ipv6_addr: Option<Ipv6Addr>, tun_interface_luid: Luid) -> TunRoutes {
        log::info!("Creating TUN routes");

        _ = add_v4_route(&create_ipv4_local_agent_route(server_tunnel_ipv4_addr, tun_interface_luid));
        _ = add_v4_route(&create_ipv4_default_route(tun_interface_luid));

        for route in &create_ipv4_split_default_routes(tun_interface_luid) {
            _ = add_v4_route(route);
        }

        if let Some(server_ipv6_addr) = server_tunnel_ipv6_addr {
            _ = add_v6_route(&create_ipv6_local_agent_route(server_ipv6_addr, tun_interface_luid));
            _ = add_v6_route(&create_ipv6_default_route(tun_interface_luid));
            
            for route in &create_ipv6_split_default_routes(tun_interface_luid) {
                _ = add_v6_route(route);
            }
        }

        log::info!("TUN routes created");

        TunRoutes { interface_luid: tun_interface_luid }
    }
    
    pub(crate) fn delete(&self) {
        log::info!("Deleting routes of interface {}", self.interface_luid);
        routing_table::delete_interface_routes(self.interface_luid);
    }
}

impl VpnServerRoute {
    /// Creates the VPN Server route, necessary to prevent routing loops when interface forwarding is enabled (ex.: Mobile Hotspot is enabled), 
    /// routing the VPN server traffic to the internet interface \[1.2.3.4/32 => Internet\]
    /// Note: No leaks occur because our WFP rules only allow our own processes to communicate with the VPN server, everything else will get their packets dropped
    pub(crate) fn create_ipv4(server_ip: Ipv4Addr, internet_interface: Ipv4InternetInterface) -> Self {
        log::info!("Creating VPN server route (Server IPv4: {server_ip}, Internet interface: {internet_interface})");
        let route: Route = create_ipv4_server_route(server_ip, &internet_interface);
        handle_stored_route(&route);
        VpnServerRoute { route }
    }

    /// Creates the VPN Server route, necessary to prevent routing loops when interface forwarding is enabled (ex.: Mobile Hotspot is enabled), 
    /// routing the VPN server traffic to the internet interface \[1234:5678:ABCD::/128 => Internet\]
    /// Note: No leaks occur because our WFP rules only allow our own processes to communicate with the VPN server, everything else will get their packets dropped
    pub(crate) fn create_ipv6(server_ip: Ipv6Addr, internet_interface: Ipv6InternetInterface) -> Self {
        log::info!("Creating VPN server route (Server IPv6: {server_ip}, Internet interface: {internet_interface})");
        let route: Route = create_ipv6_server_route(server_ip, &internet_interface);
        handle_stored_route(&route);
        VpnServerRoute { route }
    }

    fn delete(&mut self) {
        log::info!("Deleting VPN server route: {}", self.route);

        if let Ok(_) = delete_route(&self.route) {
            log::info!("Route successfully deleted from the routing table. Deleting the stored route: {}", self.route);
            Self::remove_from_stored_routes(&self);
        }
    }

    fn remove_from_stored_routes(&self) {
        let mut stored_routes: Vec<String> = get_stored_routes();
        stored_routes.retain(|stored_route| {
            match serde_json::from_str::<Route>(&stored_route) {
                Ok(route) => {
                    route != self.route
                },
                Err(err) => { // If we failed to deserialize, there is no need to re-insert this route to be deleted later as it will probably fail again
                    log::error!("Failed to deserialize the string into a route. Error: {}", err);
                    false
                },
            }
        });
        set_stored_routes(stored_routes);
    }
}

fn handle_stored_route(route: &Route) {
    if let Ok(_) = add_route(&route) {
        match serde_json::to_string(&route) {
            Ok(json_route) => { 
                let mut stored_routes: Vec<String> = get_stored_routes();
                if !stored_routes.contains(&json_route) {
                    stored_routes.push(json_route);
                    set_stored_routes(stored_routes);
                }
            },
            Err(err) => log::error!("Failed to serialize the route to string ({route}). Error: {}", err),
        }
    }
}

fn delete_stored_routes() {
    let stored_routes: Vec<String> = get_stored_routes();
    log::info!("Deleting {} stored routes of internet interface", stored_routes.len());
    let mut routes_to_reinsert: Vec<String> = vec![];
    for stored_route in stored_routes {
        match serde_json::from_str::<Route>(&stored_route) {
            Ok(route) => {
                if let Err(_) = delete_route(&route) {
                    routes_to_reinsert.push(stored_route);
                }
            },
            Err(err) => { // If we failed to deserialize, there is no need to re-insert this route to be deleted later as it will probably fail again
                log::error!("Failed to deserialize the string into a route. Error: {}", err);
            },
        }
    }

    set_stored_routes(routes_to_reinsert);
}

fn create_ipv4_local_agent_route(server_ip: Ipv4Addr, interface_luid: Luid) -> Ipv4Route {
    create_ipv4_host_route(server_ip, None, interface_luid)
}

fn create_ipv4_host_route(server_ip: Ipv4Addr, next_hop: Option<Ipv4Addr>, interface_luid: Luid) -> Ipv4Route {
    Ipv4Route {
        destination_ip_addr: server_ip,
        destination_prefix_length: 32,
        next_hop_address: next_hop,
        interface_luid: interface_luid
    }
}

fn create_ipv4_default_route(interface_luid: Luid) -> Ipv4Route {
    Ipv4Route {
        destination_ip_addr: Ipv4Addr::new(0,0,0,0),
        destination_prefix_length: 0,
        next_hop_address: None,
        interface_luid: interface_luid
    }
}

fn create_ipv4_split_default_routes(interface_luid: Luid) -> Vec<Ipv4Route> {
    vec![
        Ipv4Route {
            destination_ip_addr: Ipv4Addr::new(0,0,0,0),
            destination_prefix_length: 1,
            next_hop_address: None,
            interface_luid: interface_luid
        },
        Ipv4Route {
            destination_ip_addr: Ipv4Addr::new(128,0,0,0),
            destination_prefix_length: 1,
            next_hop_address: None,
            interface_luid: interface_luid
        }
    ]
}

fn create_ipv6_local_agent_route(server_ip: Ipv6Addr, interface_luid: Luid) -> Ipv6Route {
    create_ipv6_host_route(server_ip, None, interface_luid)
}

fn create_ipv6_host_route(server_ip: Ipv6Addr, next_hop: Option<Ipv6Addr>, interface_luid: Luid) -> Ipv6Route {
    Ipv6Route {
        destination_ip_addr: server_ip,
        destination_prefix_length: 128,
        next_hop_address: next_hop,
        interface_luid: interface_luid
    }
}

fn create_ipv6_default_route(interface_luid: Luid) -> Ipv6Route {
    return Ipv6Route {
        destination_ip_addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
        destination_prefix_length: 0,
        next_hop_address: None,
        interface_luid: interface_luid
    };
}

fn create_ipv6_split_default_routes(interface_luid: Luid) -> Vec<Ipv6Route> {
    vec![
        Ipv6Route {
            destination_ip_addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            destination_prefix_length: 1,
            next_hop_address: None,
            interface_luid: interface_luid
        },
        Ipv6Route {
            destination_ip_addr: Ipv6Addr::new(0x8000u16, 0, 0, 0, 0, 0, 0, 0),
            destination_prefix_length: 1,
            next_hop_address: None,
            interface_luid: interface_luid
        }
    ]
}

fn create_ipv4_server_route(server_ip: Ipv4Addr, internet_interface: &Ipv4InternetInterface) -> Route {
    Route::V4(create_ipv4_host_route(server_ip, Some(internet_interface.next_hop), internet_interface.interface_luid))
}

fn create_ipv6_server_route(server_ip: Ipv6Addr, internet_interface: &Ipv6InternetInterface) -> Route {
    Route::V6(create_ipv6_host_route(server_ip, Some(internet_interface.next_hop), internet_interface.interface_luid))
}