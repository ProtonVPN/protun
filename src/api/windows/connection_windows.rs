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

use std::io;
use std::io::{Error, ErrorKind};
use std::net::IpAddr;
use std::sync::Arc;
use pvpnclient::os_interface::rand::CryptoSeedProvider;

use crate::api::connection::{EventCallback, IpAddress};
use crate::api::windows::protun_error::ProTunFatalError;
use crate::api::windows::state_changed_callback::WindowsStateChangedCallback;
use crate::connection::pvpn_client::PvpnClientImpl;
use crate::connection::time::{ClientMonotonicFactory, ClientRealtimeFactory};
use crate::connection::windows::helpers::poll_waker::WindowsPollWaker;
use crate::connection::windows::helpers::routes::delete_created_routes;
use crate::connection::windows::streams::WindowsStreams;
use crate::connection::windows::tun_windows::TunStreamWindows;
use crate::connection::windows::helpers::winsock::Winsock;
use crate::api::{connection::{Connection, InitialConnectionConfig, StateChangedCallback}};
use crate::api::logger::{init_logger, ClientLogger, LogLevel};
use crate::connection::pvpn_connection::PvpnDependencies;
use crate::connection::streams::Streams;
use crate::connection::windows::helpers::wintun::wintun_session::WinTunSession;
use crate::utils::common::option_ipv6addr_to_string;


#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
#[derive(Clone)]
pub struct ProTun {
    /// Needed to terminate Winsock. On drop, Winsock gets dropped, which calls WSACleanup()
    _winsock: Winsock,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone)]
pub struct ProTunAdapterDetails {
    pub interface_index: u32,
    pub client_ipv4_addr: String,
    pub server_ipv4_addr: String,
    pub client_ipv6_addr: String,
    pub server_ipv6_addr: String
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl ProTun {

    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn initialize(
        log_level: LogLevel,
        logger_callback: Box<dyn ClientLogger>,
    ) -> Result<Self, ProTunFatalError> {
        init_logger(log_level, logger_callback);
        log::info!("Initialized ProTUN");
        
        let winsock: Winsock = Winsock::create()?;

        Ok(ProTun { _winsock: winsock })
    }

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn delete_routes(&self) {
        delete_created_routes();
    }
}

impl Drop for ProTun {
    fn drop(&mut self) {
        log::info!("Dropping ProTun");
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct NetworkConfig {
    pub tun_adapter: AdapterConfig,
    pub udp_socket: SocketConfig,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct AdapterConfig {
    pub custom_dns_server_ips: Vec<IpAddress>,
    pub is_ipv6_enabled: bool,
    pub mtu: u16,
    pub buffer_size_bytes: u32,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct SocketConfig {
    pub send_buffer_size_bytes: u32,
    pub receive_buffer_size_bytes: u32,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct WindowsConnection {
    connection: Arc<Connection>,
    tun: Arc<WinTunSession>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl WindowsConnection {

    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn connect(
        connection_config: InitialConnectionConfig,
        network_config: NetworkConfig,
        client_state_change_callback: Box<dyn StateChangedCallback>,
        event_callback: Box<dyn EventCallback>
    ) -> Result<Self, ProTunFatalError> {
        let server_ips: Vec<IpAddr> = connection_config.peers.iter().map(|peer| peer.server_ip.0).collect();
        let tun: Arc<WinTunSession> = Arc::new(WinTunSession::create(server_ips, network_config.tun_adapter)?);

        let waker: Box<WindowsPollWaker> = Box::new(WindowsStreams::create_waker()?);
        let tun_clone: Arc<WinTunSession> = tun.clone();
        let state_change_callback: Box<dyn StateChangedCallback> =
            Box::new(WindowsStateChangedCallback::new(client_state_change_callback));
        let connection: Arc<Connection> = Arc::new(Connection::connect_internal(
            waker.clone(),
            move || {
                create_pvpn_dependencies(
                    waker,
                    connection_config,
                    network_config.udp_socket,
                    tun_clone,
                    state_change_callback,
                    event_callback,
                )
            }
        ));

        Ok(WindowsConnection { connection, tun })
    }

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn get_connection(&self) -> Arc<Connection> {
        self.connection.clone()
    }
    
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn get_adapter_details(&self) -> ProTunAdapterDetails {
        ProTunAdapterDetails {
            interface_index: self.tun.interface_index,
            client_ipv4_addr: self.tun.client_ipv4_addr.to_string(),
            server_ipv4_addr: self.tun.server_ipv4_addr.to_string(),
            client_ipv6_addr: option_ipv6addr_to_string(&self.tun.client_ipv6_addr),
            server_ipv6_addr: option_ipv6addr_to_string(&self.tun.server_ipv6_addr)
        }
    }
    
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn set_ipv6(&self, is_enabled: bool) -> Result<bool, ProTunFatalError> {
        Ok(if is_enabled {
            self.tun.enable_ipv6()
        } else {
            self.tun.disable_ipv6()
        }.is_ok())
    }

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn set_dns(&self, custom_dns_server_ips: Vec<IpAddress>) -> Result<bool, ProTunFatalError> {
        Ok(self.tun.set_dns_servers(custom_dns_server_ips).is_ok())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        log::info!("Dropping Connection");
    }
}

impl Drop for WindowsConnection {
    fn drop(&mut self) {
        log::info!("Dropping Windows Connection");
    }
}

fn create_pvpn_dependencies(
    waker: Box<WindowsPollWaker>,
    config: InitialConnectionConfig,
    udp_socket_config: SocketConfig,
    tun: Arc<WinTunSession>,
    state_change_callback: Box<dyn StateChangedCallback>,
    event_callback: Box<dyn EventCallback>,
) -> Result<PvpnDependencies, io::Error> {
    let tun_stream: Box<TunStreamWindows> = Box::new(TunStreamWindows::new(tun)
        .map_err(|e| Error::new(ErrorKind::Other, format!("Failed to create streams: {e}")))?);
    let streams: Box<dyn Streams> = Box::new(WindowsStreams::new(tun_stream, waker, udp_socket_config));

    let client = Box::new(
        PvpnClientImpl::new(
            ClientMonotonicFactory::new(),
            ClientRealtimeFactory::new(),
            config.connection_mode.to_pvpn_client_mode()?,
            || CryptoSeedProvider::new(rand::rng()).into()
        )?
    );

    Ok(
        PvpnDependencies {
            config,
            streams,
            client,
            state_change_callback,
            event_callback,
        }
    )
}