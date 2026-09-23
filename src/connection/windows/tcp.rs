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

use pvpnclient::action::SocketOption;
use socket2::{Socket, Domain, Type};
use std::collections::VecDeque;
use std::io::{self, Error, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::windows::io::AsRawSocket;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Networking::WinSock::SOCKET;
use crate::connection::streams::{PendingWrite, Stream, StreamResult, WouldBlock};
use crate::connection::windows::helpers::routes::{VpnServerRouteGuard, VpnServerRouteManager};
use crate::connection::windows::helpers::sockets::SocketInterface;
use crate::connection::windows::streams::{WindowsStream, WindowsStreamState};
use crate::connection::windows::helpers::socket_handle::{SocketEvent, SocketHandle};
use crate::utils::windows::io_error::{Transport, OsErrorToSocketErrorAction, SocketErrorAction};
use crate::utils::windows::network_events::network_observer::NetworkObserver;

pub(crate) struct TcpSocketStream {
    socket: TcpStream,
    interface: SocketInterface,
    _route: VpnServerRouteGuard,
    write_buffer: VecDeque<Vec<u8>>,
    socket_handle: SocketHandle,
    is_readable: bool,
    is_writable: bool,
}

impl TcpSocketStream {
    pub fn new(network_observer: &NetworkObserver, vpn_server_route_manager: &VpnServerRouteManager, remote_socket: SocketAddr) -> io::Result<TcpSocketStream> {
        let (tcp_stream, socket_interface, route) = create(network_observer, vpn_server_route_manager, remote_socket)?;
        let raw_socket: SOCKET = SOCKET(tcp_stream.as_raw_socket() as usize);
        match SocketHandle::new(raw_socket) {
            Ok(handle) => Ok(TcpSocketStream {
                socket: tcp_stream,
                interface: socket_interface,
                _route: route,
                write_buffer: VecDeque::new(),
                socket_handle: handle,
                is_readable: false,
                is_writable: false,
            }),
            Err(error) => Err(error),
        }
    }
}

fn create(network_observer: &NetworkObserver, vpn_server_route_manager: &VpnServerRouteManager, remote_socket_address: SocketAddr) -> io::Result<(TcpStream, SocketInterface, VpnServerRouteGuard)> {
    match remote_socket_address {
        SocketAddr::V4(ipv4_addr) => {
            if let Some(ipv4_interface) = network_observer.get_ipv4_internet_interface() {
                let interface: SocketInterface = SocketInterface::new_ipv4(&ipv4_interface);
                let stream: TcpStream = create_stream(Domain::IPV4, &interface, remote_socket_address)?;
                let route: VpnServerRouteGuard = vpn_server_route_manager.create_ipv4(*ipv4_addr.ip(), ipv4_interface)?;
                Ok((stream, interface, route))
            } else {
                return Err(Error::new(ErrorKind::NetworkUnreachable, "Can't find an IPv4 internet interface"));
            }
        },
        SocketAddr::V6(ipv6_addr) => {
            if let Some(ipv6_interface) = network_observer.get_ipv6_internet_interface() {
                let interface: SocketInterface = SocketInterface::new_ipv6(&ipv6_interface);
                let stream: TcpStream = create_stream(Domain::IPV6, &interface, remote_socket_address)?;
                let route: VpnServerRouteGuard = vpn_server_route_manager.create_ipv6(*ipv6_addr.ip(), ipv6_interface)?;
                Ok((stream, interface, route))
            } else {
                return Err(Error::new(ErrorKind::NetworkUnreachable, "Can't find an IPv6 internet interface"));
            }
        }
    }
}

fn create_stream(ip_family_domain: Domain, local_socket_interface: &SocketInterface, remote_socket_address: SocketAddr) -> io::Result<TcpStream> {
    let socket: Socket = match Socket::new(ip_family_domain, Type::STREAM, None) {
        Ok(tcp_socket) => tcp_socket,
        Err(err) => {
            log::error!("Failed to create '{:?}' TCP socket: {}", ip_family_domain, err);
            return Err(err);
        }
    };

    log::info!("Binding TCP stream to local {local_socket_interface} and connect to {remote_socket_address}");

    if let Err(err) = socket.bind(&local_socket_interface.address.into()) {
        log::error!("Failed to bind the TCP socket to local {local_socket_interface}: {}", err);
        return Err(err)
    };
    if let Err(err) = socket.set_nonblocking(true) {
        log::error!("Failed to set the TCP socket as non-blocking: {}", err);
        return Err(err);
    };
    if let Err(err) = socket.connect(&remote_socket_address.into()) && err.kind() != ErrorKind::WouldBlock {
        log::error!("Failed to connect with TCP to remote socket {remote_socket_address}: {}", err);
        return Err(err)
    };
    
    let tcp_stream: TcpStream = socket.into();
    log::info!("Created TCP stream ({}->{})", local_socket_interface, remote_socket_address);
    Ok(tcp_stream)
}

impl WindowsStream for TcpSocketStream {
    fn get_interface(&self) -> &SocketInterface {
        &self.interface
    }

    fn handle(&mut self) -> HANDLE {
        self.socket_handle.handle
    }

    fn has_error(&self) -> bool {
        match self.socket.take_error() {
            Ok(Some(err)) => {
                log::error!("Error on TCP stream: {:?}", err);
                true
            },
            Err(err) => {
                log::error!("Error when fetching TCP stream error: {:?}", err);
                true
            },
            _ => false,
        }
    }
    
    fn get_state(&mut self) -> WindowsStreamState {
        let events: SocketEvent = self.socket_handle.get_events();
        
        self.is_readable = self.is_readable || events.is_readable;
        self.is_writable = self.is_writable || events.is_writable;

        WindowsStreamState {
            is_readable: self.is_readable,
            is_writable: self.is_writable,
        }
    }
}

impl Stream for TcpSocketStream {
    fn read(&mut self, buf: &mut [u8]) -> StreamResult {
        let ret: Result<usize, Error> = self.socket.read(buf);
        let pending_write: PendingWrite = (!self.write_buffer.is_empty()).into();
        match ret {
            Ok(bytes_count) => {
                if bytes_count == 0 {
                    self.is_readable = false;
                    StreamResult::StreamClosed
                } else {
                    self.is_readable = true;
                    StreamResult::ok(bytes_count, WouldBlock::No, pending_write)
                }
            },
            Err(e) => {
                self.is_readable = false;
                match e.to_socket_error_action(Transport::TCP) {
                    SocketErrorAction::FatalSocketError => StreamResult::Err(e),
                    SocketErrorAction::WouldBlock => StreamResult::ok(0, WouldBlock::Yes, pending_write),
                }
            }
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        self.write_buffer.push_back(data);
        self.write_from_buffer()
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        let mut bytes_written = 0;
        loop {
            let data = self.write_buffer.pop_front();
            let Some(data) = data else {
                self.is_writable = true;
                return StreamResult::ok(bytes_written, WouldBlock::No, PendingWrite::No);
            };
            let result = self.socket.write(&data);
            match result {
                Ok(count) => {
                    bytes_written += count;
                    if count < data.len() {
                        self.write_buffer.push_front(data[count..].to_vec());
                    }
                }
                Err(e) => {
                    self.write_buffer.push_front(data);
                    self.is_writable = false;
                    return match e.to_socket_error_action(Transport::TCP) {
                        SocketErrorAction::FatalSocketError => StreamResult::Err(e),
                        SocketErrorAction::WouldBlock => StreamResult::ok(bytes_written, WouldBlock::Yes, PendingWrite::Yes),
                    }
                }
            }
        }
    }

    fn shutdown_write(&mut self) {
        let _ = self.socket.shutdown(Shutdown::Write);
    }

    fn set_option(&mut self, _: &SocketOption) {
        // TODO: implement
    }
}

impl Drop for TcpSocketStream {
    fn drop(&mut self) {
        log::info!("Dropping TcpSocketStream");
    }
}