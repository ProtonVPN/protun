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

use crate::api::windows::connection_windows::SocketConfig;
use crate::connection::streams::{PendingWrite, Stream, StreamResult, WouldBlock};
use crate::connection::windows::helpers::local_ip_finder::{get_ipv4_internet_interface, get_ipv6_internet_interface};
use crate::connection::windows::streams::{WindowsStream, WindowsStreamState};
use crate::connection::windows::helpers::socket_handle::{SocketEvent, SocketHandle};
use crate::utils::windows::io_error::{Transport, OsErrorToSocketErrorAction, SocketErrorAction};
use std::io::{self, Error, ErrorKind};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::windows::io::AsRawSocket;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Networking::WinSock::SOCKET;
use windows::Win32::Networking::WinSock::{SIO_UDP_CONNRESET, WSAIoctl};

pub(crate) struct UdpSocketStream {
    socket: UdpSocket,
    socket_handle: SocketHandle,
    is_readable: bool,
    is_writable: bool,
}

impl UdpSocketStream {
    pub fn new(remote_socket_address: SocketAddr, socket_config: &SocketConfig) -> io::Result<UdpSocketStream> {
        let udp_socket: UdpSocket = Self::create_udp_socket(remote_socket_address, socket_config)?;
        let raw_socket: SOCKET = SOCKET(udp_socket.as_raw_socket() as usize);
        match SocketHandle::new(raw_socket) {
            Ok(handle) => Ok(UdpSocketStream {
                socket: udp_socket,
                socket_handle: handle,
                is_readable: false,
                is_writable: false
            }),
            Err(error) => Err(error),
        }
    }

    fn create_udp_socket(remote_socket_address: SocketAddr, socket_config: &SocketConfig) -> io::Result<UdpSocket> {
        let local_socket_address: SocketAddr = match remote_socket_address {
            SocketAddr::V4(_) => {
                if let Ok(Some(interface)) = get_ipv4_internet_interface() {
                    let socket_addr_v4: SocketAddrV4 = SocketAddrV4::new(interface.local_ip, 0);
                    SocketAddr::V4(socket_addr_v4)
                } else {
                    return Err(Error::new(ErrorKind::AddrNotAvailable, "Can't find an IPv4 internet interface"));
                }
            },
            SocketAddr::V6(_) => {
                if let Ok(Some(interface)) = get_ipv6_internet_interface() {
                    let socket_addr_v6: SocketAddrV6 = SocketAddrV6::new(interface.local_ip, 0, 0, 0);
                    SocketAddr::V6(socket_addr_v6)
                } else {
                    return Err(Error::new(ErrorKind::AddrNotAvailable, "Can't find an IPv6 internet interface"));
                }
            },
        };
        log::info!("Binding UDP socket to local {local_socket_address} and connect to {remote_socket_address}");
        let udp_socket: UdpSocket = match UdpSocket::bind(local_socket_address) {
            Ok(udp_socket) => udp_socket,
            Err(err) => {
                log::error!("Failed to bind UDP socket to local {local_socket_address}: {}", err);
                return Err(err);
            }
        };
        if let Err(err) = Self::disable_connection_reset(&udp_socket) {
            log::error!("Failed to disable connection resets in the UDP socket: {}", err);
            return Err(err)
        }
        let udp_socket: UdpSocket = Self::set_buffer_sizes(udp_socket, socket_config);
        if let Err(err) = udp_socket.set_nonblocking(true) {
            log::error!("Failed to set the UDP socket as non-blocking: {}", err);
            return Err(err)
        };
        if let Err(err) = udp_socket.connect(remote_socket_address) {
            log::error!("Failed to connect with UDP to remote socket {remote_socket_address}: {}", err);
            return Err(err)
        };

        log::info!("Created UDP socket ({}->{})", local_socket_address, remote_socket_address);

        Ok(udp_socket)
    }

    fn disable_connection_reset(udp_socket: &UdpSocket) -> Result<(), io::Error> {
        let handle: usize = udp_socket.as_raw_socket().try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, format!("The u64 handle does not fit into usize"))
        })?;
        let is_enabled: u32 = 0; // disable reporting
        let mut bytes_returned: u32 = 0;
        let ret = unsafe {
            WSAIoctl(
                SOCKET(handle),
                SIO_UDP_CONNRESET,
                Some(&is_enabled as *const _ as *const _),
                std::mem::size_of::<u32>() as u32,
                None,
                0,
                &mut bytes_returned,
                None,
                None,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        log::info!("Disabled connection resets for the UDP socket");
        Ok(())
    }
    
    fn set_buffer_sizes(udp_socket: UdpSocket, socket_config: &SocketConfig) -> UdpSocket {
        log::info!("Setting UDP socket buffer sizes. [Send: {} bytes] [Receive: {} bytes]",
            socket_config.send_buffer_size_bytes, socket_config.receive_buffer_size_bytes);

        let udp_socket2: socket2::Socket = socket2::Socket::from(udp_socket);
        if let Err(err) = udp_socket2.set_send_buffer_size(socket_config.send_buffer_size_bytes as usize) {
            log::error!("Failed to set the UDP socket send buffer size to {}: {}", socket_config.send_buffer_size_bytes, err);
        }
        if let Err(err) = udp_socket2.set_recv_buffer_size(socket_config.receive_buffer_size_bytes as usize) {
            log::error!("Failed to set the UDP socket receive buffer size to {}: {}", socket_config.receive_buffer_size_bytes, err);
        }
        UdpSocket::from(udp_socket2)
    }
}

impl WindowsStream for UdpSocketStream {
    fn handle(&mut self) -> HANDLE {
        self.socket_handle.handle
    }

    fn has_error(&self) -> bool {
        match self.socket.take_error() {
            Ok(None) => false,
            Ok(Some(err)) => {
                log::error!("Error on UDP socket: {:?}", err);
                true
            },
            Err(err) => {
                log::error!("Error when fetching UDP socket error: {:?}", err);
                true
            },
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
impl Stream for UdpSocketStream {
    fn read(&mut self, buf: &mut [u8]) -> StreamResult {
        let ret = self.socket.recv(buf);
        match ret {
            Ok(bytes_count) => {
                self.is_readable = true;
                StreamResult::ok(bytes_count, WouldBlock::No, PendingWrite::No)
            },
            Err(e) => {
                log::debug!("Error when reading from UDP socket {:?}", e);
                self.is_readable = false;
                match e.to_socket_error_action(Transport::UDP) {
                    SocketErrorAction::FatalSocketError => StreamResult::Err(e),
                    SocketErrorAction::WouldBlock => StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No),
                }
            }
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        let ret = self.socket.send(&data);
        match ret {
            Ok(size) => {
                self.is_writable = true;
                if size < data.len() {
                    log::debug!("UDP send truncated: Sent {size} out of {} bytes", data.len());
                }
                StreamResult::ok(size, WouldBlock::No, PendingWrite::No)
            }
            Err(e) => {
                log::debug!("Error when writing to UDP socket {:?}", e);
                self.is_writable = false;
                match e.to_socket_error_action(Transport::UDP) {
                    SocketErrorAction::FatalSocketError => StreamResult::Err(e),
                    SocketErrorAction::WouldBlock => StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No),
                }
            }
        }
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        StreamResult::ok(0, WouldBlock::No, PendingWrite::No)
    }
}

impl Drop for UdpSocketStream {
    fn drop(&mut self) {
        log::info!("UdpSocketStream dropped");
    }
}