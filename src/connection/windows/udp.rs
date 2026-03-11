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

use crate::connection::streams::{Stream, StreamResult};
use crate::connection::windows::helpers::local_ip_finder::{get_ipv4_internet_interface, get_ipv6_internet_interface};
use crate::connection::windows::streams::{WindowsStream, WindowsStreamState};
use crate::connection::windows::helpers::socket_handle::{SocketEvent, SocketHandle};
use std::io::{self, Error, ErrorKind};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::windows::io::AsRawSocket;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Networking::WinSock::SOCKET;

pub(crate) struct UdpSocketStream {
    socket: UdpSocket,
    socket_handle: SocketHandle,
    is_readable: bool,
    is_writable: bool,
}
impl UdpSocketStream {
    pub fn new(remote_socket_address: SocketAddr) -> io::Result<UdpSocketStream> {
        let udp_socket: UdpSocket = Self::create_udp_socket(remote_socket_address)?;
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

    fn create_udp_socket(remote_socket_address: SocketAddr) -> io::Result<UdpSocket> {
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
        log::trace!("Attempting to read from UDP socket");
        let ret = self.socket.recv(buf);
        match ret {
            Ok(bytes_count) => {
                log::trace!("Read {bytes_count} bytes from UDP socket");
                self.is_readable = true;
                StreamResult::ok(bytes_count, false, false)
            },
            Err(e) => {
                log::trace!("Error when read from UDP socket {:?}", e);
                self.is_readable = false;
                if e.kind() == io::ErrorKind::WouldBlock {
                    StreamResult::ok(0, true, false)
                } else {
                    StreamResult::Err(e)
                }
            }
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        log::trace!("Attempting to write to UDP socket ({} bytes)", data.len());
        let ret = self.socket.send(&data);
        match ret {
            Ok(size) => {
                self.is_writable = true;
                if size < data.len() {
                    log::debug!("UDP send truncated: Sent {size} out of {} bytes", data.len());
                } else {
                    log::trace!("Successfuly wrote to UDP socket ({size} bytes)");
                }
                StreamResult::ok(size, false, false)
            }
            Err(e) => {
                log::trace!("Error when writing to UDP socket {:?}", e);
                self.is_writable = false;
                if e.kind() == io::ErrorKind::WouldBlock {
                    StreamResult::ok(0, true, false)
                } else {
                    StreamResult::Err(e)
                }
            }
        }
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        StreamResult::ok(0, false, false)
    }
}

impl Drop for UdpSocketStream {
    fn drop(&mut self) {
        log::info!("UdpSocketStream dropped");
    }
}