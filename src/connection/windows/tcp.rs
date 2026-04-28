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
use std::net::{Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};
use std::os::windows::io::AsRawSocket;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Networking::WinSock::SOCKET;
use crate::connection::streams::{PendingWrite, Stream, StreamResult, WouldBlock};
use crate::connection::windows::helpers::local_ip_finder::{get_ipv4_internet_interface, get_ipv6_internet_interface};
use crate::connection::windows::streams::{WindowsStream, WindowsStreamState};
use crate::connection::windows::helpers::socket_handle::{SocketEvent, SocketHandle};
use crate::utils::windows::io_error::{Transport, OsErrorToSocketErrorAction, SocketErrorAction};

pub(crate) struct TcpSocketStream {
    socket: TcpStream,
    write_buffer: VecDeque<Vec<u8>>,
    socket_handle: SocketHandle,
    is_readable: bool,
    is_writable: bool,
}

impl TcpSocketStream {
    pub fn new(remote_socket: SocketAddr) -> io::Result<TcpSocketStream> {
        let tcp_stream: TcpStream = Self::create_tcp_stream(remote_socket)?;
        let raw_socket: SOCKET = SOCKET(tcp_stream.as_raw_socket() as usize);
        match SocketHandle::new(raw_socket) {
            Ok(handle) => Ok(TcpSocketStream {
                    socket: tcp_stream,
                    write_buffer: VecDeque::new(),
                    socket_handle: handle,
                    is_readable: false,
                    is_writable: false,
                }),
            Err(error) => Err(error),
        }
    }

    fn create_tcp_stream(remote_socket_address: SocketAddr) -> io::Result<TcpStream> {
        let (socket_addr, tcp_socket) = match remote_socket_address {
            SocketAddr::V4(_) => {
                if let Ok(Some(interface)) = get_ipv4_internet_interface() {
                    let socket_addr_v4: SocketAddrV4 = SocketAddrV4::new(interface.local_ip, 0);
                    log::info!("Binding TCP stream to local {socket_addr_v4} and connect to {remote_socket_address}");
                    (SocketAddr::V4(socket_addr_v4), Self::create_tcp_socket(Domain::IPV4)?)
                } else {
                    return Err(Error::new(ErrorKind::AddrNotAvailable, "Can't find an IPv4 internet interface"));
                }
            },
            SocketAddr::V6(_) => {
                if let Ok(Some(interface)) = get_ipv6_internet_interface() {
                    let socket_addr_v6: SocketAddrV6 = SocketAddrV6::new(interface.local_ip, 0, 0, 0);
                    log::info!("Binding TCP stream to local {socket_addr_v6} and connect to {remote_socket_address}");
                    (SocketAddr::V6(socket_addr_v6), Self::create_tcp_socket(Domain::IPV6)?)
                } else {
                    return Err(Error::new(ErrorKind::AddrNotAvailable, "Can't find an IPv6 internet interface"));
                }
            },
        };

        if let Err(err) = tcp_socket.bind(&socket_addr.into()) {
            log::error!("Failed to bind the TCP socket to local {socket_addr}: {}", err);
            return Err(err)
        };
        if let Err(err) = tcp_socket.set_nonblocking(true) {
            log::error!("Failed to set the TCP socket as non-blocking: {}", err);
            return Err(err);
        };
        if let Err(err) = tcp_socket.connect(&remote_socket_address.into()) && err.kind() != ErrorKind::WouldBlock {
            log::error!("Failed to connect with TCP to remote socket {remote_socket_address}: {}", err);
            return Err(err)
        };
        
        let tcp_stream: TcpStream = tcp_socket.into();
        log::info!("Created TCP stream ({}->{})", socket_addr, remote_socket_address);
        Ok(tcp_stream)
    }

    fn create_tcp_socket(domain: Domain) -> Result<Socket, std::io::Error> {
        match Socket::new(domain, Type::STREAM, None) {
            Ok(tcp_socket) => Ok(tcp_socket),
            Err(err) => {
                log::error!("Failed to create '{:?}' TCP socket: {}", domain, err);
                Err(err)
            }
        }
    }
}

impl WindowsStream for TcpSocketStream {
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
        log::info!("TcpSocketStream dropped");
    }
}