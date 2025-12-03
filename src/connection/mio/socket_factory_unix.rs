// Copyright (c) 2025 Proton AG
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

use std::{io, str::FromStr};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use libc::EINPROGRESS;
use mio::net::{TcpStream, UdpSocket};
use socket2::{Domain, SockAddr, Socket, Type};

use crate::connection::mio::streams::MioStream;
use crate::connection::mio::tcp::TcpSocketStream;
use crate::connection::mio::udp::UdpSocketStream;
use crate::{api::connection_unix::OnSocketFdAvailableCallback, connection::mio::streams::MioSocketFactory};

pub(crate) struct SocketFactoryUnix {
    on_socket_fd_available_callback: Option<Box<dyn OnSocketFdAvailableCallback>>,
}
impl SocketFactoryUnix {
    pub(crate) fn new(on_socket_fd_available_callback: Option<Box<dyn OnSocketFdAvailableCallback>>) -> Self {
        Self { on_socket_fd_available_callback }
    }
}
impl MioSocketFactory for SocketFactoryUnix {

    fn new_tcp_socket(&self, addr: SocketAddr) -> io::Result<Box<dyn MioStream>> {
        // Create raw socket2 TCP socket to be able to get the file descriptor before connecting
        // (needed by android to protect the socket from being routed via tun)
        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
        sock.set_nonblocking(true)?;
        let fd = sock.as_raw_fd();
        if let Some(callback) = &self.on_socket_fd_available_callback {
            callback.on_socket_fd_available(fd);
        }
        let connect_res = sock.connect(&SockAddr::from(addr));
        if let Err(e) = connect_res
            && !matches!(e.raw_os_error(), Some(code) if code == EINPROGRESS)
        {
            log::error!("TCP connect failed: {:?}", e);
            return Err(e);
        }
        let std_tcp = std::net::TcpStream::from(sock);
        let mio_tcp = TcpStream::from_std(std_tcp);
        Ok(Box::new(TcpSocketStream::new(mio_tcp)))
    }

    fn new_udp_socket(&self, addr: SocketAddr) -> io::Result<Box<dyn MioStream>> {
        let bind_addr = match addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let udp = UdpSocket::bind(SocketAddr::from_str(bind_addr).unwrap())?;
        if let Some(callback) = &self.on_socket_fd_available_callback {
            callback.on_socket_fd_available(udp.as_raw_fd());
        }
        udp.connect(addr)?;
        Ok(Box::new(UdpSocketStream::new(udp)?))
    }
}
