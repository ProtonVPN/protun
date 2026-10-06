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

use std::io;
use mio::{event, net::UdpSocket};
use pvpnclient::vpn::VpnStreamKind;
use crate::connection::{mio::streams::MioStream, streams::{PendingWrite, Stream, StreamResult, WouldBlock}};
use crate::connection::mio::streams::FailedIo;
use crate::connection::mio::unsent_datagrams::UnsentDatagrams;
use crate::connection::time::ClientMonotonicFactory;

pub(crate) struct UdpSocketStream {
    sock: UdpSocket,
    unsent: UnsentDatagrams,
    monotonic_factory: ClientMonotonicFactory,
}
impl UdpSocketStream {
    pub fn new(sock: UdpSocket, monotonic_factory: ClientMonotonicFactory) -> io::Result<UdpSocketStream> {
        let local_addr = sock.local_addr()?;
        log::info!("UDP local_addr: {:?}", local_addr);
        Ok(UdpSocketStream { sock, unsent: UnsentDatagrams::default(), monotonic_factory })
    }
}
impl MioStream for UdpSocketStream {
    fn source(&mut self) -> &mut dyn event::Source {
        &mut self.sock
    }
}

/// Sends one UDP datagram.
fn send_datagram(sock: &UdpSocket, datagram: &[u8]) -> Result<usize, FailedIo> {
    let size = sock.send(datagram).map_err(|e| FailedIo::on_socket(e, VpnStreamKind::Udp))?;
    if size < datagram.len() {
        log::debug!("UDP send truncated: {} < {}", size, datagram.len());
    }
    Ok(size)
}

impl Stream for UdpSocketStream {

    fn read(&mut self, buf: &mut [u8]) -> StreamResult {
        let ret = self.sock.recv(buf);
        let pending_write: PendingWrite = (!self.unsent.is_empty()).into();
        match ret.map_err(|e| FailedIo::on_socket(e, VpnStreamKind::Udp)) {
            Ok(bytes_count) => {
                StreamResult::ok(bytes_count, WouldBlock::No, pending_write)
            }
            Err(FailedIo::WouldBlock(_) | FailedIo::NoBufferSpace(_)) => {
                StreamResult::ok(0, WouldBlock::Yes, pending_write)
            }
            Err(FailedIo::Fatal(e)) => StreamResult::Err(e),
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        self.unsent.send(
            data,
            || self.monotonic_factory.duration_since_initial(),
            |datagram| send_datagram(&self.sock, datagram),
        )
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        let now = self.monotonic_factory.duration_since_initial();
        self.unsent.send_all(now, |datagram| send_datagram(&self.sock, datagram))
    }
}
