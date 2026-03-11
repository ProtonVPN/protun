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
use crate::connection::{mio::streams::MioStream, streams::{PendingWrite, Stream, StreamResult, WouldBlock}};

pub(crate) struct UdpSocketStream {
    sock: UdpSocket,
}
impl UdpSocketStream {
    pub fn new(sock: UdpSocket) -> io::Result<UdpSocketStream> {
        let local_addr = sock.local_addr()?;
        log::info!("UDP local_addr: {:?}", local_addr);
        Ok(UdpSocketStream { sock })
    }
}
impl MioStream for UdpSocketStream {
    fn source(&mut self) -> &mut dyn event::Source {
        &mut self.sock
    }
}
impl Stream for UdpSocketStream {

    fn read(&mut self, buf: &mut [u8]) -> StreamResult {
        let ret = self.sock.recv(buf);
        match ret {
            Ok(bytes_count) => {
                StreamResult::ok(bytes_count, WouldBlock::No, PendingWrite::No)
            }
            Err(e) => if e.kind() == io::ErrorKind::WouldBlock {
                StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No)
            } else {
                StreamResult::Err(e)
            }
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        let ret = self.sock.send(&data);
        match ret {
            Ok(size) => {
                if size < data.len() {
                    log::debug!("UDP send truncated: {} < {}", size, data.len());
                }
                StreamResult::ok(size, WouldBlock::No, PendingWrite::No)
            }
            Err(e) => if e.kind() == io::ErrorKind::WouldBlock {
                StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No)
            } else {
                StreamResult::Err(e)
            }
        }
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        // no write buffer for UDP
        StreamResult::ok(0, WouldBlock::No, PendingWrite::No)
    }
}