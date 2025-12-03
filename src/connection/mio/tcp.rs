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

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use mio::event;
use mio::net::TcpStream;
use pvpnclient::pvpnclient::SocketOption;

use crate::connection::mio::streams::MioStream;
use crate::connection::streams::{Stream, StreamResult};

pub(crate) struct TcpSocketStream {
    sock: TcpStream,
    write_buffer: VecDeque<Vec<u8>>
}
impl TcpSocketStream {
    pub fn new(tcp: TcpStream) -> TcpSocketStream {
        log::info!("TCP local_addr: {:?}", tcp.local_addr());
        TcpSocketStream { sock: tcp, write_buffer: VecDeque::new() }
    }
}
impl MioStream for TcpSocketStream {
    fn source(&mut self) -> &mut dyn event::Source {
        &mut self.sock
    }
}
impl Stream for TcpSocketStream {

    fn read(&mut self, buf: &mut [u8]) -> StreamResult {
        let ret = self.sock.read(buf);
        let pending_write = !self.write_buffer.is_empty();
        match ret {
            Ok(bytes_count) => StreamResult::Ok { bytes_count, would_block: false, pending_write },
            Err(e) => if e.kind() == io::ErrorKind::WouldBlock {
                StreamResult::Ok { bytes_count: 0, would_block: true, pending_write }
            } else {
                StreamResult::Err(e)
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
                return StreamResult::Ok { bytes_count: bytes_written, would_block: false, pending_write: false };
            };
            let result = self.sock.write(&data);
            match result {
                Ok(count) => {
                    bytes_written += count;
                    if count < data.len() {
                        self.write_buffer.push_front(data[count..].to_vec());
                    }
                }
                Err(e) => {
                    self.write_buffer.push_front(data);
                    return if e.kind() == io::ErrorKind::WouldBlock {
                        StreamResult::Ok { bytes_count: bytes_written, would_block: true, pending_write: true }
                    } else {
                        StreamResult::Err(e)
                    }
                }
            }
        }
    }

    fn shutdown_write(&mut self) {
        let _ = self.sock.shutdown(Shutdown::Write);
    }

    fn set_option(&mut self, _: &SocketOption) {
        // TODO: implement
    }
}