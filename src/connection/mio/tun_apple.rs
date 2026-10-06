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

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use mio::event;

use crate::connection::mio::streams::{FailedIo, MioStream};
use crate::connection::mio::tun_source::TunSourceFd;
use crate::connection::streams::{PendingWrite, Stream, StreamResult, WouldBlock};

const APPLE_TUN_PACKET_HEADER_LEN: usize = 4;
const APPLE_WRITE_BUFFER_SIZE: usize = 2048;
const AF_INET: u8 = libc::AF_INET as u8;
const AF_INET6: u8 = libc::AF_INET6 as u8;

// Helper to extract the IP version from the IP packet and return appropriate address family value
fn address_family(byte: u8) -> Result<u8, io::Error> {
    let ip_version = byte >> 4;
    match ip_version {
        4 => Ok(AF_INET),
        6 => Ok(AF_INET6),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, format!("Invalid IP version: {}", ip_version)))
    }
}

/// Apple-specific implementation of [MioStream] for the tun device.
pub(crate) struct TunStreamApple {
    file: File,
    write_buffer: Vec<u8>,
    source: TunSourceFd,
}

impl TunStreamApple {
    /// [fd] file descriptor of the tun device. Will be owned by this instance.
    pub fn new(fd: RawFd) -> TunStreamApple {
        TunStreamApple {
            file: unsafe { File::from_raw_fd(fd) },
            write_buffer: Vec::with_capacity(APPLE_WRITE_BUFFER_SIZE),
            source: TunSourceFd { fd },
        }
    }
}

impl MioStream for TunStreamApple {
    fn source(&mut self) -> &mut dyn event::Source {
        &mut self.source
    }
}

impl Stream for TunStreamApple {
    fn read(&mut self, buf: &mut[u8]) -> StreamResult {
        let rv = self.file.read(buf);
        match rv.map_err(FailedIo::on_tun) {
            Ok(bytes_read) if bytes_read >= APPLE_TUN_PACKET_HEADER_LEN => {
                StreamResult::Ok {
                    bytes_count: bytes_read - APPLE_TUN_PACKET_HEADER_LEN,
                    start_offset: APPLE_TUN_PACKET_HEADER_LEN,
                    would_block: WouldBlock::No,
                    pending_write: PendingWrite::No
                }
            }
            Ok(bytes_read) => {
                StreamResult::Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid packet: expected at least {} bytes, got {}", APPLE_TUN_PACKET_HEADER_LEN, bytes_read)
                ))
            },
            Err(FailedIo::WouldBlock(_) | FailedIo::NoBufferSpace(_)) => {
                StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No)
            }
            Err(FailedIo::Fatal(e)) => StreamResult::Err(e),
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        let af = match data.first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty packet"))
            .and_then(|&byte| address_family(byte))
            {
                Ok(af) => af,
                Err(e) => return StreamResult::Err(e),
            };

        self.write_buffer.clear();
        self.write_buffer.extend_from_slice(&[0, 0, 0, af]);
        self.write_buffer.extend_from_slice(&data);

        // The kernel takes a packet whole or not at all, so one write is one
        // packet.
        match self.file.write(&self.write_buffer).map_err(FailedIo::on_tun) {
            Ok(written) if written == self.write_buffer.len() => {
                StreamResult::ok(data.len(), WouldBlock::No, PendingWrite::No)
            }
            Ok(written) => StreamResult::Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("TUN device took {written} of {} bytes of a packet", self.write_buffer.len())
            )),
            // The kernel took nothing and the device still works, so this is
            // not an error.
            Err(FailedIo::WouldBlock(e) | FailedIo::NoBufferSpace(e)) => {
                log::debug!("TUN write refused ({e}), dropping the packet");
                StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No)
            }
            Err(FailedIo::Fatal(e)) => StreamResult::Err(e),
        }
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        StreamResult::ok(0, WouldBlock::No, PendingWrite::No)
    }
}
