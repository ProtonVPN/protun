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

use crate::connection::mio::streams::MioStream;
use crate::connection::mio::tun_source::TunSourceFd;
use crate::connection::streams::{Stream, StreamResult};

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
        match rv {
            Ok(bytes_read) if bytes_read >= APPLE_TUN_PACKET_HEADER_LEN => {
                StreamResult::Ok {
                    bytes_count: bytes_read - APPLE_TUN_PACKET_HEADER_LEN,
                    start_offset: APPLE_TUN_PACKET_HEADER_LEN,
                    would_block: false,
                    pending_write: false
                }
            }
            Ok(bytes_read) => {
                StreamResult::Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid packet: expected at least {} bytes, got {}", APPLE_TUN_PACKET_HEADER_LEN, bytes_read)
                ))
            },
            Err(e) => if e.kind() == io::ErrorKind::WouldBlock {
                StreamResult::ok(0, true, false)
            } else {
                StreamResult::Err(e)
            }
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

        let total_len = self.write_buffer.len();
        let mut bytes_written = 0;

        while bytes_written < total_len {
            match self.file.write(&self.write_buffer[bytes_written..]) {
                Ok(0) => {
                    return StreamResult::Err(io::Error::new(io::ErrorKind::WriteZero,
                        "Failed to write packet to TUN device"
                    ));
                }
                Ok(bytes_count) => {
                    bytes_written += bytes_count;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if bytes_written >= APPLE_TUN_PACKET_HEADER_LEN {
                        return StreamResult::ok(bytes_written - APPLE_TUN_PACKET_HEADER_LEN, true, false)
                    } else {
                        return StreamResult::Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("Partial header write ({} bytes) before would-block", bytes_written)
                        ));
                    }
                }
                Err(e) => return StreamResult::Err(e)
            }
        }

        StreamResult::ok(data.len(), false, false)
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        StreamResult::ok(0, false, false)
    }
}
