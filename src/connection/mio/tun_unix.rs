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

/// Unix-specific implementation of [MioStream] for the tun device.
pub(crate) struct TunStreamUnix {
    file: File,
    source: TunSourceFd,
}
impl TunStreamUnix {
    /// [fd] file descriptor of the tun device. Will be owned by this instance.
    pub fn new(fd: RawFd) -> TunStreamUnix {
        TunStreamUnix {
            file: unsafe { File::from_raw_fd(fd) },
            source: TunSourceFd { fd },
        }
    }
}
impl MioStream for TunStreamUnix {
    fn source(&mut self) -> &mut dyn event::Source {
        &mut self.source
    }
}
impl Stream for TunStreamUnix {

    fn read(&mut self, buf: &mut[u8]) -> StreamResult {
        let ret = self.file.read(buf);
        match ret {
            Ok(bytes_count) => {
                if bytes_count == 0 {
                    StreamResult::Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tun read: unexpected EOF"))
                } else {
                    StreamResult::Ok { bytes_count, would_block: false, pending_write: false }
                }
            }
            Err(e) => if e.kind() == io::ErrorKind::WouldBlock {
                StreamResult::Ok { bytes_count: 0, would_block: true, pending_write: false }
            } else {
                StreamResult::Err(e)
            }
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        let mut bytes_written = 0;
        while bytes_written < data.len() {
            let ret = self.file.write(&data[bytes_written..]);
            match ret {
                Ok(bytes_count) => {
                    if bytes_count < data.len() {
                        log::debug!("tun: partial write");
                    }
                    bytes_written += bytes_count;
                }
                Err(e) => return if e.kind() == io::ErrorKind::WouldBlock {
                    StreamResult::Ok { bytes_count: bytes_written, would_block: true, pending_write: false }
                } else {
                    StreamResult::Err(e)
                }
            }
        }
        StreamResult::Ok { bytes_count: bytes_written, would_block: false, pending_write: false }
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        StreamResult::Ok { bytes_count: 0, would_block: false, pending_write: false }
    }
}