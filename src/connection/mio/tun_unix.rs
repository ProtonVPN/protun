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
        match ret.map_err(FailedIo::on_tun) {
            Ok(bytes_count) => {
                if bytes_count == 0 {
                    StreamResult::Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tun read: unexpected EOF"))
                } else {
                    StreamResult::ok(bytes_count, WouldBlock::No, PendingWrite::No)
                }
            }
            Err(FailedIo::WouldBlock(_) | FailedIo::NoBufferSpace(_)) => {
                StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No)
            }
            Err(FailedIo::Fatal(e)) => StreamResult::Err(e),
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        // An empty packet has nothing to write.
        if data.is_empty() {
            return StreamResult::ok(0, WouldBlock::No, PendingWrite::No);
        }

        // The kernel only writes whole packets, partial writes are not possible
        match self.file.write(&data).map_err(FailedIo::on_tun) {
            Ok(written) if written == data.len() => StreamResult::ok(written, WouldBlock::No, PendingWrite::No),
            Ok(written) => StreamResult::Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("TUN device took {written} of {} bytes of a packet", data.len())
            )),
            // The kernel wrote nothing and the error is non-fatal.
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
