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
use std::net::SocketAddr;
use pvpnclient::{Deadline, StreamId};
use pvpnclient::action::SocketOption;
use crate::api::state::{InterfaceError, InterfaceState};
#[cfg(feature = "mio")]
use crate::connection::CreateTunStream;

/// Abstraction over a socket or tun device.
pub(crate) trait Stream {
    fn read(&mut self, buf: &mut[u8]) -> StreamResult;
    fn write(&mut self, data: Vec<u8>) -> StreamResult;
    /// Attempt to write data that previously failed to write.
    fn write_from_buffer(&mut self) -> StreamResult;

    /// Set socket options
    fn set_option(&mut self, _: &SocketOption) {}
    /// Shutdown the stream for writing (applies to TCP streams only).
    fn shutdown_write(&mut self) {}
}

/// Manages and polls a set of streams for libpvpnclient.
pub(crate) trait Streams {
    fn get_stream(&mut self, id: StreamId) -> Option<&mut dyn Stream>;
    fn open_new_tcp_stream(&mut self, id: StreamId, addr: SocketAddr) -> io::Result<()>;
    fn open_new_udp_stream(&mut self, id: StreamId, addr: SocketAddr) -> io::Result<()>;
    fn close_stream(&mut self, id: StreamId);

    /// Blocks thread until the timeout is reached, [PollWaker] was triggered
    /// or the streams are ready to be read/written.
    fn poll(&mut self, deadline: Deadline) -> io::Result<Vec<PollResult>>;

    /// Set whether polling should wait for stream to become writable.
    fn set_poll_enable_wait_for_write(&mut self, stream_id: StreamId, wait_for_write: bool);

    /// Update the tun stream.
    #[cfg(feature = "mio")]
    fn update_tun(&mut self, create_tun_stream: CreateTunStream) -> io::Result<()>;

    fn get_tun_interface_state(&self, last_interface_error: Option<InterfaceError>) -> InterfaceState;
}

/// A trait to interrupt a [Streams::poll] call.
pub(crate) trait PollWaker {
    fn wake(&self);
}

#[derive(Debug, PartialEq)]
pub(crate) enum WouldBlock { Yes, No }

#[derive(Debug, PartialEq)]
pub(crate) enum PendingWrite { Yes, No }

impl From<bool> for PendingWrite {
    fn from(value: bool) -> Self {
        if value {
            PendingWrite::Yes
        } else {
            PendingWrite::No
        }
    }
}

/// Result of a stream read/write operation.
#[derive(Debug)]
pub(crate) enum StreamResult {
    Ok {
        /// Number of payload bytes.
        bytes_count: usize,
        /// Offset at which caller should start read data.
        start_offset: usize,
        /// Whether the operation ended with WouldBlock.
        would_block: WouldBlock,
        /// Stream need to become writable to send more data.
        pending_write: PendingWrite,
    },
    Err(io::Error),
    StreamClosed,
}

impl StreamResult {
    /// Convenience helper for platforms defaulting to a `start_offset` of 0.
    pub fn ok(bytes_count: usize, would_block: WouldBlock, pending_write: PendingWrite) -> Self {
        StreamResult::Ok { bytes_count, start_offset: 0, would_block, pending_write }
    }
}

#[derive(Debug)]
pub(crate) struct PollResult {
    pub stream_id: StreamId,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_error: bool,
}