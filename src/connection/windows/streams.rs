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

use std::iter::once;
use std::{io, net::SocketAddr};
use crate::api::windows::connection_windows::SocketConfig;
use crate::api::windows::protun_error::ProTunFatalError;
use crate::connection::streams::{PollResult, Stream, Streams};
use crate::connection::windows::helpers::poll_waker::WindowsPollWaker;
use crate::connection::windows::tcp::TcpSocketStream;
use crate::connection::windows::udp::UdpSocketStream;
use pvpnclient::{Deadline, StreamId};
use windows::Win32::Foundation::{HANDLE, WAIT_EVENT, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::Networking::WinSock::{WSA_INFINITE, WSAWaitForMultipleEvents};
use crate::api::state::InterfaceState;

const TUN_STREAM_INDEX: usize = 0;
const TIMEOUT_EVENT: u32 = WAIT_TIMEOUT.0;
const WAKER_EVENT: u32 = WAIT_OBJECT_0.0;
const TUN_EVENT: u32 = WAIT_OBJECT_0.0 + 1;

pub(crate) trait WindowsStream: Stream {
    fn handle(&mut self) -> HANDLE;
    fn has_error(&self) -> bool;
    fn get_state(&mut self) -> WindowsStreamState;
}

pub(crate) struct WindowsStreamState {
    pub(crate) is_readable: bool,
    pub(crate) is_writable: bool,
}

struct WindowsStreamInfo {
    stream_id: StreamId,
    stream: Box<dyn WindowsStream>,
}

pub(crate) struct WindowsStreams {
    streams: Vec<WindowsStreamInfo>,
    waker: Box<WindowsPollWaker>,
    /// This vector exists to not be generated in every poll (handles = [stream handles + waker handle])
    handles: Vec<HANDLE>,
    udp_socket_config: SocketConfig,
}

impl WindowsStreams {
    pub(crate) fn create_waker() -> Result<WindowsPollWaker, ProTunFatalError> {
        WindowsPollWaker::new()
    }

    pub(crate) fn new(tun: Box<dyn WindowsStream>, waker: Box<WindowsPollWaker>, udp_socket_config: SocketConfig) -> Self {
        let mut streams = WindowsStreams {
            streams: Vec::new(),
            handles: Vec::new(),
            waker: waker,
            udp_socket_config
        };
        streams.register_stream(StreamId::TUN_STREAM_ID, tun);
        streams
    }

    fn register_stream(&mut self, stream_id: StreamId, stream: Box<dyn WindowsStream>) {
        log::debug!("Registering stream with ID {stream_id}");
        self.streams.push(WindowsStreamInfo { stream_id, stream });
        log::debug!("There are now {} streams registered", self.streams.len());
        self.reset_handles();
    }

    fn reset_handles(&mut self) {
        self.handles = once(self.waker.handle)
            .chain(self.streams.iter_mut().map(|s| s.stream.handle()))
            .collect();
        log::debug!("There are now {} handles registered (waker + streams)", self.handles.len());
    }

    fn create_poll_result(stream: &mut WindowsStreamInfo) -> PollResult {
        let state: WindowsStreamState = stream.stream.get_state();

        PollResult {
            stream_id: stream.stream_id,
            is_readable: state.is_readable,
            is_writable: state.is_writable,
            is_error: stream.stream.has_error(),
        }
    }

    fn get_all_streams_as_poll_results(&mut self) -> Vec<PollResult> {
        self.streams
            .iter_mut()
            .rev()
            .map(|s| Self::create_poll_result(s))
            .collect()
    }
    
    fn get_stream_ref(&self, stream_id: StreamId) -> Option<&WindowsStreamInfo> {
        log::debug!("Trying to get stream reference with ID {stream_id}");
        self.streams.iter().find(|s| s.stream_id == stream_id)
    }
}

impl Streams for WindowsStreams {

    fn get_stream(&mut self, stream_id: StreamId) -> Option<&mut dyn Stream> {
        log::debug!("Trying to get mut stream with ID {stream_id}");
        let WindowsStreamInfo { stream, .. } = self.streams.iter_mut().find(|s| s.stream_id == stream_id)?;
        Some(stream.as_mut())
    }

    fn open_new_tcp_stream(&mut self, stream_id: StreamId, remote_socket: SocketAddr) -> io::Result<()> {
        log::debug!("Opening up a new TCP stream");
        match TcpSocketStream::new(remote_socket) {
            Ok(tcp_socket_stream) => {
                self.register_stream(stream_id, Box::new(tcp_socket_stream));
                Ok(())
            },
            Err(error) => Err(error),
        }
    }

    fn open_new_udp_stream(&mut self, stream_id: StreamId, remote_socket: SocketAddr) -> io::Result<()> {
        log::debug!("Opening up a new UDP socket");
        match UdpSocketStream::new(remote_socket, &self.udp_socket_config) {
            Ok(udp_socket_stream) => {
                self.register_stream(stream_id, Box::new(udp_socket_stream));
                Ok(())
            },
            Err(error) => Err(error),
        }
    }

    fn close_stream(&mut self, stream_id: StreamId) {
        log::debug!("Closing stream with ID {stream_id}");
        // Make sure that the handle of the stream is destroyed
        self.streams.retain(|s| s.stream_id != stream_id);
        self.reset_handles();
    }

    fn set_poll_enable_wait_for_write(&mut self, _stream_id: StreamId, _wait_for_write: bool) {
        // This method does nothing. We don't change the socket event handles on Windows.
    }

    fn poll(&mut self, deadline: Deadline) -> io::Result<Vec<PollResult>> {
        let timeout_as_millis: u32 = deadline.map_or(WSA_INFINITE, |t| t.as_millis().min(WSA_INFINITE as u128) as u32);
        let wait_result: WAIT_EVENT  = unsafe { WSAWaitForMultipleEvents(
            &self.handles,
            false, // Don't wait for all handles to be triggered, just one
            timeout_as_millis,
            false, // We are only interested in signaled events
        ) };
        let result_index: u32 = wait_result.0;
        
        Ok(match result_index {
            TIMEOUT_EVENT => Vec::new(),
            WAKER_EVENT => {
                self.waker.reset();
                Vec::new()
            }
            _ => self.get_all_streams_as_poll_results()
        })
    }

    fn get_tun_interface_state(&self) -> InterfaceState {
        InterfaceState { is_up: self.get_stream_ref(StreamId::TUN_STREAM_ID).is_some() } //TODO: proper impl for windows
    }
}

impl Drop for WindowsStreams {
    fn drop(&mut self) {
        log::info!("WindowsStreams dropped");
    }
}