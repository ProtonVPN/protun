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

use std::{io, net::SocketAddr};
use crate::connection::{streams::{extract_socket_stream_ids, PollResult, PollWaker, Stream, Streams}};
use crate::connection::mio::poll_timer::SuspendInclusivePollTimer;
use mio::{event, Events, Poll, Token, Waker};
use pvpnclient::{Deadline, StreamId};
use pvpnclient::vpn::VpnStreamKind;
use crate::api::connection::TunStreamInfo;
use crate::api::state::{InterfaceError, InterfaceState};

#[cfg(feature = "apple")]
pub(crate) type TunStreamUnixType = crate::connection::mio::tun_apple::TunStreamApple;

#[cfg(all(feature = "unix", not(feature = "apple")))]
pub(crate) type TunStreamUnixType = crate::connection::mio::tun_unix::TunStreamUnix;

const POLL_WAKER_TOKEN: Token = Token(0);
const POLL_TIMER_TOKEN: Token = Token(1);
const FIRST_STREAM_TOKEN: usize = POLL_TIMER_TOKEN.0 + 1;
const EVENTS_CAPACITY: usize = 512; // Safe value for max number of simultaneous streams

pub(crate) trait MioStream: Stream {
    fn source(&mut self) -> &mut dyn event::Source;
}

pub(crate) trait MioSocketFactory {
    fn new_tcp_socket(&self, addr: SocketAddr) -> io::Result<Box<dyn MioStream>>;
    fn new_udp_socket(&self, addr: SocketAddr) -> io::Result<Box<dyn MioStream>>;
}

/// Multi-platform implementation of [Streams] using mio.
pub(crate) struct MioStreams {
    streams: Vec<MioStreamInfo>,
    poll: Poll,
    poll_timer: SuspendInclusivePollTimer,
    events: Events,
    next_token: usize,
    socket_factory: Box<dyn MioSocketFactory>,
}
impl MioStreams {

    /// Creates a new mio poll + waker pair. Enables MioStreams to be created in a different thread than waker.
    pub(crate) fn create_mio_poll_with_waker() -> Result<(Poll, MioPollWaker), io::Error> {
        let poll = Poll::new()?;
        let waker = MioPollWaker::new(Waker::new(poll.registry(), POLL_WAKER_TOKEN)?);
        Ok((poll, waker))
    }

    /// Creates a new MioStreams instance.
    /// [tun] mio-compatible stream for the tun device. None can be passed if TUN is not needed
    ///     (e.g., for testing VPN connection to the server)
    /// [poll] should be created with [create_mio_poll_with_waker].
    pub(crate) fn new(
        tun: Option<Box<dyn MioStream>>,
        socket_factory: Box<dyn MioSocketFactory>,
        poll: Poll,
    ) -> Result<Self, io::Error> {
        let poll_timer = SuspendInclusivePollTimer::new(poll.registry(), POLL_TIMER_TOKEN);
        let mut ret = MioStreams {
            streams: Vec::new(),
            poll,
            poll_timer,
            events: Events::with_capacity(EVENTS_CAPACITY),
            next_token: FIRST_STREAM_TOKEN,
            socket_factory,
        };
        if let Some(tun) = tun {
            ret.register_stream(StreamId::TUN_STREAM_ID, tun, mio::Interest::READABLE, false)?;
        }
        Ok(ret)
    }

    fn register_stream(&mut self, stream_id: StreamId, mut stream: Box<dyn MioStream>, interest: mio::Interest, log_when_connected: bool) -> io::Result<()> {
        let token = Token(self.next_token);
        self.next_token += 1;
        self.poll.registry().register(stream.source(), token, interest)?;
        self.streams.push(MioStreamInfo { stream, token, stream_id, interest, log_when_connected });
        Ok(())
    }
}
impl Streams for MioStreams {

    fn get_stream(&mut self, stream_id: StreamId) -> Option<&mut dyn Stream> {
        let MioStreamInfo { stream, .. } = get_stream_by_id_mut(&mut self.streams, stream_id)?;
        Some(stream.as_mut())
    }

    fn open_new_tcp_stream(&mut self, stream_id: StreamId, addr: SocketAddr) -> io::Result<()> {
        let stream = self.socket_factory.new_tcp_socket(addr)?;
        self.register_stream(stream_id, stream, mio::Interest::READABLE | mio::Interest::WRITABLE, true)?;
        Ok(())
    }

    fn open_new_udp_stream(&mut self, stream_id: StreamId, addr: SocketAddr) -> io::Result<()> {
        let stream = self.socket_factory.new_udp_socket(addr)?;
        self.register_stream(stream_id, stream, mio::Interest::READABLE, false)?;
        Ok(())
    }

    fn close_stream(&mut self, stream_id: StreamId) {
        if let Some(MioStreamInfo { stream, .. }) = get_stream_by_id_mut(&mut self.streams, stream_id) {
            let deregister_result = self.poll.registry().deregister(stream.source());
            if let Err(e) = deregister_result {
                log::error!("failed to deregister stream: {:?}", e);
            }
        }
        self.streams.retain(|s| s.stream_id != stream_id);
    }

    fn poll(&mut self, deadline: Deadline) -> io::Result<Vec<PollResult>> {
        let timeout = self.poll_timer.arm(deadline);
        self.poll.poll(&mut self.events, timeout)?;
        let mut ret = Vec::new();
        for event in self.events.iter() {
            let token = event.token();
            if token == POLL_WAKER_TOKEN {
                log::debug!("poll waker triggered");
            } else if token == POLL_TIMER_TOKEN {
                self.poll_timer.on_expired();
            } else {
                let stream = get_stream_by_token(&mut self.streams, token);
                if let Some(stream) = stream {
                    let stream_id = stream.stream_id;
                    if stream.log_when_connected && event.is_writable() {
                        stream.log_when_connected = false;
                        log::info!("stream {:?} connected", stream_id);
                    }
                    ret.push(
                        PollResult {
                            stream_id,
                            is_readable: event.is_readable(),
                            is_writable: event.is_writable(),
                            is_error: event.is_error(),
                        }
                    );
                } else {
                    log::error!("get_stream_by_token not found: {:?}", token);
                }
            }
        }
        Ok(ret)
    }

    fn set_poll_enable_wait_for_write(&mut self, stream_id: StreamId, wait_for_write: bool) {
        let stream = get_stream_by_id_mut(&mut self.streams, stream_id);
        if let Some(stream) = stream {
            let interest = if wait_for_write { mio::Interest::READABLE | mio::Interest::WRITABLE } else { mio::Interest::READABLE };
            if stream.interest != interest {
                stream.interest = interest;
                let res = self.poll.registry().reregister(stream.stream.source(), stream.token, interest);
                if let Err(e) = res {
                    log::error!("failed to reregister stream {:?}: {:?}", stream_id, e);
                }
            }
        } else {
            log::error!("stream not found: {:?}", stream_id);
        }
    }

    fn update_tun(&mut self, tun_info: TunStreamInfo) -> io::Result<()> {
        self.close_stream(StreamId::TUN_STREAM_ID);
        let tun = match tun_info {
            TunStreamInfo::NoTun => None,
            TunStreamInfo::TunFd(fd) => Some(Box::new(TunStreamUnixType::new(fd))),
        };
        if let Some(tun) = tun {
            self.register_stream(StreamId::TUN_STREAM_ID, tun, mio::Interest::READABLE, false)?
        }
        Ok(())
    }

    fn get_tun_interface_state(&self, last_interface_error: Option<InterfaceError>) -> InterfaceState {
        let is_up = get_stream_by_id(&self.streams, StreamId::TUN_STREAM_ID).is_some();
        if is_up {
            InterfaceState::Up { error: last_interface_error }
        } else {
            InterfaceState::Down { last_error: last_interface_error }
        }
    }

    fn get_socket_stream_ids(&self) -> Vec<StreamId> {
        extract_socket_stream_ids(self.streams.iter().map(|s| s.stream_id))
    }
}

fn get_stream_by_id_mut(streams: &mut Vec<MioStreamInfo>, stream_id: StreamId) -> Option<&mut MioStreamInfo> {
    streams.iter_mut().find(|s| s.stream_id == stream_id)
}

fn get_stream_by_id(streams: &Vec<MioStreamInfo>, stream_id: StreamId) -> Option<&MioStreamInfo> {
    streams.iter().find(|s| s.stream_id == stream_id)
}

fn get_stream_by_token(streams: &mut Vec<MioStreamInfo>, token: Token) -> Option<&mut MioStreamInfo> {
    streams.iter_mut().find(|s| s.token == token)
}

struct MioStreamInfo {
    stream_id: StreamId,
    stream: Box<dyn MioStream>,
    token: Token,
    log_when_connected: bool,
    interest: mio::Interest,
}

pub(crate) struct MioPollWaker {
    waker: Waker,
}
impl MioPollWaker {
    pub(crate) fn new(waker: Waker) -> Self {
        Self { waker }
    }
}
impl PollWaker for MioPollWaker {
    fn wake(&self) {
        if let Err(e) = self.waker.wake() {
            log::error!("failed to wake poll: {:?}", e);
        }
    }
}

/// What the kernel said when it failed a read or a write on a stream. Each
/// stream decides what to do in each case.
///
/// A stream builds one with [Self::on_socket] or [Self::on_tun]. There is no
/// `From<io::Error>`, so that `?` cannot skip the rule for a kind of socket.
#[derive(Debug)]
pub(crate) enum FailedIo {
    /// The kernel cannot do it right now, and will report the stream readable
    /// or writable when it is ready to try again.
    WouldBlock(io::Error),
    /// The kernel had no buffer space to accommodate the request.
    NoBufferSpace(io::Error),
    /// Any other error. The stream is no longer usable.
    Fatal(io::Error),
}

impl FailedIo {
    /// Classifies an error from a socket of `kind`.
    pub(crate) fn on_socket(e: io::Error, kind: VpnStreamKind) -> Self {
        // Whether the kernel reports the socket writable again after ENOBUFS.
        let enobufs_is_flow_control = match kind {
            // xnu returns ENOBUFS when the interface flow controls the socket.
            // It drops the datagram, and reports the socket writable once the
            // interface lifts the flow control.
            //
            // Linux only returns ENOBUFS when it has no memory for the
            // datagram, and does not communicate a full queue for the interface
            // unless IP_RECVERR is set.
            VpnStreamKind::Udp => cfg!(target_vendor = "apple"),
            // A TCP socket that has to wait reports EAGAIN. ENOBUFS does not
            // imply flow control.
            VpnStreamKind::Tcp => false,
        };
        Self::new(e, enobufs_is_flow_control)
    }

    /// Classifies an error from the TUN device.
    pub(crate) fn on_tun(e: io::Error) -> Self {
        match e.raw_os_error() {
            // xnu's utun returns ENOSPC while more than
            // `net.utun.max_pending_input` packets, 512 by default, wait for
            // the network stack.
            Some(libc::ENOSPC) if cfg!(target_vendor = "apple") => Self::NoBufferSpace(e),
            _ => Self::new(e, false),
        }
    }

    fn new(e: io::Error, enobufs_is_flow_control: bool) -> Self {
        match (e.kind(), e.raw_os_error()) {
            (io::ErrorKind::WouldBlock, _) => Self::WouldBlock(e),
            (_, Some(libc::ENOBUFS)) if enobufs_is_flow_control => Self::WouldBlock(e),
            (_, Some(libc::ENOBUFS)) => Self::NoBufferSpace(e),
            _ => Self::Fatal(e),
        }
    }
}
