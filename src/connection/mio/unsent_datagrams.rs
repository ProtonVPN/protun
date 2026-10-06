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

use std::collections::VecDeque;
use std::time::Duration;
use crate::connection::mio::streams::FailedIo;
use crate::connection::streams::{PendingWrite, StreamResult, WouldBlock};

/// Datagrams the kernel refused to send due to a blocking error, kept until the
/// socket is writable.
///
/// This queue exists to improve handshake performance when a device is coming
/// out of sleep and the kernel isn't yet ready to send packets. It should
/// remain small and have a very short retry window before aging packets out.
#[derive(Default)]
pub(crate) struct UnsentDatagrams {
    /// In the order they started to wait, so the datagram that waited longest is first.
    datagrams: VecDeque<UnsentDatagram>,
}

impl UnsentDatagrams {
    /// How many datagrams should wait in the queue at any given moment. This
    /// should be very small to avoid buffer bloat; it's mostly to handle a
    /// refused send in cases where the kernel isn't quite ready to send data
    /// during device wake, and this is UDP so dropping packets is expected. A
    /// bigger value would just result in a large amount of packets getting
    /// queued and dropped for no reason.
    pub(crate) const CAPACITY: usize = 16;

    /// How long to wait before dropping a datagram from the queue, potentially
    /// retrying the send during the interval.
    pub(crate) const MAX_WAIT: Duration = Duration::from_millis(500);

    pub(crate) fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    /// Attempts to send a datagram, enqueueing packets if the kernel tells us
    /// to wait and try again. If the kernel drops a packet then we drop it as
    /// well, and outright failures are propagated to the caller.
    pub(crate) fn send(
        &mut self,
        datagram: Vec<u8>,
        now: impl FnOnce() -> Duration,
        mut send: impl FnMut(&[u8]) -> Result<usize, FailedIo>,
    ) -> StreamResult {
        if !self.is_empty() {
            let now = now();
            self.push(now, datagram);
            return self.send_all(now, send);
        }
        match send(&datagram) {
            Ok(size) => StreamResult::ok(size, WouldBlock::No, PendingWrite::No),
            Err(FailedIo::WouldBlock(e)) => {
                log::debug!("UDP send refused ({e}), keeping the datagram until the socket is writable");
                self.push(now(), datagram);
                StreamResult::ok(0, WouldBlock::Yes, PendingWrite::Yes)
            }
            Err(FailedIo::NoBufferSpace(e)) => {
                log::debug!("UDP send failed ({e}), dropping the datagram");
                StreamResult::ok(0, WouldBlock::Yes, PendingWrite::No)
            }
            Err(FailedIo::Fatal(e)) => StreamResult::Err(e),
        }
    }

    /// Enqueues a datagram, forcing out the oldest one if the queue is full.
    fn push(&mut self, now: Duration, datagram: Vec<u8>) {
        if self.datagrams.len() == Self::CAPACITY {
            self.datagrams.pop_front();
            log::debug!("UDP send queue full, dropping the oldest datagram");
        }
        self.datagrams.push_back(UnsentDatagram { queued_at: now, bytes: datagram });
    }

    /// First, drops the datagrams that waited longer than [Self::MAX_WAIT], and
    /// then tries sending the waiting datagrams in order. A datagram that fails
    /// with [FailedIo::WouldBlock] stops the loop and stays first in the queue.
    /// One that fails with [FailedIo::NoBufferSpace] is removed, and the loop
    /// moves on to the next one. [FailedIo::Fatal] is handled similarly, except
    /// the error is then propagated to the caller.
    pub(crate) fn send_all(
        &mut self,
        now: Duration,
        mut send: impl FnMut(&[u8]) -> Result<usize, FailedIo>,
    ) -> StreamResult {
        self.drop_expired(now);
        let longest_wait = self.datagrams.front().map_or(Duration::ZERO, |first| first.waited(now));
        let mut sent = 0;
        let mut bytes_sent = 0;
        while let Some(first) = self.datagrams.pop_front() {
            match send(&first.bytes) {
                Ok(size) => {
                    sent += 1;
                    bytes_sent += size;
                }
                Err(FailedIo::WouldBlock(e)) => {
                    self.datagrams.push_front(first);
                    log::debug!("UDP send refused again ({e}), {} datagram(s) waiting", self.datagrams.len());
                    return StreamResult::ok(bytes_sent, WouldBlock::Yes, PendingWrite::Yes);
                }
                Err(FailedIo::NoBufferSpace(e)) => log::debug!("UDP send failed ({e}), dropping the datagram"),
                Err(FailedIo::Fatal(e)) => return StreamResult::Err(e),
            }
        }
        if sent > 0 {
            log::debug!("UDP socket accepts datagrams again, sent {sent} that waited up to {longest_wait:?}");
        }
        StreamResult::ok(bytes_sent, WouldBlock::No, PendingWrite::No)
    }

    /// Drops the datagrams that waited longer than [Self::MAX_WAIT].
    fn drop_expired(&mut self, now: Duration) {
        while let Some(first) = self.datagrams.front() && first.waited(now) > Self::MAX_WAIT {
            log::debug!("dropping a UDP datagram that waited {:?}", first.waited(now));
            self.datagrams.pop_front();
        }
    }
}

struct UnsentDatagram {
    queued_at: Duration,
    bytes: Vec<u8>,
}

impl UnsentDatagram {
    fn waited(&self, now: Duration) -> Duration {
        now.saturating_sub(self.queued_at)
    }
}
