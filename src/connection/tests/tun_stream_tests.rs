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

use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;
use crate::connection::mio::streams::TunStreamUnixType;
use crate::connection::streams::{PendingWrite, Stream, StreamResult, WouldBlock};

/// More packets than any host lets wait in a socket that nobody reads.
const MORE_PACKETS_THAN_FIT: usize = 100_000;

/// A "packet" that looks like IPv4 to the TUN stream.
fn packet(len: usize) -> Vec<u8> {
    vec![0x45; len]
}

/// A TUN stream that writes to one end of a datagram socket pair. Like a TUN
/// device, that socket takes a packet whole or not at all, and refuses packets
/// once too many wait for the other end.
fn tun_and_its_peer() -> (TunStreamUnixType, UnixDatagram) {
    let (device, peer) = UnixDatagram::pair().expect("a socket pair");
    device.set_nonblocking(true).expect("a nonblocking device");
    peer.set_read_timeout(Some(Duration::from_secs(5))).expect("a read timeout");
    (TunStreamUnixType::new(device.into_raw_fd()), peer)
}

fn is_sent(result: &StreamResult) -> bool {
    matches!(result, StreamResult::Ok { would_block: WouldBlock::No, .. })
}

#[test]
fn a_packet_the_device_takes_is_written_whole() {
    let (mut tun, peer) = tun_and_its_peer();

    let result = tun.write(packet(100));
    let mut received = [0u8; 256];
    let size = peer.recv(&mut received).expect("the packet arrives");

    let sent = matches!(
        result,
        StreamResult::Ok { bytes_count: 100, would_block: WouldBlock::No, pending_write: PendingWrite::No, .. }
    );
    assert!(sent, "{result:?}");
    assert!(received[..size].ends_with(&packet(100)));
}

/// A full device still works, so a refused packet must not look like a broken
/// interface.
#[test]
fn a_packet_the_device_refuses_is_dropped_without_an_error() {
    let (mut tun, _peer) = tun_and_its_peer();

    // Nothing reads the other end, so the device fills up and then refuses.
    let refused = (0..MORE_PACKETS_THAN_FIT).map(|_| tun.write(packet(1024))).find(|result| !is_sent(result));

    let dropped = matches!(
        refused,
        Some(StreamResult::Ok { bytes_count: 0, would_block: WouldBlock::Yes, pending_write: PendingWrite::No, .. })
    );
    assert!(dropped, "{refused:?}");
}
