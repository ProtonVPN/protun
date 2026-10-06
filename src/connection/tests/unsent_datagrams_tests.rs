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

use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use pvpnclient::vpn::VpnStreamKind;
use crate::connection::mio::streams::FailedIo;
use crate::connection::mio::udp::UdpSocketStream;
use crate::connection::mio::unsent_datagrams::UnsentDatagrams;
use crate::connection::streams::{PendingWrite, Stream, StreamResult, WouldBlock};
use crate::connection::time::ClientMonotonicFactory;

/// A kernel that refuses every datagram with EAGAIN.
fn refusing(_: &[u8]) -> Result<usize, FailedIo> {
    Err(FailedIo::on_socket(io::Error::from_raw_os_error(libc::EAGAIN), VpnStreamKind::Udp))
}

/// A kernel that drops every datagram.
fn losing(_: &[u8]) -> Result<usize, FailedIo> {
    Err(FailedIo::NoBufferSpace(io::Error::other("lost")))
}

/// A kernel that fails every datagram with a fatal error.
fn failing(_: &[u8]) -> Result<usize, FailedIo> {
    Err(FailedIo::on_socket(io::Error::from(ErrorKind::ConnectionRefused), VpnStreamKind::Udp))
}

/// A kernel that accepts every datagram and records it in `sent`.
fn accepting(sent: &mut Vec<Vec<u8>>) -> impl FnMut(&[u8]) -> Result<usize, FailedIo> + '_ {
    move |datagram| {
        sent.push(datagram.to_vec());
        Ok(datagram.len())
    }
}

/// A kernel that accepts `limit` datagrams, records them in `sent`, and refuses
/// every later one.
fn accepting_up_to(limit: usize, sent: &mut Vec<Vec<u8>>) -> impl FnMut(&[u8]) -> Result<usize, FailedIo> + '_ {
    move |datagram| {
        if sent.len() < limit { accepting(sent)(datagram) } else { refusing(datagram) }
    }
}

/// A kernel that loses `lost`, and accepts every other datagram and records it
/// in `sent`.
fn losing_only<'a>(lost: &'a [u8], sent: &'a mut Vec<Vec<u8>>) -> impl FnMut(&[u8]) -> Result<usize, FailedIo> + 'a {
    move |datagram| {
        if datagram == lost { losing(datagram) } else { accepting(sent)(datagram) }
    }
}

fn is_pending(result: &StreamResult) -> bool {
    matches!(result, StreamResult::Ok { pending_write: PendingWrite::Yes, .. })
}

fn bytes_sent(result: &StreamResult) -> Option<usize> {
    match result {
        StreamResult::Ok { bytes_count, .. } => Some(*bytes_count),
        _ => None,
    }
}

/// Whether `result` is the error that [failing] reports.
fn is_failure(result: &StreamResult) -> bool {
    matches!(result, StreamResult::Err(e) if e.kind() == ErrorKind::ConnectionRefused)
}

fn datagram(label: u8) -> Vec<u8> {
    vec![label; 4]
}

#[test]
fn a_refused_datagram_is_sent_once_the_socket_accepts_again() {
    let mut unsent = UnsentDatagrams::default();
    let refused_at = Duration::ZERO;
    let while_refused = unsent.send(datagram(1), || refused_at, refusing);

    let mut sent = Vec::new();
    let once_writable = unsent.send_all(refused_at + Duration::from_millis(100), accepting(&mut sent));

    assert!(is_pending(&while_refused), "{while_refused:?}");
    assert!(!is_pending(&once_writable), "{once_writable:?}");
    assert_eq!(sent, [datagram(1)]);
    assert!(unsent.is_empty());
}

#[test]
fn later_datagrams_wait_behind_a_refused_one() {
    let mut unsent = UnsentDatagrams::default();
    let refused_at = Duration::ZERO;
    unsent.send(datagram(1), || refused_at, refusing);
    let still_refused = unsent.send(datagram(2), || refused_at + Duration::from_millis(10), refusing);

    let mut sent = Vec::new();
    let once_accepted = unsent.send(datagram(3), || refused_at + Duration::from_millis(20), accepting(&mut sent));

    assert!(is_pending(&still_refused), "{still_refused:?}");
    assert!(!is_pending(&once_accepted), "{once_accepted:?}");
    assert_eq!(sent, [datagram(1), datagram(2), datagram(3)]);
}

/// A writable socket can fill up again before every waiting datagram is sent.
#[test]
fn the_datagrams_behind_a_sent_one_keep_waiting_in_order_when_the_kernel_refuses_again() {
    let mut unsent = UnsentDatagrams::default();
    let refused_at = Duration::ZERO;
    for label in 1..=3 {
        unsent.send(datagram(label), || refused_at, refusing);
    }

    let mut sent_first = Vec::new();
    let refused_again = unsent.send_all(refused_at, accepting_up_to(1, &mut sent_first));
    let mut sent_later = Vec::new();
    let once_writable = unsent.send_all(refused_at, accepting(&mut sent_later));

    assert!(is_pending(&refused_again), "{refused_again:?}");
    assert_eq!(bytes_sent(&refused_again), Some(datagram(1).len()));
    assert_eq!(sent_first, [datagram(1)]);
    assert!(!is_pending(&once_writable), "{once_writable:?}");
    assert_eq!(sent_later, [datagram(2), datagram(3)]);
}

#[test]
fn the_oldest_datagram_makes_room_when_the_queue_is_full() {
    let mut unsent = UnsentDatagrams::default();
    let refused_at = Duration::ZERO;
    let labels = 0..=UnsentDatagrams::CAPACITY as u8;
    for label in labels.clone() {
        unsent.send(datagram(label), || refused_at, refusing);
    }

    let mut sent = Vec::new();
    unsent.send_all(refused_at, accepting(&mut sent));

    let kept: Vec<Vec<u8>> = labels.skip(1).map(datagram).collect();
    assert_eq!(sent, kept);
}

#[test]
fn a_datagram_that_waited_too_long_is_dropped() {
    let mut unsent = UnsentDatagrams::default();
    let refused_at = Duration::ZERO;
    unsent.send(datagram(1), || refused_at, refusing);
    unsent.send(datagram(2), || refused_at + Duration::from_millis(400), refusing);

    let mut sent = Vec::new();
    let writable_at = refused_at + UnsentDatagrams::MAX_WAIT + Duration::from_millis(1);
    let result = unsent.send_all(writable_at, accepting(&mut sent));

    assert_eq!(sent, [datagram(2)]);
    assert!(!is_pending(&result), "{result:?}");
}

#[test]
fn a_waiting_datagram_is_dropped_when_any_other_error_is_reported() {
    let mut unsent = UnsentDatagrams::default();
    let refused_at = Duration::ZERO;
    unsent.send(datagram(1), || refused_at, refusing);
    unsent.send(datagram(2), || refused_at, refusing);
    let result = unsent.send_all(refused_at, failing);

    let mut sent = Vec::new();
    unsent.send_all(refused_at, accepting(&mut sent));

    assert!(is_failure(&result), "{result:?}");
    assert_eq!(sent, [datagram(2)]);
}

#[test]
fn a_lost_datagram_is_dropped_without_waiting() {
    let mut unsent = UnsentDatagrams::default();

    let result = unsent.send(datagram(1), || Duration::ZERO, losing);

    assert!(!is_pending(&result), "{result:?}");
    assert_eq!(bytes_sent(&result), Some(0));
    assert!(unsent.is_empty());
}

#[test]
fn a_lost_datagram_does_not_hold_back_the_ones_behind_it() {
    let mut unsent = UnsentDatagrams::default();
    let refused_at = Duration::ZERO;
    for label in 1..=3 {
        unsent.send(datagram(label), || refused_at, refusing);
    }

    let mut sent = Vec::new();
    let result = unsent.send_all(refused_at, losing_only(&datagram(1), &mut sent));

    assert!(!is_pending(&result), "{result:?}");
    assert_eq!(sent, [datagram(2), datagram(3)]);
    assert!(unsent.is_empty());
}

/// The common case must not cost a clock read.
#[test]
fn an_accepted_datagram_is_sent_without_reading_the_clock() {
    let mut unsent = UnsentDatagrams::default();
    let mut sent = Vec::new();

    let result = unsent.send(datagram(1), || panic!("the clock was read"), accepting(&mut sent));

    assert!(!is_pending(&result), "{result:?}");
    assert_eq!(sent, [datagram(1)]);
    assert!(unsent.is_empty());
}

/// Tests the normal case where the kernel happily sends a datagram.
#[test]
fn a_datagram_the_kernel_accepts_is_sent_at_once() {
    let receiver = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("a receiver");
    let sender = mio::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).expect("a sender");
    sender.connect(receiver.local_addr().unwrap()).expect("connected to the receiver");
    let mut stream = UdpSocketStream::new(sender, ClientMonotonicFactory::new()).expect("a stream");

    let result = stream.write(b"hello".to_vec());
    let mut received = [0u8; 16];
    let size = receiver.recv(&mut received).expect("the datagram arrives");

    let sent_at_once = matches!(
        result,
        StreamResult::Ok { bytes_count: 5, would_block: WouldBlock::No, pending_write: PendingWrite::No, .. }
    );
    assert!(sent_at_once, "{result:?}");
    assert_eq!(&received[..size], b"hello");
}
