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

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{BorrowedFd, RawFd};
use std::sync::mpsc;
use pvpnclient::StreamId;
use socket2::SockRef;
use crate::connection::mio::socket_factory_unix::SocketFactoryUnix;
use crate::connection::mio::streams::MioStreams;
use crate::connection::streams::Streams;
use crate::connection::time::ClientMonotonicFactory;

fn streams_protected_by(protect_socket: impl Fn(RawFd) -> bool + Send + Sync + 'static) -> MioStreams {
    let (poll, _waker) = MioStreams::create_mio_poll_with_waker().expect("a poll");
    let socket_factory = SocketFactoryUnix::new(Some(Box::new(protect_socket)), ClientMonotonicFactory::new());
    MioStreams::new(None, Box::new(socket_factory), poll).expect("streams without a tun")
}

/// Whether the socket behind `fd` has been connected to a peer.
fn is_connected(fd: RawFd) -> bool {
    let fd = unsafe { BorrowedFd::borrow_raw(fd) };
    SockRef::from(&fd).peer_addr().is_ok()
}

/// Failing to protect a socket should make the connection wait for the network.
#[test]
fn a_socket_the_host_could_not_protect_is_not_opened() {
    let server = SocketAddr::from((Ipv4Addr::LOCALHOST, 51820));
    let mut streams = streams_protected_by(|_| false);

    let udp = streams.open_new_udp_stream(StreamId::from(1), server).map_err(|e| e.kind());
    let tcp = streams.open_new_tcp_stream(StreamId::from(2), server).map_err(|e| e.kind());

    assert_eq!(udp, Err(ErrorKind::NetworkUnreachable));
    assert_eq!(tcp, Err(ErrorKind::NetworkUnreachable));
}

/// Protecting a socket only takes effect before the socket connects.
#[test]
fn the_host_protects_each_socket_before_it_connects() {
    let udp_server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let tcp_server = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let (connected_tx, connected_rx) = mpsc::channel();
    let mut streams = streams_protected_by(move |fd| {
        let _ = connected_tx.send(is_connected(fd));
        true
    });

    streams.open_new_udp_stream(StreamId::from(1), udp_server.local_addr().unwrap()).expect("a UDP socket");
    streams.open_new_tcp_stream(StreamId::from(2), tcp_server.local_addr().unwrap()).expect("a TCP socket");

    assert_eq!(connected_rx.try_iter().collect::<Vec<_>>(), [false, false]);
}
