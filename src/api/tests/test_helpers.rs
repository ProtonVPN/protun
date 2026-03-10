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

use std::{
    io::{self, Read, Write}, net::{Ipv4Addr, SocketAddr}, os::fd::AsRawFd, str::FromStr, sync::{
        mpsc::{self, Receiver}, Arc
    }, thread::JoinHandle, time::Duration
};
use std::sync::Mutex;
use std::time::Instant;
use mio::net::UdpSocket;
use rand::Rng;

use crate::{
    api::{
        connection::{
            Connection, InitialConnectionConfig, PeerInfo, IpAddress, StateChangedCallback, WgClientPrivateKey, WgPeerPublicKey
        },
        state::State,
        tests::dummy_protocol::{DummyProtocolPacket, DummyPvpnClient},
    },
    connection::{
        mio::{
            socket_factory_unix::SocketFactoryUnix,
            streams::{MioStream, MioStreams},
            udp::UdpSocketStream,
        },
    },
};
use crate::api::connection::EventCallback;
use crate::api::events::Event;
use super::test_clocks::{TestMonotonicClock, TestRealtimeClock};

pub(crate) struct TestEventCallback {
    captured_events: Mutex<Vec<Event>>
}
impl TestEventCallback {
    fn new() -> Self {
        Self { captured_events: Mutex::new(vec![]) }
    }
}
impl EventCallback for TestEventCallback {
    fn on_event(&self, event: Event) {
        self.captured_events.lock().unwrap().push(event);
    }
}

pub(crate) struct TestStateChangedCallback {
    on_state_updated: mpsc::Sender<State>,
}
impl TestStateChangedCallback {
    pub(crate) fn new(on_state_updated: mpsc::Sender<State>) -> Self {
        Self { on_state_updated }
    }
}
impl StateChangedCallback for TestStateChangedCallback {
    fn on_state_changed(&self, new_state: State) {
        self.on_state_updated.send(new_state).unwrap();
    }
}

pub(crate) struct ConnectionTestHelper {
    pub(crate) buf: Box<Vec<u8>>,
    pub(crate) tun_socket: Option<std::net::UdpSocket>,
    pub(crate) state_updated_receiver: Receiver<State>,
    pub(crate) connection: Connection,
    pub(crate) join_handle: JoinHandle<()>,
    pub(crate) monotonic_clock: TestMonotonicClock,
    pub(crate) realtime_clock: TestRealtimeClock,
}
impl ConnectionTestHelper {
    pub(crate) fn recv_udp(&mut self, socket: &std::net::UdpSocket) -> io::Result<(DummyProtocolPacket, SocketAddr)> {
        let (bytes_read, src) = socket.recv_from(&mut self.buf[..])?;
        let packet = bincode::deserialize(&self.buf[..bytes_read]).unwrap();
        Ok((packet, src))
    }

    pub(crate) fn send_udp_to(&mut self, socket: &std::net::UdpSocket, dst: &SocketAddr, packet: &DummyProtocolPacket) -> io::Result<usize> {
        Ok(socket.send_to(&packet.serialize(), dst)?)
    }

    pub(crate) fn send_to_tun(&mut self, packet: &DummyProtocolPacket) -> io::Result<usize> {
        Ok(self.tun_socket.as_ref().unwrap().send(&packet.serialize())?)
    }

    pub(crate) fn recv_from_tun(&mut self) -> io::Result<DummyProtocolPacket> {
        let (bytes_read, _) = self.tun_socket.as_ref().unwrap().recv_from(&mut self.buf[..])?;
        Ok(bincode::deserialize(&self.buf[..bytes_read]).unwrap())
    }

    pub(crate) fn recv_tcp(&mut self, stream: &mut std::net::TcpStream) -> io::Result<DummyProtocolPacket> {
        let bytes_read = stream.read(&mut self.buf[..])?;
        Ok(bincode::deserialize(&self.buf[..bytes_read]).unwrap())
    }

    pub(crate) fn send_tcp(&mut self, stream: &mut std::net::TcpStream, packet: &DummyProtocolPacket) -> io::Result<usize> {
        Ok(stream.write(&packet.serialize())?)
    }

    pub(crate) fn accept_and_verify_udp_connection(&mut self, socket: &std::net::UdpSocket) -> SocketAddr {
        let (handshake, client_addr) = self.recv_udp(socket).unwrap();
        assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, _)));
        self.send_udp_to(socket, &client_addr, &DummyProtocolPacket::HandshakeResponse).unwrap();
        self.expect_state(|state| matches!(state, State::Connected { .. }));
        client_addr
    }

    pub(crate) fn send_tcp_rst(&mut self, stream: &mut std::net::TcpStream) {
        unsafe {
            let fd = stream.as_raw_fd();
            let linger = libc::linger { l_onoff: 1, l_linger: 0 };
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &linger as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            );
        }
    }

    pub(crate) fn expect_state(&mut self, predicate: impl Fn(&State) -> bool) {
        let max_wait = Duration::from_millis(100);
        let now = Instant::now();
        while now.elapsed() < max_wait {
            let left = max_wait - now.elapsed();
            if let Ok(state) = self.state_updated_receiver.recv_timeout(left) {
                if predicate(&state) {
                    return
                }
            }
        }
        panic!("timed out waiting for expected state");
    }
}

pub(crate) fn prepare_connection_test(
    peers: Vec<PeerInfo>,
    private_key: [u8; 32],
    network_available: bool,
) -> ConnectionTestHelper {
    let _ = env_logger::builder().is_test(true).try_init();

    let (state_updated_sender, state_updated_receiver) = mpsc::channel::<State>();

    // Prepare TUN
    let tun_socket = std::net::UdpSocket::bind(SocketAddr::from_str("0.0.0.0:0").unwrap()).unwrap();
    let client_tun_socket_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        rand::rng().random_range(10000..65535),
    ));
    tun_socket.connect(client_tun_socket_addr).unwrap();
    let tun_socket_addr = tun_socket.local_addr().unwrap();

    let monotonic_clock = TestMonotonicClock::new();
    let realtime_clock = TestRealtimeClock::new();
    let monotonic_clock_clone = monotonic_clock.clone();
    let realtime_clock_clone = realtime_clock.clone();

    // Launch connection loop
    let socket_factory = Box::new(SocketFactoryUnix::new(None));
    let (poll, waker) =
        MioStreams::create_mio_poll_with_waker().expect("Failed to create mio poll");
    let config = InitialConnectionConfig {
        peers,
        wg_private_key: WgClientPrivateKey(private_key),
        network_available,
        pcap_file: None,
    };
    let (connection, join_handle) = Connection::connect_internal(
        Box::new(waker),
        move || {
            let tun_stream =
                create_udp_tun_stream(client_tun_socket_addr, tun_socket_addr).unwrap();
            let streams = MioStreams::new(tun_stream, socket_factory, poll)
                .expect("Failed to create mio streams");
            Ok(Box::new(streams))
        },
        move || Box::new(DummyPvpnClient::new(monotonic_clock_clone, realtime_clock_clone)),
        Arc::new(TestStateChangedCallback::new(state_updated_sender)),
        Box::new(TestEventCallback::new()),
        config,
    );

    ConnectionTestHelper {
        buf: Box::new(vec![0u8; 4096]),
        tun_socket: Some(tun_socket),
        state_updated_receiver,
        connection,
        join_handle,
        monotonic_clock,
        realtime_clock,
    }
}

pub(crate) fn create_udp_tun_stream(
    bind_addr: SocketAddr,
    connect_to: SocketAddr,
) -> Result<Box<dyn MioStream>, io::Error> {
    let udp = UdpSocket::bind(bind_addr)?;
    udp.connect(connect_to)?;
    Ok(Box::new(UdpSocketStream::new(udp)?))
}

pub(crate) fn create_udp_peer(id: u8) -> (std::net::UdpSocket, PeerInfo) {
    let socket = std::net::UdpSocket::bind(SocketAddr::from_str("0.0.0.0:0").unwrap()).unwrap();
    let socket_addr = socket.local_addr().unwrap();
    (socket, PeerInfo {
        peer_id: format!("peer_{id}"),
        server_ip: IpAddress(socket_addr.ip()),
        server_public_key: WgPeerPublicKey([id; 32]),
        udp_ports: vec![socket_addr.port()],
        tcp_ports: vec![],
        tls_ports: vec![],
        priority: 0,
    })
}

pub(crate) fn create_tcp_peer(ip: &str, id: u8) -> (std::net::TcpListener, PeerInfo) {
    let socket = std::net::TcpListener::bind(SocketAddr::from_str(format!("{}:0", ip).as_str()).unwrap()).unwrap();
    let socket_addr = socket.local_addr().unwrap();
    (socket, PeerInfo {
        peer_id: format!("peer_{id}"),
        server_ip: ip.to_string().try_into().unwrap(),
        server_public_key: WgPeerPublicKey([id; 32]),
        udp_ports: vec![],
        tcp_ports: vec![socket_addr.port()],
        tls_ports: vec![],
        priority: 0,
    })
}