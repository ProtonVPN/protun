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

use std::{collections::VecDeque, net::SocketAddr, num::NonZero, time::Duration};
use pvpnclient::{Action, ActionKind, Deadline, StreamId, TunnelInfo};
use pvpnclient::action::OpenStream;
use pvpnclient::os_interface::time::{FromDuration, Instant, SinceUnixEpoch, SystemTime};
use pvpnclient::peer::{Peer, PeerAddr};
use pvpnclient::vpn::{VpnProtocol, WireguardPrivateKey};
use serde::{Serialize, Deserialize};
use pvpnclient::id::CaptureId;
use pvpnclient::stats::TunnelStats;
use crate::connection::{pvpn_client::PvpnClient, util::error_kind_to_socket_err};
use super::test_clocks::{TestMonotonicClock, TestRealtimeClock};

/// Fake [PvpnClient] implementing dummy protocol for integration testing.
/// - [DummyProtocolPacket]s are exchanged between TUN and server sockets.
/// - dummy client when connecting sends [DummyProtocolPacket::Handshake] with its private key (as dummies do) and a timestamp
/// - when server responds with [DummyProtocolPacket::HandshakeResponse] connection is established
/// - when client receives [DummyProtocolPacket::Data] from server it passes it to TUN and vice versa
/// - on socket error or removing connected peer client will find another configuration (ip, protocol, port) to connect to

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub(crate) enum DummyProtocolPacket {
    Handshake(u128, Vec<u8>),
    HandshakeResponse,
    Data(Vec<u8>),
}
impl DummyProtocolPacket {
    pub(crate) fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }
    pub(crate) fn deserialize(data: &[u8]) -> Self {
        bincode::deserialize(data).unwrap()
    }
}

#[derive(Clone, PartialEq, Debug)]
struct ConnectionInfo {
    peer_addr: PeerAddr,
    vpn_protocol: VpnProtocol,
    port: NonZero<u16>,
}
impl ConnectionInfo {
    fn socket_addr(&self) -> SocketAddr {
        let port = self.port.get();
        match self.peer_addr {
            PeerAddr::Ipv4(ipv4) => (ipv4, port).into(),
            PeerAddr::Ipv6(ipv6) => (ipv6, port).into(),
            PeerAddr::Both(ipv4, _) => (ipv4, port).into(),
        }
    }
}

#[derive(PartialEq)]
pub(crate) enum ConnectionState {
    Disconnected,
    WaitingForTcpConnection,
    WaitingForHandshake,
    Connected(SystemTime)
}

pub(crate) struct DummyPvpnClient {
    private_key: Option<WireguardPrivateKey>,
    monotonic_clock: TestMonotonicClock,
    realtime_clock: TestRealtimeClock,
    peers: Vec<Peer>,
    actions: VecDeque<Action>,
    current_connection: Option<(StreamId, Peer, ConnectionInfo)>,
    next_stream_id: i32,
    connection_state: ConnectionState,
    failed_connections: Vec<ConnectionInfo>,
}
impl DummyPvpnClient {
    pub(crate) fn new(monotonic_clock: TestMonotonicClock, realtime_clock: TestRealtimeClock) -> Self {
        Self {
            private_key: None,
            monotonic_clock,
            realtime_clock,
            peers: Vec::new(),
            actions: VecDeque::new(),
            current_connection: None,
            next_stream_id: 1,
            connection_state: ConnectionState::Disconnected,
            failed_connections: Vec::new(),
        }
    }

    pub(crate) fn monotonic_clock(&self) -> &TestMonotonicClock {
       &self.monotonic_clock
    }

    pub(crate) fn realtime_clock(&self) -> &TestRealtimeClock {
       &self.realtime_clock
    }

    fn maybe_connect(&mut self) {
        if self.current_connection.is_none() && self.peers.len() > 0 {
            if let Some((peer, connection_info)) = self.find_non_failed_connection() {
                let stream_id = self.next_stream_id.into();
                let socket_addr = connection_info.socket_addr();
                log::info!("found non-failed connection, connecting to: {:?}", connection_info);
                match connection_info.vpn_protocol {
                    VpnProtocol::WireguardTcp | VpnProtocol::Stealth => {
                        self.connection_state = ConnectionState::WaitingForTcpConnection;
                        self.actions.push_back(Action::mock_open(stream_id, OpenStream::mock_open_tcp(socket_addr)));
                    }
                    VpnProtocol::WireguardUdp => {
                        self.connection_state = ConnectionState::WaitingForHandshake;
                        self.actions.push_back(Action::mock_open(stream_id, OpenStream::mock_open_udp(socket_addr)));
                        let handshake = &DummyProtocolPacket::Handshake(
                            self.realtime_clock.now_nanos(),
                            self.private_key.as_ref().unwrap().key.to_vec()
                        );
                        self.actions.push_back(Action::mock_write(stream_id, DummyProtocolPacket::serialize(handshake)));
                    }
                }
                self.current_connection = Some((stream_id, peer, connection_info));
                self.next_stream_id += 1;
            } else {
                log::warn!("No non-failed connection found, starting over..");
                self.failed_connections.clear();
                self.maybe_connect();
            }
        }
    }

    fn find_non_failed_connection(&self) -> Option<(Peer, ConnectionInfo)> {
        for peer in &self.peers {
            let peer_addr = get_peer_addr(peer);
            for vpn_protocol in [VpnProtocol::WireguardUdp, VpnProtocol::WireguardTcp, VpnProtocol::Stealth] {
                let ports = match vpn_protocol {
                    VpnProtocol::WireguardUdp => peer.udp_ports(),
                    VpnProtocol::WireguardTcp => peer.tcp_ports(),
                    VpnProtocol::Stealth => peer.tls_ports(),
                };
                for port in ports {
                    if !self.failed_connections.contains(&ConnectionInfo { peer_addr, vpn_protocol, port: *port }) {
                        return Some((peer.clone(), ConnectionInfo { peer_addr, vpn_protocol, port: *port }));
                    }
                }
            }
        }
        None
    }

    fn close_current_connection(&mut self) {
        if let Some((stream_id, _, _)) = self.current_connection {
            self.actions.clear();
            self.actions.push_back(Action::close(stream_id.clone()));
            self.current_connection = None;
            self.connection_state = ConnectionState::Disconnected;
        }
    }

    fn reset_current_connection(&mut self) {
        if let Some((_, _, _)) = self.current_connection {
            self.close_current_connection();
            self.maybe_connect();
        }
    }
}
impl PvpnClient for DummyPvpnClient {
    fn set_private_key(&mut self, private_key: &WireguardPrivateKey) {
        self.private_key = Some(private_key.clone());
        self.reset_current_connection();
    }
    
    fn set_current_time(&mut self) -> (Instant, SystemTime) {
        let real_time =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        self.realtime_clock.set_nanos(real_time.as_nanos());
        (self.monotonic_now(), SystemTime::from_duration(real_time))
    }

    fn need_pull(&self) -> bool {
        !self.actions.is_empty()
    }

    fn peer_add(&mut self, peer: Peer) {
        let peer_addr = get_peer_addr(&peer);
        self.peers.retain(|p| !p.is_same_destination(&peer));
        self.peers.push(peer);
        if let Some((_, _, connection_info)) = &self.current_connection && connection_info.peer_addr == peer_addr {
            self.reset_current_connection();
        } else {
            self.maybe_connect();
        }
    }

    fn peer_remove(&mut self, peer_addr: PeerAddr) {
        self.peers.retain(|p| get_peer_addr(p) != peer_addr);
        if let Some((_, _, connection_info)) = &self.current_connection && connection_info.peer_addr == peer_addr {
            self.reset_current_connection();
        }
    }
    
    fn pull(&mut self) -> Option<Action> {
        self.actions.pop_front()
    }
    
    fn push(&mut self, action: Action) {
        let action_stream_id = action.stream();
        let peer_stream_id = self.current_connection.as_ref().map(|(stream_id, _, _)| stream_id);
        match action.kind() {        
            ActionKind::Read(data) => {
                let received_packet = DummyProtocolPacket::deserialize(data);
                match received_packet {
                    DummyProtocolPacket::Data(_) => {
                        if let Some(current_stream_id) = peer_stream_id {
                            let dst_stream_id = if action_stream_id == StreamId::TUN_STREAM_ID {
                                // Pass data to server
                                current_stream_id.clone()
                            } else {
                                // Pass data to TUN
                                StreamId::TUN_STREAM_ID.clone()
                            };
                            self.actions.push_back(Action::mock_write(dst_stream_id, data.clone()));
                        }
                    },
                    DummyProtocolPacket::HandshakeResponse => {
                        self.connection_state = ConnectionState::Connected(
                            SystemTime::since_unix_epoch(Duration::from_nanos(self.realtime_clock.now_nanos() as u64))
                        );
                    }
                    DummyProtocolPacket::Handshake(_, _) => {
                        panic!("unexpected hanshake")
                    }
                }
            },
            ActionKind::Error(_) => {
                if let Some((peer_stream_id, _, connection_info)) = &self.current_connection && action_stream_id == peer_stream_id.clone() {
                    self.failed_connections.push(connection_info.clone());
                    self.reset_current_connection();
                }
            },
            ActionKind::Done => {
                if let Some((peer_stream_id, _, connection_info)) = &self.current_connection && action_stream_id == peer_stream_id.clone() {
                    let tcp_protocol = connection_info.vpn_protocol == VpnProtocol::WireguardTcp || connection_info.vpn_protocol == VpnProtocol::Stealth;
                    if tcp_protocol && self.connection_state == ConnectionState::WaitingForTcpConnection {
                        self.connection_state = ConnectionState::WaitingForHandshake;
                        let handshake = DummyProtocolPacket::serialize(&DummyProtocolPacket::Handshake(
                            self.realtime_clock.now_nanos(),
                            self.private_key.as_ref().unwrap().key.to_vec(),
                        ));
                        self.actions.push_back(Action::mock_write(peer_stream_id.clone(), handshake));
                    }
                }
            },
            _ => panic!("unexpected action: {:?}", action),
        }
    }

    fn push_error(&mut self, stream_id: StreamId, error_kind: std::io::ErrorKind) {
        self.push(Action::error(stream_id, error_kind_to_socket_err(error_kind)));
    }
    
    fn get_tunnel_info(&mut self) -> Option<TunnelInfo> {
        Some(if let Some((_, peer, connection_info)) = &self.current_connection {
            let protocol = connection_info.vpn_protocol;
            let peer = peer.clone();
            let peer_addr = connection_info.socket_addr();
            match self.connection_state {
                ConnectionState::Disconnected => {
                    TunnelInfo::Disconnected
                }
                ConnectionState::WaitingForTcpConnection | ConnectionState::WaitingForHandshake => {
                    TunnelInfo::Connecting { protocol, peer, peer_addr }
                }
                ConnectionState::Connected(since) => {
                    TunnelInfo::Connected { protocol, peer, peer_addr, since }
                }
            }
        } else {
            TunnelInfo::Disconnected
        })
    }
    
    fn wakeup_deadline(&self) -> Deadline {
        None
    }
    
    fn notify_network_change(&mut self) {
        self.maybe_connect()
    }
    
    fn notify_network_down(&mut self) {
        // simulate pvpnclient closing sockets when on network gone errors
        self.close_current_connection();
    }   

    fn get_stats(&mut self) -> Option<TunnelStats> {
        None
    }

    fn monotonic_now(&self) -> Instant {
        Instant::from_duration(self.monotonic_clock.now())
    }

    fn set_packet_capture_enabled(&mut self, _enabled: bool) -> CaptureId {
        // not supported in tests
        StreamId::PCAP_STREAM_ID
    }
}

fn get_peer_addr(p: &Peer) -> PeerAddr {
    match (p.ipv4(), p.ipv6()) {
        (Some(v4), Some(v6)) => PeerAddr::Both(v4, v6),
        (Some(v4), _) => PeerAddr::Ipv4(v4),
        (_, Some(v6)) => PeerAddr::Ipv6(v6),
        _ => panic!("no peer addr"),
    }
}