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

use std::{thread, time::Duration};

use crate::{api::{
    connection::{PrivateKeyUpdateInfo, WgClientPrivateKey},
    state::{PeerConnectionInfo, Protocol, State, WaitReason},
    tests::{
        dummy_protocol::DummyProtocolPacket,
        test_helpers::{
            create_tcp_peer, create_udp_peer, prepare_connection_test
        },
    },
}};

/// Set of integration tests using:
/// - Real [Streams], [Connection] and [PvpnConnection] under test
/// - [DummyPvpnClient] to fake pvpnclient
/// - localhost sockets to fake VPN server (using dummy protocol - see [dummy_protocol.rs])

#[test_log::test]
fn happy_path_udp_connection() {
    // create client
    let client_private_key = [1; 32];
    let (udp_server_socket, udp_server_peer) = create_udp_peer(1);
    let server_addr = udp_server_socket.local_addr().unwrap();
    let mut helper = prepare_connection_test(vec![udp_server_peer], client_private_key, true);

    let expected_peer = PeerConnectionInfo {
        peer_id: "peer_1".to_string(),
        entry_ip: server_addr.ip().to_string(),
        protocol: Protocol::WireguardUdp,
        port: server_addr.port()
    };

    // expect handshake from client and "connecting" state
    let (handshake, client_addr) = helper.recv_udp(&udp_server_socket).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, key) if key == client_private_key.to_vec()));
    helper.expect_state(|state| matches!(
        state,
        State::Connecting { peers } if peers == &vec![expected_peer.clone()]
    ));

    // send handshake response to client and expect "connected" state
    helper.send_udp_to(&udp_server_socket, &client_addr, &DummyProtocolPacket::HandshakeResponse).unwrap();
    helper.expect_state(|state| matches!(state,State::Connected { peer } if peer == &expected_peer));

    // send data to TUN and receive it on server socket
    let data = DummyProtocolPacket::Data(vec![1u8]);
    helper.send_to_tun(&data).unwrap();
    let (received_packet, _) = helper.recv_udp(&udp_server_socket).unwrap();
    assert_eq!(received_packet, data);

    // send data from server and receive it on TUN
    let data = DummyProtocolPacket::Data(vec![2u8]);
    helper.send_udp_to(&udp_server_socket, &client_addr, &data).unwrap();
    let received_packet = helper.recv_from_tun().unwrap();
    assert_eq!(received_packet, data);

    // disconnect and make sure connection thread ends
    helper.connection.disconnect();
    helper.expect_state(|state| matches!(state, State::Disconnected { error: None }));
    helper.join_handle.join().unwrap();
}

#[test_log::test]
fn happy_path_tcp_connection() {
    let client_private_key = [1; 32];
    let (tcp_server_socket_listener, tcp_server_peer) = create_tcp_peer("127.0.0.1", 1);
    let server_addr = tcp_server_socket_listener.local_addr().unwrap();
    let mut helper = prepare_connection_test(vec![tcp_server_peer], client_private_key, true);

    // expect handshake from client and connecting state
    let (mut tcp_server_socket, _) = tcp_server_socket_listener.accept().unwrap();
    let handshake = helper.recv_tcp(&mut tcp_server_socket).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, key) if key == client_private_key.to_vec()));
    let expected_peer = PeerConnectionInfo {
        peer_id: "peer_1".to_string(),
        entry_ip: server_addr.ip().to_string(),
        protocol: Protocol::WireguardTcp,
        port: server_addr.port()
    };
    helper.expect_state(|state| matches!(
        state,
        State::Connecting { peers } if peers == &vec![expected_peer.clone()]
    ));

    // send handshake response to client and expect connected state
    helper.send_tcp(&mut tcp_server_socket, &DummyProtocolPacket::HandshakeResponse).unwrap();
    helper.expect_state(|state| matches!(state,State::Connected { peer } if peer == &expected_peer));

    // send tun data and receive it on server socket
    let data = DummyProtocolPacket::Data(vec![1u8]);
    helper.send_to_tun(&data).unwrap();
    let received_packet = helper.recv_tcp(&mut tcp_server_socket).unwrap();
    assert_eq!(received_packet, data);

    // send data from server socket and recive it on tun
    let data = DummyProtocolPacket::Data(vec![2u8]);
    helper.send_tcp(&mut tcp_server_socket, &data).unwrap();
    let received_packet = helper.recv_from_tun().unwrap();
    assert_eq!(received_packet, data);

    // disconnect and join
    helper.connection.disconnect();
    helper.expect_state(|state| matches!(state, State::Disconnected { .. }));
    helper.join_handle.join().unwrap();
}

#[test_log::test]
fn fallback_to_another_peer() {
    // create client with 2 peers
    let client_private_key = [1; 32];
    let (tcp_server_socket1_listener, tcp_server_peer1) = create_tcp_peer("127.0.0.1", 1);
    let (tcp_server_socket2_listener, tcp_server_peer2) = create_tcp_peer("127.0.0.2", 2);

    let mut helper = prepare_connection_test(vec![tcp_server_peer1, tcp_server_peer2], client_private_key, true);

    // close connection to peer 1 after receiving hanshake
    let (mut tcp_server_socket1, _) = tcp_server_socket1_listener.accept().unwrap();
    let handshake = helper.recv_tcp(&mut tcp_server_socket1).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, _)));
    helper.send_tcp_rst(&mut tcp_server_socket1);
    drop(tcp_server_socket1);

    // expect successful fallback to peer 2
    let (mut tcp_server_socket2, _) = tcp_server_socket2_listener.accept().unwrap();
    let handshake = helper.recv_tcp(&mut tcp_server_socket2).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, _)));
    helper.send_tcp(&mut tcp_server_socket2, &DummyProtocolPacket::HandshakeResponse).unwrap();
    helper.expect_state(|state| matches!(state,State::Connected { .. }));

    helper.connection.disconnect();
    helper.join_handle.join().unwrap();
}

#[test_log::test]
fn connect_waiting_for_network() {
    // Create client without network connectivity
    let client_private_key = [1; 32];
    let (udp_server_socket, udp_server_peer) = create_udp_peer(1);
    let mut helper = prepare_connection_test(vec![udp_server_peer], client_private_key, false);

    thread::sleep(Duration::from_millis(5));
    helper.expect_state(|state| matches!(state, State::WaitingForAction { reason: WaitReason::WaitingForNetwork }));

    // Make network available and expect handshake from client that was initiated after network became available
    let before_network_available_ts = helper.realtime_clock.now_nanos();
    helper.connection.on_set_network_available(true);
    let (handshake, client_addr) = helper.recv_udp(&udp_server_socket).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(timestamp, _) if timestamp >= before_network_available_ts));
    helper.send_udp_to(&udp_server_socket, &client_addr, &DummyProtocolPacket::HandshakeResponse).unwrap();
    helper.expect_state(|state| matches!(state, State::Connected { .. }));

    helper.connection.disconnect();
    helper.join_handle.join().unwrap();
}

#[test_log::test]
fn pause_and_resume_network_while_connected() {
    let client_private_key = [1; 32];
    let (udp_server_socket, udp_server_peer) = create_udp_peer(1);
    let mut helper = prepare_connection_test(vec![udp_server_peer], client_private_key, true);

    let client_addr1 = helper.accept_and_verify_udp_connection(&udp_server_socket);

    helper.connection.on_set_network_available(false);
    helper.expect_state(|state| matches!(
        state,
        State::WaitingForAction { reason: WaitReason::WaitingForNetwork }
    ));

    helper.connection.on_set_network_available(true);
    let client_addr2 = helper.accept_and_verify_udp_connection(&udp_server_socket);
    assert_ne!(client_addr1, client_addr2);

    helper.connection.disconnect();
    helper.join_handle.join().unwrap();
}

#[test_log::test]
fn update_peer_while_connected() {
    let client_private_key = [1; 32];
    let (udp_server_socket1, udp_server_peer1) = create_udp_peer(1);
    let mut helper = prepare_connection_test(vec![udp_server_peer1], client_private_key, true);

    let client_addr1 = helper.accept_and_verify_udp_connection(&udp_server_socket1);

    // Change peer and expect new connection
    let (udp_server_socket2, udp_server_peer2) = create_udp_peer(2);
    helper.connection.update_peers(vec![udp_server_peer2]);

    let client_addr2 = helper.accept_and_verify_udp_connection(&udp_server_socket2);
    assert_ne!(client_addr1, client_addr2);

    helper.connection.disconnect();
    helper.join_handle.join().unwrap();
}

#[test_log::test]
fn update_private_key_while_connected() {
    let client_private_key = [1; 32];
    let (udp_server_socket, udp_server_peer) = create_udp_peer(1);
    let mut helper = prepare_connection_test(vec![udp_server_peer], client_private_key, true);

    let client_addr = helper.accept_and_verify_udp_connection(&udp_server_socket);

    let new_client_private_key = [2; 32];
    helper.connection.update_wg_private_key(PrivateKeyUpdateInfo { wg_private_key: WgClientPrivateKey(new_client_private_key) });
    let (handshake, new_client_addr) = helper.recv_udp(&udp_server_socket).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, key) if key == new_client_private_key.to_vec()));
    helper.send_udp_to(&udp_server_socket, &new_client_addr, &DummyProtocolPacket::HandshakeResponse).unwrap();
    helper.expect_state(|state| matches!(state, State::Connected { .. }));
    assert_ne!(client_addr, new_client_addr);

    helper.connection.disconnect();
    helper.join_handle.join().unwrap();
}

