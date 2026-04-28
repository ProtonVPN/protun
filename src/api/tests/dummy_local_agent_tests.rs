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

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;
use muon::util::IntoIterExt;
use proton_vpn_local_agent::types::{NetshieldBlockList, Stats};
use pvpnclient::{LocalAgentAction, LocalAgentMessage, LocalAgentSelector, LocalAgentValue};
use crate::api::connection::{ConnectivityEvent, IpAddress};
use crate::api::events::Event;
use crate::api::local_agent::{LocalAgentSettings, NetshieldLevel, WaitJailReason};
use crate::api::state::{AgentConnectionWaitReason, ConnectionState, PeerConnectionInfo, Protocol};
use crate::api::tests::dummy_protocol::DummyProtocolPacket;
use crate::api::tests::test_helpers::{create_udp_peer, prepare_local_agent_connection_test, LocalAgentTestHandles};

fn connect_with_udp_for_local_agent(messages: HashMap<String, LocalAgentMessage>) -> (LocalAgentTestHandles, UdpSocket, SocketAddr) {
    let (udp_server_socket, udp_server_peer) = create_udp_peer(1);
    let server_addr = udp_server_socket.local_addr().unwrap();
    let mut handles = prepare_local_agent_connection_test(
        vec![udp_server_peer],
        true,
        true,
        LocalAgentSettings::default(),
        messages,
    );

    // WG handshake to bring the tunnel up.
    let (handshake, client_addr) = handles.helper.recv_udp(&udp_server_socket).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, _)));
    handles.helper.send_udp_to(
        &udp_server_socket,
        &client_addr,
        &DummyProtocolPacket::HandshakeResponse,
    ).unwrap();

    // Local agent has not confirmed Established yet → ConnectingToLocalAgent.
    let expected_peer = PeerConnectionInfo {
        peer_id: "peer_1".to_string(),
        entry_ip: IpAddress(server_addr.ip()),
        protocol: Protocol::WireguardUdp,
        port: server_addr.port(),
    };
    handles.helper.expect_state(|state| matches!(
        &state.connection_state,
        ConnectionState::ConnectingToLocalAgent { peer, .. } if peer == &expected_peer
    ));
    (handles, udp_server_socket, client_addr)
}

#[cfg(feature = "local-agent")]
#[test_log::test]
fn local_agent_happy_path() {
    let connected_id = "connected";
    let messages = HashMap::from(
        [(connected_id.to_string(), LocalAgentMessage::LocalAgentConnected)]
    );

    // Establish WG connection.
    let (mut handles, mut server_sock, client_addr) = connect_with_udp_for_local_agent(messages);

    let data = DummyProtocolPacket::LocalAgentMessage { id: connected_id.to_string() };
    handles.helper.send_udp_to(&mut server_sock, &client_addr, &data).unwrap();

    handles.helper.expect_state(|state| matches!(
        &state.connection_state,
        ConnectionState::Connected { agent_info: Some(_), .. }
    ));

    handles.helper.connection.disconnect_and_wait();
}

#[cfg(feature = "local-agent")]
#[test_log::test]
fn local_agent_values_cache_invalidated_when_connecting_to_another_peer() {
    let connected_id = "connected";
    let messages = HashMap::from([
        (connected_id.to_string(), LocalAgentMessage::LocalAgentConnected)
    ]);

    // Connect to peer 1 and fully establish local agent.
    let (mut handles, peer_1_socket, peer_1_client_addr) = connect_with_udp_for_local_agent(messages);
    handles.helper.send_udp_to(&peer_1_socket, &peer_1_client_addr, &DummyProtocolPacket::LocalAgentMessage { id: connected_id.to_string() }).unwrap();
    handles.helper.expect_state(|state| matches!(&state.connection_state, ConnectionState::Connected { .. }));

    // Switch to peer 2 only — this forces peer 1 to be removed and a fresh connection to peer 2.
    let (peer_2_socket, peer_2_info) = create_udp_peer(2);
    let peer_2_addr = peer_2_socket.local_addr().unwrap();
    handles.helper.connection.update_peers(vec![peer_2_info]);

    // Complete WG handshake with peer 2.
    let (handshake, peer_2_client_addr) = handles.helper.recv_udp(&peer_2_socket).unwrap();
    assert!(matches!(handshake, DummyProtocolPacket::Handshake(_, _)));
    handles.helper.send_udp_to(&peer_2_socket, &peer_2_client_addr, &DummyProtocolPacket::HandshakeResponse).unwrap();

    // established_ts was reset by on_connected_to_peer when the peer changed, so state must be
    // ConnectingToLocalAgent rather than Connected.
    let expected_peer = PeerConnectionInfo {
        peer_id: "peer_2".to_string(),
        entry_ip: peer_2_addr.ip().to_string(),
        protocol: Protocol::WireguardUdp,
        port: peer_2_addr.port(),
    };
    handles.helper.expect_state(|state| matches!(
        &state.connection_state,
        ConnectionState::ConnectingToLocalAgent { peer, .. } if peer == &expected_peer
    ));

    handles.helper.connection.disconnect_and_wait();
}

#[cfg(feature = "local-agent")]
#[test_log::test]
fn set_netshield_level() {
    let connected_id = "connected";
    let netshield_id = "netshield";
    let messages = HashMap::from([
        (connected_id.to_string(), LocalAgentMessage::LocalAgentConnected),
        (netshield_id.to_string(), LocalAgentMessage::Value(LocalAgentValue::SettingsNetshieldLevel(
            Some(pvpnclient::NetshieldLevel::AdsAndMalwareFilter)
        ))),
    ]);

    let (mut handles, server_sock, client_addr) = connect_with_udp_for_local_agent(messages);

    // Request new netshield setting.
    handles.helper.connection.update_local_agent_settings(LocalAgentSettings {
        netshield_level: Some(NetshieldLevel::AdsAndMalwareFilter),
        ..Default::default()
    });
    thread::sleep(Duration::from_millis(5));

    // Verify the setting was forwarded to pvpnclient.
    let settings = handles.script.get_settings().unwrap();
    assert_eq!(settings.session_settings.netshield_level, Some(pvpnclient::NetshieldLevel::AdsAndMalwareFilter));

    // Server responds with Established and new netshield value
    handles.helper.send_udp_to(&server_sock, &client_addr, &DummyProtocolPacket::LocalAgentMessage { id: connected_id.to_string() }).unwrap();
    handles.helper.send_udp_to(&server_sock, &client_addr, &DummyProtocolPacket::LocalAgentMessage { id: netshield_id.to_string() }).unwrap();

    // Verify Connected state reflects the netshield level in agent_info.
    handles.helper.expect_state(|state| matches!(
        &state.connection_state,
        ConnectionState::Connected { agent_info: Some(info), .. }
            if info.settings.netshield_level == Some(NetshieldLevel::AdsAndMalwareFilter)
    ));

    handles.helper.connection.disconnect_and_wait();
}

#[cfg(feature = "local-agent")]
#[test_log::test]
fn pause_and_resume_network_while_connected() {
    let connected_id = "connected";
    let messages = HashMap::from([
        (connected_id.to_string(), LocalAgentMessage::LocalAgentConnected)
    ]);

    // Establish full local agent connection.
    let (mut handles, server_sock, client_addr1) = connect_with_udp_for_local_agent(messages);
    handles.helper.send_udp_to(&server_sock, &client_addr1, &DummyProtocolPacket::LocalAgentMessage { id: connected_id.to_string() }).unwrap();
    handles.helper.expect_state(|state| matches!(&state.connection_state, ConnectionState::Connected { .. }));

    // Pause network.
    handles.helper.connection.on_connectivity_change(ConnectivityEvent::Down);
    handles.helper.expect_state(|state| state.connection_state.is_waiting_for_network());

    // Resume network — client reconnects to the same peer. Since the peer didn't change,
    // on_connected_to_peer preserves established_ts and state returns directly to Connected.
    handles.helper.connection.on_connectivity_change(ConnectivityEvent::Up);
    let client_addr2 = handles.helper.accept_and_verify_udp_connection(&server_sock);
    assert_ne!(client_addr1, client_addr2);

    handles.helper.connection.disconnect_and_wait();
}

#[cfg(feature = "local-agent")]
#[test_log::test]
fn jail_after_connecting_to_local_agent() {
    let connected_id = "connected";
    let jails_set_id = "jails_set";
    let clear_policy_violation_id = "clear_policy_violation";
    let jails_cleared_id = "jails_cleared";
    let messages = HashMap::from([
        (connected_id.to_string(), LocalAgentMessage::LocalAgentConnected),
        (jails_set_id.to_string(), LocalAgentMessage::Value(LocalAgentValue::Jails(Some(
            pvpnclient::Jails(HashSet::from([
                pvpnclient::Jail::PolicyViolation1("low plan".to_string()),
                pvpnclient::Jail::ExpiredCertificate("cert expired".to_string()),
            ]))
        )))),
        (clear_policy_violation_id.to_string(), LocalAgentMessage::Value(LocalAgentValue::Jails(Some(
            pvpnclient::Jails(HashSet::from([
                pvpnclient::Jail::ExpiredCertificate("cert expired".to_string()),
            ]))
        )))),
        (jails_cleared_id.to_string(), LocalAgentMessage::Value(LocalAgentValue::Jails(None))),
    ]);

    // Establish full connection.
    let (mut handles, server_sock, client_addr) = connect_with_udp_for_local_agent(messages);
    handles.helper.send_udp_to(&server_sock, &client_addr, &DummyProtocolPacket::LocalAgentMessage { id: connected_id.to_string() }).unwrap();
    handles.helper.expect_state(|state| matches!(&state.connection_state, ConnectionState::Connected { .. }));

    // Server jails the client.
    handles.helper.send_udp_to(&server_sock, &client_addr, &DummyProtocolPacket::LocalAgentMessage { id: jails_set_id.to_string() }).unwrap();

    handles.helper.expect_state(|state| matches!(
        &state.connection_state,
        ConnectionState::ConnectingToLocalAgent { wait_reason: Some(AgentConnectionWaitReason::HardJailed { jails }), .. } if jails.len() == 2
    ));

    // Clear policy violation first.
    handles.helper.send_udp_to(&server_sock, &client_addr, &DummyProtocolPacket::LocalAgentMessage { id: clear_policy_violation_id.to_string() }).unwrap();
    handles.helper.expect_state(|state| matches!(
        &state.connection_state,
        ConnectionState::ConnectingToLocalAgent { wait_reason: Some(AgentConnectionWaitReason::HardJailed { jails }), .. }
            if jails.len() == 1 && matches!(&jails[0], WaitJailReason::Internal { .. })
    ));

    // Clear cert expired
    handles.helper.send_udp_to(&server_sock, &client_addr, &DummyProtocolPacket::LocalAgentMessage { id: jails_cleared_id.to_string() }).unwrap();
    handles.helper.expect_state(|state| matches!(&state.connection_state, ConnectionState::Connected { .. }));

    handles.helper.connection.disconnect_and_wait();
}

#[test_log::test]
fn local_agent_get_stats() {
    let connected_id = "connected";
    let stats_id = "stats";

    // Inject a Stats reply with one of each NetShield bucket populated.
    let mut netshield = std::collections::HashMap::new();
    netshield.insert(NetshieldBlockList::Malicious, 1);
    netshield.insert(NetshieldBlockList::Adult, 2);
    let stats = Stats {
        bytes_received: Some(1234),
        bytes_sent: Some(5678),
        netshield_dnsbl: Some(netshield),
    };

    let messages = HashMap::from([
        (connected_id.to_string(), LocalAgentMessage::LocalAgentConnected),
        (stats_id.to_string(), LocalAgentMessage::Value(LocalAgentValue::Stats(Some(stats))))
    ]);

    // Establish WG connection.
    let (mut handles, mut server_sock, client_addr) = connect_with_udp_for_local_agent(messages);

    let establish_data = DummyProtocolPacket::LocalAgentMessage { id: connected_id.to_string() };
    handles.helper.send_udp_to(&mut server_sock, &client_addr, &establish_data).unwrap();

    handles.helper.connection.request_local_agent_stats();
    thread::sleep(Duration::from_millis(5));
    let action = handles.script.get_last_action();
    assert!(matches!(action.unwrap(), LocalAgentAction::Get(LocalAgentSelector::Stats)));

    // Send stats reply
    let stats_data = DummyProtocolPacket::LocalAgentMessage { id: stats_id.to_string() };
    handles.helper.send_udp_to(&mut server_sock, &client_addr, &stats_data).unwrap();

    handles.helper.expect_event(|event| matches!(event,
        Event::LocalAgentStats {
            bytes_received: Some(1234),
            bytes_sent: Some(5678),
            malicious_blocked: Some(1),
            ads_blocked: None,
            trackers_blocked: None,
            adult_content_blocked: Some(2),
            data_saved: Some(_),
        }
    ));

    handles.helper.connection.disconnect_and_wait();
}

