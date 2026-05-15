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

use std::net::IpAddr;
use crate::api::connection::{IpAddress, PeerInfo, WgPeerPublicKey};
use crate::connection::sanitized_peers::SanitizedPeers;

#[test]
fn sanitize_empty_list() {
    let result = SanitizedPeers::from(vec![]);
    assert!(result.is_empty());
}

#[test]
fn sanitize_single_peer() {
    let peers = vec![peer("10.0.0.1", 1)];
    let result = SanitizedPeers::from(peers.clone());
    assert_eq!(result.0, peers);
}

#[test]
fn sanitize_no_duplicates() {
    let peers = vec![
        peer("10.0.0.1", 1),
        peer("10.0.0.2", 2),
        peer("10.0.0.3", 3),
    ];
    let result = SanitizedPeers::from(peers.clone());
    assert_eq!(result.0, peers);
}

#[test]
fn sanitize_remove_duplicates_by_priority() {
    let peers = vec![
        peer("10.0.0.1", 5),
        peer("10.0.0.2", 3),
        peer("10.0.0.1", 1),
        peer("10.0.0.3", 7),
    ];
    let result = SanitizedPeers::from(peers);
    assert_eq!(result.0.len(), 3);
    let priorities: Vec<_> = result.0.iter().map(|p| (p.server_ip.0.to_string(), p.priority)).collect();
    assert!(priorities.contains(&("10.0.0.1".to_string(), 1)));
    assert!(priorities.contains(&("10.0.0.2".to_string(), 3)));
    assert!(priorities.contains(&("10.0.0.3".to_string(), 7)));
}

#[test]
fn sanitize_keeps_higher_priority_peer() {
    // Lower numeric priority = higher priority
    let peers = vec![
        peer("10.0.0.1", 5),
        peer("10.0.0.1", 1),
    ];
    let result = SanitizedPeers::from(peers);
    assert_eq!(result.0.len(), 1);
    assert_eq!(result.0[0].priority, 1);
}

#[test]
fn sanitize_keeps_first_on_equal_priority() {
    let peers = vec![
        peer_with_id("10.0.0.1", 3, "1".to_string()),
        peer_with_id("10.0.0.1", 3, "2".to_string()),
    ];
    let result = SanitizedPeers::from(peers);
    assert_eq!(result.0.len(), 1);
    assert_eq!(result.0[0].peer_id, "1");
}

#[test]
fn sanitize_ipv6_peers() {
    let peers = vec![
        peer("::1", 2),
        peer("::1", 1),
        peer("::2", 3),
    ];
    let result = SanitizedPeers::from(peers);
    assert_eq!(result.0.len(), 2);
    assert_eq!(
        result.0.iter().find(|p| p.server_ip.0.to_string() == "::1").unwrap().priority,
        1
    );
}

fn peer(ip: &str, priority: i32) -> PeerInfo {
    peer_with_id(ip, priority, format!("peer-{ip}-{priority}"))
}

fn peer_with_id(ip: &str, priority: i32, id: String) -> PeerInfo {
    PeerInfo {
        peer_id: id,
        server_ip: IpAddress(ip.parse::<IpAddr>().unwrap()),
        server_public_key: WgPeerPublicKey([0u8; 32]),
        udp_ports: vec![51820],
        tcp_ports: vec![],
        tls_ports: vec![],
        priority,
        #[cfg(feature = "local-agent")]
        exit_label: None,
    }
}