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

use crate::api::connection::PeerInfo;

#[derive(Debug, PartialEq)]
pub(crate) struct SanitizedPeers(pub Vec<PeerInfo>);

impl SanitizedPeers {

    // Removes peers with duplicated entry IP preferring ones with higher priority
    pub(crate) fn from(peers: Vec<PeerInfo>) -> SanitizedPeers {
        use std::collections::HashMap;
        use crate::api::connection::IpAddress;

        // ip -> (index, priority)
        let mut best_peer_for_ip: HashMap<IpAddress, (usize, i32)> = HashMap::new();
        let mut duplicates_idx = Vec::new();

        for (index, peer) in peers.iter().enumerate() {
            let ip = peer.server_ip;
            match best_peer_for_ip.get(&ip) {
                Some((existing_index, existing_priority)) => {
                    if peer.priority < *existing_priority {
                        // New peer has lower priority, mark old one as duplicate
                        duplicates_idx.push(*existing_index);
                        best_peer_for_ip.insert(ip, (index, peer.priority));
                    } else {
                        // Existing peer has lower or equal priority, mark new one as duplicate
                        duplicates_idx.push(index);
                    }
                }
                None => {
                    best_peer_for_ip.insert(ip, (index, peer.priority));
                }
            }
        }

        if duplicates_idx.is_empty() {
            return SanitizedPeers(peers);
        }

        let mut result = Vec::with_capacity(peers.len() - duplicates_idx.len());
        for (index, peer) in peers.iter().enumerate() {
            if duplicates_idx.contains(&index) {
                log::warn!("duplicate peer found for IP {} (ID: {})", peer.server_ip.0, peer.peer_id);
            } else {
                result.push(peer.clone());
            }
        }
        SanitizedPeers(result)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn contains(&self, peer: &PeerInfo) -> bool {
        self.0.contains(peer)
    }
}

impl IntoIterator for SanitizedPeers {
    type Item = PeerInfo;
    type IntoIter = std::vec::IntoIter<PeerInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a SanitizedPeers {
    type Item = &'a PeerInfo;
    type IntoIter = std::slice::Iter<'a, PeerInfo>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}