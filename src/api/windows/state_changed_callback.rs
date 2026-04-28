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

use crate::api::connection::StateChangedCallback;
use crate::api::state::{ConnectionState, DisconnectReason, PeerConnectionInfo, PeerConnectionWaitReason, VpnState};
#[cfg(feature = "local-agent")]
use crate::api::state::AgentConnectionWaitReason;
use crate::utils::windows::registry_editor::set_network_adapter_status_text;

pub struct WindowsStateChangedCallback {
    client_callback: Box<dyn StateChangedCallback>
}

impl WindowsStateChangedCallback {
    pub fn new(client_callback: Box<dyn StateChangedCallback>) -> WindowsStateChangedCallback {
        WindowsStateChangedCallback {
            client_callback
        }
    }
}

impl StateChangedCallback for WindowsStateChangedCallback {
    fn on_state_changed(&self, state: VpnState) {
        set_network_adapter_status_text(&map_status_to_text(&state.connection_state));
        self.client_callback.on_state_changed(state);
    }
}

fn map_status_to_text(connection_state: &ConnectionState) -> String {
    match connection_state {
        ConnectionState::Disconnected { error } => disconnected_to_string(error),
        ConnectionState::Connecting { peers, wait_reasons } => connecting_to_string(peers, wait_reasons),
        #[cfg(feature = "local-agent")]
        ConnectionState::ConnectingToLocalAgent { peer, wait_reason } => connecting_local_agent_to_string(peer, wait_reason),
        ConnectionState::Connected { peer, .. } => connected_to_string(peer),
    }
}

fn disconnected_to_string(error: &Option<DisconnectReason>) -> String {
    match error {
        Some(_) => "Disconnected with error".to_string(),
        None => "Disconnected".to_string(),
    }
}

fn connecting_to_string(peers: &[PeerConnectionInfo], wait_reasons: &[PeerConnectionWaitReason]) -> String {
    let waiting_label = if wait_reasons.is_empty() {
        ""
    } else {
        " (waiting...)"
    };
    let num_peers: usize = peers.len();
    if num_peers > 1 {
        format!("Connecting ({} peers){}", num_peers, waiting_label)
    } else if num_peers == 1 {
        format!("Connecting to {}{}", peers[0].peer_id, waiting_label)
    } else {
        format!("Connecting{}", waiting_label)
    }
}

fn connected_to_string(peer: &PeerConnectionInfo) -> String {
    format!("Connected to {}", peer.peer_id)
}

#[cfg(feature = "local-agent")]
fn connecting_local_agent_to_string(
    peer: &PeerConnectionInfo,
    wait_reason: &Option<AgentConnectionWaitReason>,
) -> String {
    if wait_reason.is_some() {
        format!("Connecting to {} (waiting...)", peer.peer_id)
    } else {
        format!("Connecting to {}", peer.peer_id)
    }
}
