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
use crate::api::state::{DisconnectReason, PeerConnectionInfo, State, WaitReason};
use crate::utils::windows::registry_editor::set_network_adapter_status_text;

pub struct WindowsStateChangedCallback {
    client_callback: Box<dyn StateChangedCallback>
}

impl WindowsStateChangedCallback {
    pub fn new(client_callback: Box<dyn StateChangedCallback>) -> WindowsStateChangedCallback {
        WindowsStateChangedCallback {
            client_callback: client_callback
        }
    }
}

impl StateChangedCallback for WindowsStateChangedCallback {
    fn on_state_changed(&self, state: State) {
        set_network_adapter_status_text(&map_status_to_text(&state));
        self.client_callback.on_state_changed(state);
    }
}

fn map_status_to_text(state: &State) -> String {
    match state {
        State::Disconnected { error } => disconnected_to_string(error),
        State::Connecting { peers } => connecting_to_string(peers),
        State::WaitingForAction { reason } => waiting_to_string(reason),
        State::Connected { peer } => connected_to_string(peer),
    }
}

fn disconnected_to_string(error: &Option<DisconnectReason>) -> String {
    match error {
        Some(_) => "Disconnected with error".to_string(),
        None => "Disconnected".to_string(),
    }
}

fn connecting_to_string(peers: &[PeerConnectionInfo]) -> String {
    let num_peers: usize = peers.len();
    if num_peers > 1 {
        format!("Connecting ({} peers)", num_peers)
    } else if num_peers == 1 {
        format!("Connecting to {}", peers[0].peer_id)
    } else {
        "Connecting".to_string()
    }
}

fn waiting_to_string(reason: &WaitReason) -> String {
    match reason {
        WaitReason::WaitingForNetwork => "Waiting for network".to_string(),
        WaitReason::TunIoError { message: _ } => "Tun I/O error".to_string(),
    }
}

fn connected_to_string(peer: &PeerConnectionInfo) -> String {
    format!("Connected to {}", peer.peer_id)
}