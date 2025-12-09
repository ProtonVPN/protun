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

#[cfg(not(feature = "local-agent"))]
use std::sync::Arc;

#[cfg(not(feature = "local-agent"))]
use crate::api::{connection::StateChangedCallback, state::State};

use crate::{connection::pvpn_connection::{PvpnConnectionState}};

/// Trait to receive pvpn connection state changes.
pub(crate) trait PvpnConnectionStateHandler {
    fn on_state_changed(&self, state: &PvpnConnectionState);
}

/// State handler that converts pvpn connection state to api state and forwards it to the client app.
#[cfg(not(feature = "local-agent"))]
pub(crate) struct PvpnToApiStateHandler {
    pub state_change_callback: Arc<dyn StateChangedCallback>,
}
#[cfg(not(feature = "local-agent"))]
impl PvpnConnectionStateHandler for PvpnToApiStateHandler {
    fn on_state_changed(&self, state: &PvpnConnectionState) {
        self.state_change_callback.on_state_changed(state.clone().to_api_state());
    }
}

#[cfg(not(feature = "local-agent"))]
impl PvpnConnectionState {
    pub fn to_api_state(self) -> State {
        match self {
            PvpnConnectionState::Disconnected(error) => State::Disconnected { error },
            PvpnConnectionState::Connecting(peers) => State::Connecting { peers },
            PvpnConnectionState::WaitingForAction(reason) => State::WaitingForAction { reason },
            PvpnConnectionState::Connected(peer) => State::Connected { peer },
        }
    }
}