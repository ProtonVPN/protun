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

#[cfg(feature = "local-agent")]
use crate::api::connection::PeerLocalAgentInfo;

use crate::{
    api::{
        connection::{InitialConnectionConfig, PeerInfo, WgClientPrivateKey},
        state::{PeerConnectionInfo, VpnConnectingError},
    },
    connection::{pvpn_state_handler::PvpnConnectionStateHandler, streams::Streams},
};

/// State of the pvpn connection.
#[derive(Clone)]
pub(crate) enum PvpnConnectionState {
    Disconnected,
    WaitingForNetwork,
    Connecting(Vec<PeerConnectionInfo>, Option<VpnConnectingError>),
    Connected(
        PeerConnectionInfo,
        #[cfg(feature = "local-agent")] Option<PeerLocalAgentInfo>,
    ),
}

/// Messages that can be sent to the connection loop.
pub(crate) enum PvpnMessage {
    /// Disconnect the stop the connection loop.
    Disconnect,
    SetPeers(Vec<PeerInfo>),
    SetIsNetworkAvailable(bool),
    UpdateWgPrivateKey(WgClientPrivateKey),
}

/// Starts a new thread with libpvpnclient connection loop.
/// Returns a callback that can be used to send messages ([PvpnMessage]) to the connection loop.
///
/// [create_streams] factory method to create a new [Streams] instance to be used for the connection.
/// [pvpn_state_change_callback] callback that will receive pvpn connection state changes.
/// [config] initial connection configuration.
pub(crate) fn start_pvpn_connection(
    create_streams: impl FnOnce () -> Box<dyn Streams> + Send + 'static,
    pvpn_state_change_callback: Box<dyn PvpnConnectionStateHandler + Send + 'static>,
    config: InitialConnectionConfig,
) -> Box<dyn Fn(PvpnMessage) -> () + Send + Sync> {
    todo!()
}
