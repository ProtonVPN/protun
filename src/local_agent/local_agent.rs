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

use std::sync::Arc;

use local_agent_rs::AgentFeatures;

use crate::{
    api::connection::{InitialLocalAgentConfig, LocalAgentClientCert, StateChangedCallback},
    connection::pvpn_state_handler::PvpnConnectionStateHandler,
};

#[derive(Debug)]
pub(crate) enum LocalAgentMessage {
    UpdateCert(LocalAgentClientCert),
    UpdateFeatures(AgentFeatures),
    RequestStats,
}

/// Start a task that will handle local agent connection.
///
/// [local_agent_config] initial local agent configuration.
/// [state_change_callback] callback that will receive local agent state changes.
///
/// Returns a tuple of:
/// - [PvpnConnectionStateHandler] callback that will receive pvpn connection state changes.
/// - [LocalAgentMessage] callback that can be used to send messages to the local agent.
pub(crate) fn start_local_agent_task(
    local_agent_config: Option<InitialLocalAgentConfig>,
    state_change_callback: Arc<dyn StateChangedCallback>,
) -> (
    Box<dyn PvpnConnectionStateHandler + Send + Sync>,
    Box<dyn Fn(LocalAgentMessage) -> () + Send + Sync>,
) {
    todo!()
}
