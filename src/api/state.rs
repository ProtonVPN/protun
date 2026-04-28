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

use crate::api::connection::IpAddress;
#[cfg(feature = "local-agent")]
use crate::api::local_agent::{AgentConnectionInfo, WaitJailReason};

/// Combined state of the VPN connection and the TUN interface.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug, PartialEq)]
pub struct VpnState {
    pub interface_state: InterfaceState,
    pub connection_state: ConnectionState,
}

/// State of the TUN interface.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceState {
    pub is_up: bool,
}

/// State of the VPN connection.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionState {

    /// Disconnected. [error] will be set if disconnection happened due to an error.
    Disconnected {
        error: Option<DisconnectReason>
    },

    /// Library is attempting VPN connection to one or more candidate peers.
    Connecting {
        peers: Vec<PeerConnectionInfo>,
        wait_reasons: Vec<PeerConnectionWaitReason>,
    },

    /// In local-agent mode, library established VPN connection and is connecting to local agent.
    #[cfg(feature = "local-agent")]
    ConnectingToLocalAgent {
        peer: PeerConnectionInfo,
        wait_reason: Option<AgentConnectionWaitReason>,
    },

    /// Connection to [peer] is established.
    /// In non-local-agent mode: VPN connection is established.
    /// In local-agent mode: VPN and local agent connections are established. [agent_info] will not
    /// be None in this mode.
    Connected {
        peer: PeerConnectionInfo,

        #[cfg(feature = "local-agent")]
        agent_info: Option<AgentConnectionInfo>,
    },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(PartialEq, Clone, Debug)]
pub struct PeerConnectionInfo {
    pub peer_id: String,
    pub entry_ip: IpAddress,
    pub protocol: Protocol,
    pub port: u16,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum PeerConnectionWaitReason {

    /// Device currently has no network (airplane mode, no signal, etc.)
    WaitingForNetwork,

    /// There is I/O problem with TUN interface. Calling code might need to wait, recreate TUN or
    /// disconnect (when it was caused by connection by another VPN app).
    TunIoError { message: String },
}

#[cfg(feature = "local-agent")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum AgentConnectionWaitReason {
    SoftJailed,
    HardJailed { jails: Vec<WaitJailReason> },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum DisconnectReason {

    /// There was a problem establishing TUN interface.
    TunEstablishError { message: String },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Protocol {
    WireguardUdp, WireguardTcp, Stealth,
}
