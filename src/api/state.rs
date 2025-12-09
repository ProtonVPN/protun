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
use local_agent_rs::StatusMessage;

/// State of the VPN connection.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
pub enum State {

    /// Disconnected. [error] will be set if disconnection happened due to an error.
    Disconnected {
        error: Option<DisconnectReason>
    },

    /// Library is attempting VPN connection to one or more candidate peers.
    Connecting {
        peers: Vec<PeerConnectionInfo>,
    },

    /// Library connection attempt requires app, user or system action to proceed.
    WaitingForAction {
        reason: WaitReason
    },

    /// Connection to [peer] is established.
    Connected {
        peer: PeerConnectionInfo,
        #[cfg(feature = "local-agent")]
        status: Option<StatusMessage>
    },

    /// Connected with VPN server, but hard-jailed by local agent.
    #[cfg(feature = "local-agent")]
    HardJailed { peer: PeerConnectionInfo, status: StatusMessage },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum WaitReason {

    /// Device currently has no network (airplane mode, no signal, etc.)
    WaitingForNetwork,

    /// There is I/O problem with TUN interface. Calling code might need to wait, recreate TUN or
    /// disconnect (when it was caused by connection by another VPN app).
    TunIoError { message: String },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum DisconnectReason {

    /// There was a problem establishing TUN interface.
    TunEstablishError { message: String },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(PartialEq, Clone, Debug)]
pub struct PeerConnectionInfo {
    pub peer_id: String,
    pub entry_ip: String,
    pub protocol: Protocol,
    pub port: u16,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Protocol {
    WireguardUdp, WireguardTcp, Stealth,
}
