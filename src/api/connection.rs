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
use local_agent_rs::AgentFeatures;

use crate::{
    api::state::State,
};

pub const CLIENT_PRIV_KEY_SIZE_BYTES: usize = 32;
pub const PEER_PUB_KEY_SIZE_BYTES: usize = 32;

/// [CLIENT_PRIV_KEY_SIZE_BYTES] bytes long client private key.
pub struct WgClientPrivateKey(pub [u8; CLIENT_PRIV_KEY_SIZE_BYTES]);

/// [PEER_PUB_KEY_SIZE_BYTES] bytes long peer public key.
pub struct WgPeerPublicKey(pub [u8; PEER_PUB_KEY_SIZE_BYTES]);

/// Represents an active VPN connection.
/// Platform-specific constructor (::*_connect) is defined in dedicated module (see e.g. [crate::api::connection_unix])
///
/// Connection will make a best effort to maintain VPN connection cycling through a set of candidate peers
/// (along with ports and protocols) based on their priority and availability in current network conditions.
/// 
/// Connection can run in two modes:
/// - with built-in local agent: when client passes [LocalAgentClientCert] != None.
/// - without local agent: [LocalAgentClientCert] == None
/// 
/// Local agent mode is available when `local-agent` feature is enabled.
/// 
/// In local-agent mode, after establishing VPN connection via e.g. WireGuard, LocalAgentConnection will
/// be established before Connection enters connected state.
/// 
/// In non-local-agent mode, Connection will enter connected state immediately after establishing VPN connection.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Connection;

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Connection {

    /// Updates candidate peers for connection.
    /// Method call might not necessarily result in new connection if suitable peer is already connected.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_peers(&self, peers: Vec<PeerInfo>) {
        todo!()
    }

    /// Updates WireGuard private key.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_wg_private_key(&self, info: PrivateKeyUpdateInfo) {
        todo!()
    }

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn on_set_network_available(&self, is_network_available: bool) {
        todo!()
    }

    /// Disconnects. Connection should not be used after this.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn disconnect(&self) {
        todo!()
    }
}

/// Part of the interface specific to local-agent mode.
#[cfg_attr(feature = "uniffi", uniffi::export)]
#[cfg(feature = "local-agent")]
impl Connection {

    /// Updates shared local agent features for all peers.
    /// Some features, like AgentFeatures::Bouncing will have values specific to the peer and defined in [PeerLocalAgentInfo].
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_base_features(&self, features: AgentFeatures) {
        todo!()
    }

    /// Updates local agent client certificate.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_local_agent_client_cert(&self, cert: LocalAgentClientCert) {
        todo!()
    }

    /// Requests statistics (NetShield) from local agent.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn request_local_agent_stats(&self) {
        todo!()
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InitialConnectionConfig {
    pub wg_private_key: WgClientPrivateKey,
    pub peers: Vec<PeerInfo>,
    pub network_available: bool,
    #[cfg(feature = "local-agent")]
    pub local_agent: Option<InitialLocalAgentConfig>,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg(feature = "local-agent")]
pub struct InitialLocalAgentConfig {
    pub client_cert: LocalAgentClientCert,
    pub base_features: AgentFeatures,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PrivateKeyUpdateInfo {
    pub wg_private_key: WgClientPrivateKey,
    #[cfg(feature = "local-agent")]
    pub local_agent_client_cert: Option<LocalAgentClientCert>,
}

#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait StateChangedCallback: Send + Sync {
    fn on_state_changed(&self, state: State);
}

/// Represents a candidate peer for connection.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PeerInfo {
    /// Unique identifier of connected peer (as defined by client). This id will be available in
    /// connection states when given peer is connecting/connected (see peer_id in [State]).
    pub peer_id: String,
    /// Local agent info for the peer.
    #[cfg(feature = "local-agent")]
    pub local_agent: Option<PeerLocalAgentInfo>,
    pub server_ip: String,
    pub server_public_key: WgPeerPublicKey,
    pub udp_ports: Vec<u16>,
    pub tcp_ports: Vec<u16>,
    pub tls_ports: Vec<u16>,
    pub priority: i32,
}

#[cfg(feature = "local-agent")]
#[cfg_attr(all(feature = "uniffi", feature = "local-agent"), derive(uniffi::Record))]
pub struct PeerLocalAgentInfo {
    pub bouncing: Option<String>,
    pub domain: String,
}

#[cfg(feature = "local-agent")]
#[cfg_attr(all(feature = "uniffi", feature = "local-agent"), derive(uniffi::Record))]
#[derive(Debug, Clone, PartialEq)]
pub struct LocalAgentClientCert {
    /// Client certificate in PEM format.
    pub cert_pem: String,
    /// Client certificate private key in PEM format.
    pub private_key_pem: String,
}
