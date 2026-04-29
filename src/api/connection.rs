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

use derive_more::Debug;
use std::{io, net::IpAddr, thread::JoinHandle};
use std::sync::Mutex;
use crate::api::events::Event;
use crate::connection::pvpn_connection::{start_pvpn_connection, PvpnDependencies, PvpnMessage, SendPvpnMessage};
use crate::connection::streams::PollWaker;
use crate::api::state::VpnState;

#[cfg(feature = "local-agent")]
use crate::api::local_agent::LocalAgentSettings;

pub const CLIENT_PRIV_KEY_SIZE_BYTES: usize = 32;
pub const PEER_PUB_KEY_SIZE_BYTES: usize = 32;

/// [CLIENT_PRIV_KEY_SIZE_BYTES] bytes long client private key.
#[derive(Clone, Debug)]
#[debug("<wireguard private key>")]
pub struct WgClientPrivateKey(pub [u8; CLIENT_PRIV_KEY_SIZE_BYTES]);

/// Wrapper around IpAddr to be used in uniffi.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct IpAddress(pub IpAddr);

/// [PEER_PUB_KEY_SIZE_BYTES] bytes long peer public key.
#[derive(Clone, Debug)]
pub struct WgPeerPublicKey(pub [u8; PEER_PUB_KEY_SIZE_BYTES]);

/// Represents an active VPN connection.
/// Platform-specific constructor (::*_connect) is defined in dedicated module
/// (see e.g. [crate::api::connection_unix]). Helper constructor capturing common logic
/// ([Connection::connect_internal]) is added for convenience.
///
/// Connection will make a best effort to maintain VPN connection cycling through a set of candidate peers
/// (along with ports and protocols) based on their priority and availability in current network conditions.
/// 
/// For initializing logging, see [crate::api::logger::init_logger].
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Connection {
    pub(crate) send_pvpn_message: SendPvpnMessage,
    join_handle: Mutex<Option<JoinHandle<()>>>,
}

impl Connection {

    /// Helper constructor to be used by platform-specific ones.
    pub(crate) fn connect_internal(
        poll_waker: Box<dyn PollWaker + Send + Sync>,
        create_pvpn_dependencies: impl FnOnce() -> Result<PvpnDependencies, io::Error> + Sync + Send + 'static,
    ) -> Self {
        let (send_pvpn_message, join_handle) =
            start_pvpn_connection(poll_waker, create_pvpn_dependencies);
        Self { send_pvpn_message, join_handle: Mutex::new(Some(join_handle)) }
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Connection {

    /// Updates candidate peers for connection.
    /// Method call might not necessarily result in new connection if suitable peer is already connected.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_peers(&self, peers: Vec<PeerInfo>) {
        (self.send_pvpn_message)(PvpnMessage::UpdatePeers(peers));
    }

    /// Call it when connectivity or underlying network adapter(s) change
    /// (e.g. network switched from wifi to mobile). Library will use that information
    /// to reset VPN connection sockets.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn on_connectivity_change(&self, event: ConnectivityEvent) {
        (self.send_pvpn_message)(PvpnMessage::ConnectivityChange(event));
    }

    /// Disconnects. Connection should not be used after this.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn disconnect(&self) {
        (self.send_pvpn_message)(PvpnMessage::Disconnect);
    }

    /// Disconnects and waits for the connection to be fully closed.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn disconnect_and_wait(&self) {
        self.disconnect();
        if let Some(join_handle) = self.join_handle.lock().unwrap().take() {
            match join_handle.join() {
                Ok(_) => log::info!("disconnect_and_wait: success"),
                Err(e) => log::error!("disconnect_and_wait: failed: {:?}", e),
            }
        }
    }
    
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn start_packet_capture(&self, pcap_file: PcapFileInfo) {
        (self.send_pvpn_message)(PvpnMessage::StartPacketCapture(pcap_file));
    }

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn stop_packet_capture(&self) {
        (self.send_pvpn_message)(PvpnMessage::StopPacketCapture);
    }

    /// One-off call to get connection stats - they will be delivered via [Event::ConnectionStats].
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn request_stats(&self) {
        (self.send_pvpn_message)(PvpnMessage::RequestStats);
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
#[cfg(feature = "local-agent")]
impl Connection {

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_local_agent_settings(&self, settings: LocalAgentSettings) {
        (self.send_pvpn_message)(PvpnMessage::UpdateLocalAgentSettings(settings));
    }

    /// One-off call to get local agent stats - they will be delivered via [Event::LocalAgentStats].
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn request_local_agent_stats(&self) {
        (self.send_pvpn_message)(PvpnMessage::RequestLocalAgentStats);
    }

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn provide_api_fork_selector(&self, fork_selector: String) {
        (self.send_pvpn_message)(PvpnMessage::ProvideApiForkSelector(fork_selector))
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct InitialConnectionConfig {
    pub peers: Vec<PeerInfo>,
    pub network_available: bool,
    pub pcap_file: Option<PcapFileInfo>,
    pub connection_mode: ConnectionMode,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
pub enum ConnectionMode {

    /// Local agent connection will not be established, and [ConnectionState::Connected] state
    /// will be emitted as soon as WG connection is ready.
    NoLocalAgent {
        wg_private_key: WgClientPrivateKey
    },

    #[cfg(feature = "local-agent")]
    LocalAgent {
        user_agent: String,
        app_version: String,
        settings: LocalAgentSettings,
    },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(PartialEq)]
pub enum ConnectivityEvent {
    Up,
    Down,

    /// Network switch occurred (wifi -> mobile, between different wifi etc.).
    /// This informs the library that it should reset VPN sockets.
    NetworkSwitch,
}

/// Callback interface for receiving connection state changes. Avoid doing heavy work in the
/// callback to avoid blocking the connection thread.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait StateChangedCallback: Send + Sync {
    fn on_state_changed(&self, state: VpnState);
}

/// Blanket implementation to allow using closures as state change callbacks.
impl<F> StateChangedCallback for F
where
    F: Send + Sync + Fn(VpnState) + 'static
{
    fn on_state_changed(&self, state: VpnState) {
        self(state);
    }
}

/// Persistent cache. Libpvpnclient will use it to store secrets (certificates, private keys, etc.).
/// Data is sensitive and implementation should make sure it's stored securely. Note that all
/// functions in this trait will be blocking the connection thread.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait PersistentCache: Send + Sync {
    fn put(&self, key: CacheKey, bytes: Vec<u8>);
    fn get(&self, key: CacheKey) -> Option<Vec<u8>>;
    fn clear(&self);
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Hash, PartialEq, Eq)]
pub enum CacheKey {
    Certificate,
    PrivateKey,
    ApiSession,
}

/// Callback interface for receiving events. Avoid doing heavy work in the callback to avoid
/// blocking the connection thread (delegate to another thread if needed).
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait EventCallback: Send + Sync {
    fn on_event(&self, event: Event);
}

/// Blanket implementation to allow using closures as event callback.
impl<F> EventCallback for F
where
    F: Send + Sync + Fn(Event) + 'static
{
    fn on_event(&self, event: Event) {
        self(event);
    }
}

/// Represents a candidate peer for connection.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// Unique identifier of connected peer (as defined by client). This id will be available in
    /// connection states when given peer is connecting/connected (see peer_id in [VpnState]).
    pub peer_id: String,
    pub server_ip: IpAddress,
    pub server_public_key: WgPeerPublicKey,
    pub udp_ports: Vec<u16>,
    pub tcp_ports: Vec<u16>,
    pub tls_ports: Vec<u16>,
    pub priority: i32,

    #[cfg(feature = "local-agent")]
    pub exit_label: Option<String>
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug)]
pub struct PcapFileInfo {
    pub file: PcapFile,

    /// File size limit in bytes. When the limit is reached, the library will stop writing.
    pub max_bytes: Option<u64>
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug)]
pub enum PcapFile {
    Path { path: String, mode: FileWriteMode },
    #[cfg(feature = "unix")]
    Fd(i32),
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug)]
pub enum FileWriteMode {
    Append,
    Overwrite,
}
