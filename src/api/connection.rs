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

use std::{io::Error, net::IpAddr, sync::Arc, thread::JoinHandle};

use crate::connection::pvpn_state_handler::PvpnToApiStateHandler;

use crate::connection::pvpn_connection::{start_pvpn_connection, PvpnMessage, SendPvpnMessage};
use crate::connection::streams::{PollWaker, Streams};
use crate::{api::state::State, connection::pvpn_client::PvpnClient};
use crate::api::events::Event;

pub const CLIENT_PRIV_KEY_SIZE_BYTES: usize = 32;
pub const PEER_PUB_KEY_SIZE_BYTES: usize = 32;

/// [CLIENT_PRIV_KEY_SIZE_BYTES] bytes long client private key.
#[derive(Clone)]
pub struct WgClientPrivateKey(pub [u8; CLIENT_PRIV_KEY_SIZE_BYTES]);

/// Wrapper around IpAddr to be used in uniffi.
#[derive(Copy, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct IpAddress(pub IpAddr);

/// [PEER_PUB_KEY_SIZE_BYTES] bytes long peer public key.
#[derive(Clone)]
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
}

impl Connection {

    /// Helper constructor to be used by platform-specific ones.
    pub(crate) fn connect_internal(
        poll_waker: Box<dyn PollWaker + Send + Sync>,
        create_streams: impl FnOnce() -> Result<Box<dyn Streams>, Error> + Send + 'static,
        create_client: impl FnOnce() -> Box<dyn PvpnClient> + Send + 'static,
        state_change_callback: Arc<dyn StateChangedCallback>,
        event_callback: Box<dyn EventCallback>,
        config: InitialConnectionConfig,
    ) -> (Self, JoinHandle<()>) {
        let pvpn_state_change_callback = Box::new(PvpnToApiStateHandler { state_change_callback });
        let (send_pvpn_message, join_handle) = start_pvpn_connection(
            poll_waker,
            create_streams,
            create_client,
            pvpn_state_change_callback,
            event_callback,
            config,
        );
        (Self { send_pvpn_message }, join_handle)
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Connection {

    /// Updates candidate peers for connection.
    /// Method call might not necessarily result in new connection if suitable peer is already connected.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_peers(&self, peers: Vec<PeerInfo>) {
        (self.send_pvpn_message)(PvpnMessage::SetPeers(peers));
    }

    /// Updates WireGuard private key.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_wg_private_key(&self, info: PrivateKeyUpdateInfo) {
        (self.send_pvpn_message)(PvpnMessage::UpdateWgPrivateKey(info.wg_private_key.into()));
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
    
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn start_packet_capture(&self, pcap_file: PcapFileInfo) {
        (self.send_pvpn_message)(PvpnMessage::StartPacketCapture(pcap_file));
    }

    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn stop_packet_capture(&self) {
        (self.send_pvpn_message)(PvpnMessage::StopPacketCapture);
    }
    
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn get_stats(&self) {
        (self.send_pvpn_message)(PvpnMessage::RequestStats);
    }
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct InitialConnectionConfig {
    pub wg_private_key: WgClientPrivateKey,
    pub peers: Vec<PeerInfo>,
    pub network_available: bool,
    pub pcap_file: Option<PcapFileInfo>,
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

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PrivateKeyUpdateInfo {
    pub wg_private_key: WgClientPrivateKey,
}

/// Callback interface for receiving connection state changes. Avoid doing heavy work in the
/// callback to avoid blocking the connection thread.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait StateChangedCallback: Send + Sync {
    fn on_state_changed(&self, state: State);
}

/// Callback interface for receiving events. Avoid doing heavy work in the callback to avoid
/// blocking the connection thread (delegate to another thread if needed).
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait EventCallback: Send + Sync {
    fn on_event(&self, event: Event);
}

/// Represents a candidate peer for connection.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PeerInfo {
    /// Unique identifier of connected peer (as defined by client). This id will be available in
    /// connection states when given peer is connecting/connected (see peer_id in [State]).
    pub peer_id: String,
    pub server_ip: IpAddress,
    pub server_public_key: WgPeerPublicKey,
    pub udp_ports: Vec<u16>,
    pub tcp_ports: Vec<u16>,
    pub tls_ports: Vec<u16>,
    pub priority: i32,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug)]
pub struct PcapFileInfo {
    pub file_type: PcapFile,

    /// File size limit in bytes. When the limit is reached, the library will stop writing.
    pub max_bytes: Option<u64>
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
pub enum PcapFile {
    Path { path: String, mode: FileWriteMode },
    #[cfg(feature = "unix")]
    Fd(i32),
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
pub enum FileWriteMode {
    Append,
    Overwrite,
}
