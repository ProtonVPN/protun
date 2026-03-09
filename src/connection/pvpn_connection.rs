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

use std::{io::Error, net::SocketAddr, sync::mpsc, thread::{self, JoinHandle}};
use std::cmp::min;
use std::io::ErrorKind;
use std::time::Duration;
use pvpnclient::{Action, ActionKind, StreamId, TunnelInfo};
use pvpnclient::action::OpenStream;
use pvpnclient::peer::Peer;
use pvpnclient::vpn::{VpnProtocol, VpnStreamKind};

#[cfg(feature = "mio")]
use crate::connection::CreateTunStream;

use crate::{
    api::{
        connection::{ConnectionStatsCallback, InitialConnectionConfig, PeerInfo, WgClientPrivateKey},
        state::{DisconnectReason, PeerConnectionInfo, Protocol, WaitReason},
    },
    connection::{pvpn_client::PvpnClient, pvpn_state_handler::PvpnConnectionStateHandler, streams::{PollResult, PollWaker, StreamResult, Streams}},
};
use crate::api::connection::{ConnectivityEvent, PcapFileInfo};
use crate::connection::network_recovery_handler::NetworkRecoveryHandler;
use crate::connection::pcap_stream::PcapStream;

/// State of the pvpn connection.
#[derive(Clone, PartialEq, Debug)]
pub(crate) enum PvpnConnectionState {
    Disconnected(Option<DisconnectReason>),
    Connecting(Vec<PeerConnectionInfo>),
    WaitingForAction(WaitReason),
    Connected(PeerConnectionInfo),
}

/// Messages that can be sent to the connection loop.
pub(crate) enum PvpnMessage {
    /// Disconnect the stop the connection loop.
    Disconnect,
    SetPeers(Vec<PeerInfo>),
    ConnectivityChange(ConnectivityEvent),
    #[cfg(feature = "mio")]
    UpdateTun(CreateTunStream),
    UpdateWgPrivateKey(WgClientPrivateKey),
    StartPacketCapture(PcapFileInfo),
    StopPacketCapture,
    RequestStats,
}

pub(crate) type SendPvpnMessage = Box<dyn Fn(PvpnMessage) -> () + Send + Sync>;

/// Starts a new thread with libpvpnclient connection loop.
/// Returns a callback that can be used to send messages ([PvpnMessage]) to the connection loop.
///
/// [create_streams] factory method to create a new [Streams] instance to be used for the connection.
/// [pvpn_state_change_callback] callback that will receive pvpn connection state changes.
/// [config] initial connection configuration.
pub(crate) fn start_pvpn_connection(
    poll_waker: Box<dyn PollWaker + Send + Sync>,
    create_streams: impl FnOnce () -> Result<Box<dyn Streams>, Error> + Send + 'static,
    create_client: impl FnOnce () -> Box<dyn PvpnClient> + Send + 'static,
    pvpn_state_change_callback: Box<dyn PvpnConnectionStateHandler + Send + 'static>,
    stats_callback: Box<dyn ConnectionStatsCallback>,
    config: InitialConnectionConfig,
) -> (SendPvpnMessage, JoinHandle<()>) {
    let (message_sender, message_receiver) = mpsc::channel();
    let join_handle = thread::spawn(move || {
        let client = create_client();
        match create_streams() {
            Ok(streams) => {
                let mut connection = PvpnConnection::new(
                    client,
                    streams,
                    pvpn_state_change_callback,
                    stats_callback,
                    message_receiver,
                    config.network_available,
                    config.peers,
                    config.wg_private_key,
                    config.pcap_file,
                );
                connection.run();
            },
            Err(err) => log::error!("failed to create streams: {err}"),
        }
    });

    // Message sender will interrupt the poll to make sure the message is handled in a timely manner.
    let send_msg = Box::new(move |message| {
        message_sender.send(message).unwrap();
        poll_waker.wake();
    });
    (send_msg, join_handle)
}

const STREAM_BUFFER_SIZE: usize = 65536;

struct PvpnConnection {
    client: Box<dyn PvpnClient>,
    streams: Box<dyn Streams>,
    state_change_callback: Box<dyn PvpnConnectionStateHandler>,
    stats_callback: Box<dyn ConnectionStatsCallback>,
    message_receiver: mpsc::Receiver<PvpnMessage>,
    state: PvpnConnectionState,
    peers: Vec<PeerInfo>,
    stream_read_buffer: Box<[u8; STREAM_BUFFER_SIZE]>,
    should_stop: bool,
    current_tun_error: Option<String>,
    network_recovery_handler: NetworkRecoveryHandler,
    pcap_stream: Option<PcapStream>,
}
impl PvpnConnection {
    fn new(
        client: Box<dyn PvpnClient>,
        streams: Box<dyn Streams>,
        state_change_callback: Box<dyn PvpnConnectionStateHandler>,
        stats_callback: Box<dyn ConnectionStatsCallback>,
        message_receiver: mpsc::Receiver<PvpnMessage>,
        network_available: bool,
        peers: Vec<PeerInfo>,
        wg_private_key: WgClientPrivateKey,
        pcap_file_info: Option<PcapFileInfo>,
    ) -> Self {
        let mut ret = Self {
            client,
            streams,
            state_change_callback,
            stats_callback,
            message_receiver,
            state: PvpnConnectionState::Disconnected(None),
            peers,
            stream_read_buffer: Box::new([0; STREAM_BUFFER_SIZE]),
            should_stop: false,
            current_tun_error: None,
            network_recovery_handler: NetworkRecoveryHandler::new(network_available),
            pcap_stream: None,
        };
        ret.client.set_private_key(&wg_private_key.into());
        ret.activate_peers();
        if !ret.network_recovery_handler.is_network_available() {
            ret.client.notify_network_down();
            ret.set_state(PvpnConnectionState::WaitingForAction(WaitReason::WaitingForNetwork))
        }
        if let Some(pcap_file_info) = pcap_file_info {
            ret.start_packet_capture(pcap_file_info);
        }
        ret
    }

    fn run(&mut self) {
        while self.handle_messages() {
            self.client.set_current_time();
            self.pull_from_client();
            self.update_state();
            self.poll_from_streams();
        };

        match &self.state {
            PvpnConnectionState::Disconnected(_) => {}
            _ => self.set_state(PvpnConnectionState::Disconnected(None))
        }
        log::info!("pvpn connection loop finished with state: {:?}", self.state);
    }

    fn update_state(&mut self) {
        if self.network_recovery_handler.is_network_available() {
            let info = self.client.get_tunnel_info();
            self.set_state(to_client_state(info, self.current_tun_error.clone(), &self.peers));
            if let PvpnConnectionState::Connected(_) = &self.state {
                self.network_recovery_handler.on_connected();
            }
        } else {
            self.set_state(PvpnConnectionState::WaitingForAction(WaitReason::WaitingForNetwork))
        }
    }

    fn handle_messages(&mut self) -> bool {
        // Non-blocking read of messages
        while let Ok(m) = self.message_receiver.try_recv() {
            match m {
                PvpnMessage::Disconnect => {
                    self.should_stop = true;
                    break;
                },
                PvpnMessage::SetPeers(peers) => {
                    self.set_peers(peers);
                },
                PvpnMessage::ConnectivityChange(event) => {
                    self.on_connectivity_change(event);
                },
                #[cfg(feature = "mio")]
                PvpnMessage::UpdateTun(create_tun_stream) => {
                    self.streams.update_tun(create_tun_stream);
                },
                PvpnMessage::UpdateWgPrivateKey(wg_private_key) => {
                    self.client.set_private_key(&wg_private_key.into());
                },
                PvpnMessage::StartPacketCapture(file_info) => {
                    self.start_packet_capture(file_info);
                },
                PvpnMessage::StopPacketCapture => {
                    self.client.set_packet_capture_enabled(false);
                    self.pcap_stream = None
                },
                PvpnMessage::RequestStats => {
                    if let Some(stats) = self.client.get_stats() {
                        self.stats_callback.on_stats_response(stats.into());
                    }
                }
            }
        }
        !self.should_stop
    }

    fn start_packet_capture(&mut self, file_info: PcapFileInfo) {
        let res = PcapStream::new(file_info);
        match res {
            Ok(stream) => {
                self.pcap_stream = Some(stream);
                self.client.set_packet_capture_enabled(true);
            }
            Err(e) => {
                log::error!("failed to start packet capture: {:?}", e);
            }
        }
    }

    fn pull_from_client(&mut self) {
        while self.client.need_pull() {
            if let Some(action) = self.client.pull() {
                let (stream_id, kind) = action.into_parts();
                match kind {
                    ActionKind::Open(open_stream) =>
                        self.handle_open(stream_id, &open_stream),
                    ActionKind::Write(vec) =>
                        self.handle_write(stream_id, vec),
                    ActionKind::Set(socket_option) =>
                        if let Some(stream) = self.streams.get_stream(stream_id) {
                            stream.set_option(&socket_option);
                        } else {
                            log::error!("stream {:?} not found", stream_id);
                        }
                    ActionKind::Close => {
                        log::info!("closing stream {:?}", stream_id);
                        self.streams.close_stream(stream_id)
                    }
                    ActionKind::Shutdown => {
                        log::info!("stream shutdown {:?}", stream_id);
                        if let Some(stream) = self.streams.get_stream(stream_id) {
                            stream.shutdown_write();
                        } else {
                            log::error!("stream {:?} not found", stream_id);
                        }
                    }

                    // Actions below can only be passed to libvpnclient
                    ActionKind::Read(_) |
                    ActionKind::Error(_) |
                    ActionKind::Done => {
                        log::error!("Unexpected action pulled from libvpnclient: {:?}", kind);
                        debug_assert!(false, "Unexpected action pulled from libvpnclient: {:?}", kind);
                    }
                }
            }
        }
    }

    fn poll_from_streams(&mut self) {
        let poll_results = self.streams.poll(self.poll_deadline());
        let (monotonic_now, _) = self.client.set_current_time();
        self.network_recovery_handler.on_resumed(monotonic_now, || self.client.notify_network_change());
        match poll_results {
            Ok(poll_results) => {
                for res in &poll_results {
                    self.handle_poll_result(res);
                }
            }
            Err(e) => {
                if e.kind() != ErrorKind::Interrupted {
                    log::error!("failed to poll streams: {:?}", e);
                }
            }
        }
    }

    fn poll_deadline(&self) -> Option<Duration> {
        let pvpn_delay = self.client.wakeup_deadline();
        if let Some(network_handler_delay) = self.network_recovery_handler.wakeup_delay(|| self.client.monotonic_now()) {
            match pvpn_delay {
                None => Some(network_handler_delay),
                Some(pvpn_delay) => Some(min(pvpn_delay, network_handler_delay))
            }
        } else {
            pvpn_delay
        }
    }

    fn handle_poll_result(&mut self, res: &PollResult) {
        if res.is_readable {
            self.read_from_stream(res.stream_id);
        }
        if res.is_writable {
            if let Some(stream) = self.streams.get_stream(res.stream_id) {
                let write_result = stream.write_from_buffer();
                self.handle_stream_write_result(res.stream_id, "poll write", &write_result);
            } else {
                log::error!("stream {:?} not found", res.stream_id);
            }
        }
        if res.is_error {
            log::error!("poll error on stream {:?}", res.stream_id);
        }
    }

    fn handle_open(&mut self, stream_id: StreamId, open_stream: &OpenStream) {
        let is_udp = open_stream.kind() == VpnStreamKind::Udp;
        log::info!("opening {} socket id={:?}: {}",
            if is_udp { "udp" } else { "tcp" }, stream_id, open_stream.addr());
        let open_result = if is_udp {
            self.streams.open_new_udp_stream(stream_id, open_stream.addr())
        } else {
            self.streams.open_new_tcp_stream(stream_id, open_stream.addr())
        };
        match open_result {
            Ok(()) => {
                self.network_recovery_handler.on_successful_socket_open();
                if !is_udp {
                    self.streams.set_poll_enable_wait_for_write(stream_id, true);
                }
            }
            Err(e) => {
                log::error!("stream {:?} open error: {:?}", stream_id, e);
                self.handle_stream_error(stream_id, &e);
            }
        }
    }

    fn read_from_stream(&mut self, stream_id: StreamId) {
        let mut last_tun_maybe_error = None;
        loop {
            let stream = match self.streams.get_stream(stream_id) {
                Some(stream) => stream,
                None => {
                    log::error!("stream {:?} not found", stream_id);
                    break;
                }
            };
            let read_result = stream.read(&mut self.stream_read_buffer[..]);
            if stream_id == StreamId::TUN_STREAM_ID {
                last_tun_maybe_error = to_tun_error(&read_result);
            }
            match read_result {
                StreamResult::Ok { bytes_count: bytes_read, would_block, pending_write: _ } => {
                    if bytes_read > 0 && self.network_recovery_handler.is_network_available() {
                        // When there's no network, just drop the data from tun device.
                        self.client.push(Action::read(stream_id, self.stream_read_buffer[..bytes_read].to_vec()));
                        self.pull_from_client();
                    }
                    if would_block || bytes_read == 0 {
                        break;
                    }
                }
                StreamResult::Err(e) => {
                    log::info!("stream {:?} read error: {:?}", stream_id, e);
                    self.handle_stream_error(stream_id, &e);
                    break;
                }
                StreamResult::StreamClosed => {
                    log::info!("closing stream {:?}", stream_id);
                    self.client.push(Action::close(stream_id));
                    break;
                }
            }
        }
        if stream_id == StreamId::TUN_STREAM_ID {
            self.current_tun_error = last_tun_maybe_error;
        }
    }

    fn handle_write(&mut self, stream_id: StreamId, data: Vec<u8>) {
        match stream_id {
            StreamId::PCAP_STREAM_ID => {
                if let Some(stream) = &mut self.pcap_stream {
                    stream.write(&data);
                } else {
                    log::error!("write to pcap stream but pcap capture is not started");
                }
            }
            _ => {
                if let Some(stream) = self.streams.get_stream(stream_id) {
                    let write_result = stream.write(data);
                    self.handle_stream_write_result(stream_id, "write", &write_result);
                } else {
                    log::error!("stream {:?} not found", stream_id);
                }
            }
        }
    }

    fn handle_stream_write_result(&mut self, stream_id: StreamId, op_name: &str, res: &StreamResult) {
        if stream_id == StreamId::TUN_STREAM_ID {
            self.current_tun_error = to_tun_error(res);
        }
        match res {
            StreamResult::Ok { bytes_count: _, would_block: _, pending_write } => {
                self.streams.set_poll_enable_wait_for_write(stream_id, *pending_write);
                if !*pending_write && stream_id > StreamId::TUN_STREAM_ID {
                    self.client.push(Action::done(stream_id));
                }
            },
            StreamResult::Err(e) => {
                log::error!("stream {:?} {op_name} error: {:?}", stream_id, e);
                self.handle_stream_error(stream_id, e);
            },
            StreamResult::StreamClosed => {
                log::error!("closing stream {:?}...", stream_id);
                self.client.push(Action::close(stream_id));
            }
        }
    }

    fn on_connectivity_change(&mut self, event: ConnectivityEvent) {
        self.network_recovery_handler.on_connectivity_change(event);
        if self.network_recovery_handler.is_network_available() {
            self.client.notify_network_change();
        } else {
            self.client.notify_network_down();
            self.set_state(PvpnConnectionState::WaitingForAction(WaitReason::WaitingForNetwork))
        }
    }

    fn handle_stream_error(&mut self, stream_id: StreamId, err: &std::io::Error) {
        if stream_id > StreamId::TUN_STREAM_ID { // Only notify libpvpnclient about socket errors
            self.network_recovery_handler.on_stream_error(stream_id, err, self.client.monotonic_now());
            self.client.push_error(stream_id, err.kind());
        }
    }

    fn set_peers(&mut self, new_peers: Vec<PeerInfo>) {
        for peer in &self.peers {
            self.client.peer_remove(peer.addr());
        }
        self.peers = new_peers;
        self.activate_peers();
    }

    fn activate_peers(&mut self) {
        for peer in &self.peers {
            self.client.peer_add(peer.as_peer());
        }
    }

    fn set_state(&mut self, state: PvpnConnectionState) {
        if state != self.state {
            log::info!("state: {:?}", state);
            self.state = state.clone();
            self.state_change_callback.on_state_changed(&self.state);
        }
    }
}

fn to_tun_error(res: &StreamResult) -> Option<String> {
    match res {
        StreamResult::Ok { bytes_count: _, would_block: _, pending_write: _ } => None,
        StreamResult::Err(e) => Some(e.to_string()),
        StreamResult::StreamClosed => Some("Stream closed".to_string()),
    }
}

fn to_client_state(tunnel_info: Option<TunnelInfo>, last_tun_error: Option<String>, peers: &Vec<PeerInfo>) -> PvpnConnectionState {
    match tunnel_info {
        Some(TunnelInfo::Connected { protocol, peer_addr, peer, .. }) => {
            PvpnConnectionState::Connected(
                get_peer_connection_info(&peer, &peer_addr, protocol),
            )
        }
        Some(TunnelInfo::Connecting { protocol, peer_addr, peer, .. }) => {
            match last_tun_error {
                None => PvpnConnectionState::Connecting(vec![get_peer_connection_info(&peer, &peer_addr, protocol)]),
                Some(error) => PvpnConnectionState::WaitingForAction(WaitReason::TunIoError { message: error })
            }
        }
        _ => PvpnConnectionState::Connecting(vec![]),
    }
}

fn get_peer_id(peer: &Peer, peer_addr: &SocketAddr) -> String {
    peer.tag().unwrap_or(&peer_addr.ip().to_string()).to_string()
}

fn get_peer_connection_info(peer: &Peer, peer_addr: &SocketAddr, protocol: VpnProtocol) -> PeerConnectionInfo {
    PeerConnectionInfo {
        peer_id: get_peer_id(peer, peer_addr),
        entry_ip: peer_addr.ip().to_string(),
        protocol: protocol.into(),
        port: peer_addr.port(),
    }
}

impl From<VpnProtocol> for Protocol {
    fn from(protocol: VpnProtocol) -> Self {
        match protocol {
            VpnProtocol::WireguardUdp => Protocol::WireguardUdp,
            VpnProtocol::WireguardTcp => Protocol::WireguardTcp,
            VpnProtocol::Stealth => Protocol::Stealth,
        }
    }
}