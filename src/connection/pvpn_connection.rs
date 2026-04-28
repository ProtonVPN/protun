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

use std::{io, net::SocketAddr, sync::mpsc, thread::{self, JoinHandle}};
use std::cmp::min;
use std::io::ErrorKind;
use std::time::Duration;
use pvpnclient::{Action, ActionKind, StreamId, TunnelInfo};
use pvpnclient::action::OpenStream;
use pvpnclient::peer::Peer;
use pvpnclient::vpn::{VpnProtocol, VpnStreamKind};
use smallvec::SmallVec;
#[cfg(feature = "mio")]
use crate::connection::CreateTunStream;

use crate::{
    api::{
        connection::{InitialConnectionConfig, PeerInfo},
        state::{PeerConnectionInfo, Protocol},
    },
    connection::{pvpn_client::PvpnClient, streams::{PendingWrite, PollResult, PollWaker, StreamResult, Streams, WouldBlock}},
};
use crate::api::connection::{ConnectivityEvent, EventCallback, PcapFileInfo, StateChangedCallback, IpAddress};
use crate::api::events::{CaptureStopReason, Event};
use crate::api::state::{ConnectionState, PeerConnectionWaitReason, VpnState};
use crate::connection::network_recovery_handler::NetworkRecoveryHandler;
use crate::connection::pcap_stream::PcapStream;

pub(crate) struct PvpnDependencies {
    pub config: InitialConnectionConfig,
    pub streams: Box<dyn Streams>,
    pub client: Box<dyn PvpnClient>,
    pub state_change_callback: Box<dyn StateChangedCallback>,
    pub event_callback: Box<dyn EventCallback>,
}

/// Messages that can be sent to the connection loop.
pub(crate) enum PvpnMessage {
    /// Disconnect the stop the connection loop.
    Disconnect,
    UpdatePeers(Vec<PeerInfo>),
    ConnectivityChange(ConnectivityEvent),
    #[cfg(feature = "mio")]
    UpdateTun(CreateTunStream),
    StartPacketCapture(PcapFileInfo),
    StopPacketCapture,
    RequestStats,
}

pub(crate) type SendPvpnMessage = Box<dyn Fn(PvpnMessage) -> () + Send + Sync>;

/// Starts a new thread with libpvpnclient connection loop.
/// Returns a callback that can be used to send messages ([PvpnMessage]) to the connection loop.
///
/// [create_pvpn_dependencies] factory that builds the connection dependencies (streams,
/// client), executed in connection thread.
pub(crate) fn start_pvpn_connection(
    poll_waker: Box<dyn PollWaker + Send + Sync>,
    create_pvpn_dependencies: impl FnOnce() -> Result<PvpnDependencies, io::Error> + Sync + Send + 'static,
) -> (SendPvpnMessage, JoinHandle<()>) {
    let (message_sender, message_receiver) = mpsc::channel();
    let join_handle = thread::spawn(move || {
        match create_pvpn_dependencies() {
            Ok(deps) => {
                let mut connection = PvpnConnection::new(
                    deps.client,
                    deps.streams,
                    deps.state_change_callback,
                    deps.event_callback,
                    message_receiver,
                    deps.config.network_available,
                    deps.config.peers,
                    deps.config.pcap_file,
                );
                connection.run();
            },
            Err(err) => log::error!("failed to create connection: {err}"),
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
    state_change_callback: Box<dyn StateChangedCallback>,
    event_callback: Box<dyn EventCallback>,
    message_receiver: mpsc::Receiver<PvpnMessage>,
    connection_state: ConnectionState,
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
        state_change_callback: Box<dyn StateChangedCallback>,
        event_callback: Box<dyn EventCallback>,
        message_receiver: mpsc::Receiver<PvpnMessage>,
        network_available: bool,
        peers: Vec<PeerInfo>,
        pcap_file_info: Option<PcapFileInfo>,
    ) -> Self {
        let mut ret = Self {
            client,
            streams,
            state_change_callback,
            event_callback,
            message_receiver,
            connection_state: ConnectionState::Disconnected { error: None },
            peers,
            stream_read_buffer: Box::new([0; STREAM_BUFFER_SIZE]),
            should_stop: false,
            current_tun_error: None,
            network_recovery_handler: NetworkRecoveryHandler::new(network_available),
            pcap_stream: None,
        };
        ret.activate_peers();
        if !ret.network_recovery_handler.is_network_available() {
            ret.client.notify_network_down();
            ret.set_state(
                ConnectionState::Connecting {
                    peers: vec![],
                    wait_reasons: vec!(PeerConnectionWaitReason::WaitingForNetwork)
                })
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
        self.on_connection_loop_end();
    }

    fn on_connection_loop_end(&mut self) {
        // End packet capture if it's still running.
        if let Some(_) = &self.pcap_stream {
            self.stop_packet_capture(|file| CaptureStopReason::Disconnected { file });
        }
        // Make sure to enter disconnected state.
        match &self.connection_state {
            ConnectionState::Disconnected { .. } => {}
            _ => self.set_state(ConnectionState::Disconnected { error: None })
        }
        log::info!("pvpn connection loop finished with state: {:?}", self.connection_state);
    }

    fn update_state(&mut self) {
        let info = self.client.get_tunnel_info();
        let connection_state = self.get_peer_connection_state(&info);
        self.set_state(connection_state);
        if let ConnectionState::Connected { .. } = &self.connection_state {
            self.network_recovery_handler.on_connected();
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
                PvpnMessage::UpdatePeers(peers) => {
                    self.update_peers(peers);
                },
                PvpnMessage::ConnectivityChange(event) => {
                    let tunnel_info = self.client.get_tunnel_info();
                    self.on_connectivity_change(event, &tunnel_info);
                },
                #[cfg(feature = "mio")]
                PvpnMessage::UpdateTun(create_tun_stream) => {
                    if let Err(e) = self.streams.update_tun(create_tun_stream) {
                        log::error!("failed to update tun: {:?}", e);
                    }
                },
                PvpnMessage::StartPacketCapture(file_info) => {
                    self.start_packet_capture(file_info);
                },
                PvpnMessage::StopPacketCapture => {
                    self.stop_packet_capture(|file| CaptureStopReason::Request { file });
                },
                PvpnMessage::RequestStats => {
                    if let Some(stats) = self.client.get_stats() {
                        self.emit_event(stats.into());
                    }
                }
            }
        }
        !self.should_stop
    }

    fn start_packet_capture(&mut self, file_info: PcapFileInfo) {
        let res = PcapStream::new(file_info.clone());
        match res {
            Ok(stream) => {
                self.pcap_stream = Some(stream);
                self.client.set_packet_capture_enabled(true);
                self.emit_event(Event::PacketCaptureStarted { info: file_info });
            }
            Err(e) => {
                log::error!("failed to start packet capture: {:?}", e);
            }
        }
    }

    fn stop_packet_capture(&mut self, reason: fn(PcapFileInfo) -> CaptureStopReason) {
        self.client.set_packet_capture_enabled(false);
        if let Some(stream) = &self.pcap_stream {
            let file = stream.file_info.clone();
            self.pcap_stream = None;
            self.emit_event(Event::PacketCaptureStopped { reason: reason(file) });
        } else {
            self.emit_event(Event::PacketCaptureStopped { reason: CaptureStopReason::AlreadyStopped });
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

                    // The actions below can only be passed to the libpvpnclient
                    ActionKind::Read(_) |
                    ActionKind::Error(_) |
                    ActionKind::Done => {
                        log::error!("Unexpected action pulled from libpvpnclient: {:?}", kind);
                        debug_assert!(false, "Unexpected action pulled from libpvpnclient: {:?}", kind);
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
                self.handle_poll_results(poll_results);
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

    fn handle_poll_results(&mut self, results: Vec<PollResult>) {
        // Use stack-based vector to avoid heap allocations if number of streams is small.
        let mut readable_streams = SmallVec::<[StreamId; 8]>::new();
        for res in &results {
            if res.is_readable {
                readable_streams.push(res.stream_id);
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
        self.read_from_streams(readable_streams);
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

    fn read_from_streams(&mut self, mut stream_ids: SmallVec<[StreamId; 8]>) {
        while stream_ids.len() > 0 {
            let mut next_stream_ids = SmallVec::<[StreamId; 8]>::new();
            for stream_id in &mut stream_ids {
                match self.streams.get_stream(*stream_id) {
                    Some(stream) => {
                        let read_result = stream.read(&mut self.stream_read_buffer[..]);
                        if *stream_id == StreamId::TUN_STREAM_ID {
                            self.current_tun_error = to_tun_error(&read_result);
                        }
                        match read_result {
                            StreamResult::Ok { bytes_count: bytes_read, start_offset, would_block, pending_write: _ } => {
                                if bytes_read > 0 && self.network_recovery_handler.is_network_available() {
                                    // When there's no network, just drop the data from tun device.
                                    let range = start_offset..start_offset+bytes_read;
                                    self.client.push(Action::read(*stream_id, self.stream_read_buffer[range].to_vec()));
                                    self.pull_from_client();
                                }
                                if would_block == WouldBlock::No && bytes_read > 0 {
                                    next_stream_ids.push(*stream_id);
                                }
                            }
                            StreamResult::Err(e) => {
                                log::info!("stream {:?} read error: {:?}", stream_id, e);
                                self.handle_stream_error(*stream_id, &e);
                            }
                            StreamResult::StreamClosed => {
                                log::info!("closing stream {:?}", stream_id);
                                self.client.push(Action::close(*stream_id));
                            }
                        }
                    },
                    None => {
                        log::error!("stream {:?} not found", stream_id);
                    }
                }
            }
            // next_stream_ids now have all the streams that still have data to read. use them as
            // stream_ids for the next iteration.
            stream_ids = next_stream_ids;
        }
    }

    fn handle_write(&mut self, stream_id: StreamId, data: Vec<u8>) {
        match stream_id {
            StreamId::PCAP_STREAM_ID => {
                if let Some(stream) = &mut self.pcap_stream {
                    stream.write(&data);
                    if stream.at_max_size {
                        self.stop_packet_capture(|file| CaptureStopReason::MaxSizeReached { file });
                    }
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
            StreamResult::Ok { pending_write, .. } => {
                self.streams.set_poll_enable_wait_for_write(stream_id, *pending_write == PendingWrite::Yes);
                if *pending_write == PendingWrite::No && stream_id > StreamId::TUN_STREAM_ID {
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

    fn on_connectivity_change(&mut self, event: ConnectivityEvent, tunnel_info: &Option<TunnelInfo>) {
        self.network_recovery_handler.on_connectivity_change(event);
        if self.network_recovery_handler.is_network_available() {
            self.client.notify_network_change();
        } else {
            self.client.notify_network_down();
            self.set_state(network_unavailable_state(tunnel_info, &self.current_tun_error));
        }
    }

    fn handle_stream_error(&mut self, stream_id: StreamId, err: &io::Error) {
        if stream_id > StreamId::TUN_STREAM_ID { // Only notify libpvpnclient about socket errors
            self.network_recovery_handler.on_stream_error(stream_id, err, self.client.monotonic_now());
            self.client.push_error(stream_id, err.kind());
        }
    }

    fn update_peers(&mut self, new_peers: Vec<PeerInfo>) {
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

    fn set_state(&mut self, connection_state: ConnectionState) {
        if connection_state != self.connection_state {
            log::info!("connection state: {:?}", connection_state);
            self.connection_state = connection_state;
            self.state_change_callback.on_state_changed(VpnState {
                interface_state: self.streams.get_tun_interface_state(),
                connection_state: self.connection_state.clone(),
            });
        }
    }

    fn emit_event(&self, event: Event) {
        log::debug!("emitting event: {:?}", event);
        self.event_callback.on_event(event);
    }

    fn get_peer_connection_state(&mut self, tunnel_info: &Option<TunnelInfo>) -> ConnectionState {
        if !self.network_recovery_handler.is_network_available() {
            return network_unavailable_state(tunnel_info, &self.current_tun_error);
        }
        let mut wait_reasons = vec![];
        if let Some(message) = &self.current_tun_error {
            wait_reasons.push(PeerConnectionWaitReason::TunIoError { message: message.clone() });
        }
        match tunnel_info {
            Some(TunnelInfo::Connected { protocol, peer_addr, peer, .. }) => {
                ConnectionState::Connected {
                    peer: get_peer_connection_info(&peer, &peer_addr, *protocol),
                    #[cfg(feature = "local-agent")]
                    agent_info: None,
                }
            }
            Some(TunnelInfo::Connecting { protocol, peer_addr, peer, .. }) => {
                ConnectionState::Connecting {
                    peers: vec![get_peer_connection_info(&peer, &peer_addr, *protocol)],
                    wait_reasons,
                }
            }
            Some(TunnelInfo::Disconnected { .. }) if !self.peers.is_empty() => ConnectionState::Connecting {
                peers: vec![],
                wait_reasons,
            },
            Some(TunnelInfo::Disconnected { .. }) => ConnectionState::Disconnected { error: None },
            None => ConnectionState::Disconnected { error: None },
        }
    }
}

fn to_tun_error(res: &StreamResult) -> Option<String> {
    match res {
        StreamResult::Ok { .. } => None,
        StreamResult::Err(e) => Some(e.to_string()),
        StreamResult::StreamClosed => Some("Stream closed".to_string()),
    }
}

fn network_unavailable_state(tunnel_info: &Option<TunnelInfo>, last_tun_error: &Option<String>) -> ConnectionState {
    let mut wait_reasons = vec![PeerConnectionWaitReason::WaitingForNetwork];
    if let Some(message) = last_tun_error {
        wait_reasons.push(PeerConnectionWaitReason::TunIoError { message: message.clone() });
    }
    let peers = match tunnel_info {
        Some(TunnelInfo::Connected { protocol, peer_addr, peer, .. }) => {
            vec![get_peer_connection_info(&peer, &peer_addr, *protocol)]
        }
        Some(TunnelInfo::Connecting { protocol, peer_addr, peer, .. }) => {
            vec![get_peer_connection_info(&peer, &peer_addr, *protocol)]
        }
        _ => vec![]
    };
    ConnectionState::Connecting { peers, wait_reasons }
}

fn get_peer_id(peer: &Peer, peer_addr: &SocketAddr) -> String {
    peer.tag().unwrap_or(&peer_addr.ip().to_string()).to_string()
}

fn get_peer_connection_info(peer: &Peer, peer_addr: &SocketAddr, protocol: VpnProtocol) -> PeerConnectionInfo {
    PeerConnectionInfo {
        peer_id: get_peer_id(peer, peer_addr),
        entry_ip: IpAddress(peer_addr.ip()),
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