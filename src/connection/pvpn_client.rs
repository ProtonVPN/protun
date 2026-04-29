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

use std::io;
use std::io::ErrorKind;
use pvpnclient::os_interface::time::{Instant, InstantFactory, SystemTime, SystemTimeFactory};
use pvpnclient::vpn::{WireguardPrivateKey};
use pvpnclient::{Deadline, Settings, TunnelInfo};
use pvpnclient::Client;
use pvpnclient::{Action, PvpnReturn, StreamId, Task};
use pvpnclient::id::CaptureId;
use pvpnclient::os_interface::rand::Seed256;
use pvpnclient::peer::{Peer, PeerAddr};
use pvpnclient::stats::TunnelStats;
use crate::connection::time::{ClientMonotonicFactory, ClientRealtimeFactory};
use crate::connection::util::{error_kind_to_socket_err};

#[cfg(feature = "local-agent")]
use pvpnclient::{Ed25519PrivateKey, LocalAgentAction, LocalAgentCertificate, LocalAgentMessage, MuonAuth};

/// Abstraction over [pvpnclient::pvpnclient::Client]
pub trait PvpnClient {
    fn set_current_time(&mut self) -> (Instant, SystemTime);
    fn need_pull(&self) -> bool;
    fn peer_add(&mut self, peer: Peer);
    fn peer_remove(&mut self, peer_addr: PeerAddr);
    fn pull(&mut self) -> Option<Action>;
    fn push(&mut self, action: Action);
    fn push_error(&mut self, stream_id: StreamId, error_kind: ErrorKind);
    fn get_tunnel_info(&mut self) -> Option<TunnelInfo>;
    fn wakeup_deadline(&self) -> Deadline;
    fn notify_network_change(&mut self);
    fn notify_network_down(&mut self);
    fn get_stats(&mut self) -> Option<TunnelStats>;
    fn monotonic_now(&self) -> Instant;
    fn set_packet_capture_enabled(&mut self, enabled: bool) -> CaptureId;
    fn set_settings(&mut self, settings: Settings);

    #[cfg(feature = "local-agent")]
    fn pull_local_agent(&mut self) -> Option<LocalAgentMessage>;
    #[cfg(feature = "local-agent")]
    fn push_local_agent(&mut self, action: LocalAgentAction);
}
pub(crate) struct PvpnClientImpl<'a> {
    c: Client<'a>,
    need_pull: bool,
    wakeup_deadline: Deadline,
    monotonic_factory: ClientMonotonicFactory,
    realtime_factory: ClientRealtimeFactory,
}

pub(crate) enum PvpnClientMode {

    #[cfg(feature = "local-agent")]
    LocalAgent {
        app_version: String,
        user_agent: String,
        private_key: Option<Ed25519PrivateKey>,
        certificate: Option<LocalAgentCertificate>,
        muon_auth: Option<MuonAuth>,
    },

    NoLocalAgent {
        wg_private_key: WireguardPrivateKey,
    },
}

impl <'a> PvpnClientImpl<'a> {
    pub(crate) fn new(
        monotonic_factory: ClientMonotonicFactory,
        realtime_factory: ClientRealtimeFactory,
        mode: PvpnClientMode,
        seed: fn() -> Seed256
    ) -> Result<Self, io::Error> {
        let builder = Client::builder::<ClientRealtimeFactory, ClientMonotonicFactory>(
            seed(),
            monotonic_factory.now(),
            realtime_factory.now()
        );
        let client = match mode {
            #[cfg(feature = "local-agent")]
            PvpnClientMode::LocalAgent {
                app_version,
                user_agent,
                private_key,
                certificate,
                muon_auth: auth,
            } => {
                let muon_app = muon::App::new(app_version)
                    .map_err(|e| io::Error::new(ErrorKind::Other, e))?
                    .with_user_agent(user_agent);
                builder.with_local_agent(private_key, certificate, muon_app.into(), auth)
            }
            PvpnClientMode::NoLocalAgent { wg_private_key } => {
                builder.no_local_agent().with_wg_private_key(wg_private_key)
            }
        }.build();
        Ok(PvpnClientImpl {
            c: client,
            need_pull: true,
            wakeup_deadline: None,
            monotonic_factory,
            realtime_factory
        })
    }

    fn handle_result<T>(&mut self, result: &PvpnReturn<T>) {
        self.need_pull = matches!(result.task, Task::NeedPull);
        self.wakeup_deadline = result.wakeup_deadline;
    }
}
impl <'a> PvpnClient for PvpnClientImpl<'a> {

    fn set_current_time(&mut self) -> (Instant, SystemTime) {
        let monotonic_now = self.monotonic_factory.now();
        let realtime_now = self.realtime_factory.now();
        let result = &self.c.set_time::<ClientRealtimeFactory, ClientMonotonicFactory>(
            monotonic_now,
            realtime_now
        );
        self.handle_result(result);
        (monotonic_now, realtime_now)
    }

    fn need_pull(&self) -> bool { self.need_pull }

    fn wakeup_deadline(&self) -> Deadline { self.wakeup_deadline }

    fn peer_add(&mut self, peer: Peer) {
        let result = &self.c.add_peer(peer);
        self.handle_result(result);
    }

    fn peer_remove(&mut self, peer_addr: PeerAddr) {
        let result = &self.c.remove_peer(peer_addr);
        self.handle_result(result);
    }

    fn pull(&mut self) -> Option<Action> {
        let pull_result = self.c.pull();
        self.handle_result(&pull_result);
        pull_result.value
    }

    #[cfg(feature = "local-agent")]
    fn pull_local_agent(&mut self) -> Option<LocalAgentMessage> {
        self.c.pull_local_agent()
    }

    #[cfg(feature = "local-agent")]
    fn push_local_agent(&mut self, action: LocalAgentAction) {
        let result = &self.c.push_local_agent(action);
        self.handle_result(result);
    }

    fn push(&mut self, action: Action) {
        let result = &self.c.push(action);
        if let Err(e) = &result.value {
            log::error!("client.push error: {e:?}");
        }
        self.handle_result(result);
    }

    fn push_error(&mut self, stream_id: StreamId, error_kind: ErrorKind) {
        self.push(Action::error(stream_id, error_kind_to_socket_err(error_kind)));
    }

    fn notify_network_change(&mut self) {
        let result = &self.c.notify_network_change();
        self.handle_result(result);
    }

    fn notify_network_down(&mut self) {
        // no-op in real impl, libpvpnclient will find it out based on socket errors,
        // needed for testing
    }

    fn get_tunnel_info(&mut self) -> Option<TunnelInfo> {
        let tunnel_info = self.c.tunnel_info();
        self.handle_result(&tunnel_info);
        tunnel_info.value
    }

    fn get_stats(&mut self) -> Option<TunnelStats> {
        let tunnel_stats = self.c.tunnel_stats();
        self.handle_result(&tunnel_stats);
        tunnel_stats.value
    }

    fn monotonic_now(&self) -> Instant {
        self.monotonic_factory.now()
    }

    fn set_settings(&mut self, settings: Settings) {
        let result = self.c.set_settings(settings);
        self.handle_result(&result);
    }

    fn set_packet_capture_enabled(&mut self, enabled: bool) -> CaptureId {
        let capture_id = if enabled {
            self.c.capture_packet()
        } else {
            self.c.stop_capture_packet()
        };
        self.handle_result(&capture_id);
        capture_id.value
    }
}
