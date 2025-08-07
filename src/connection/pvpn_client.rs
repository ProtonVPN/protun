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

use std::io::ErrorKind;
use pvpnclient::pvpnclient::{Deadline, Peer, PeerAddr, TunnelInfo, WireguardPrivateKey};
use pvpnclient::pvpnclient::Client;
use pvpnclient::pvpnclient::{Action, PvpnReturn, StreamId, Task};
use crate::connection::util::{error_kind_to_socket_err, now};

/// Abstraction over [pvpnclient::pvpnclient::Client]
pub trait PvpnClient {
    fn set_private_key(&mut self, private_key: &WireguardPrivateKey);
    fn set_time(&mut self, time_ns: u64);
    fn need_pull(&self) -> bool;
    fn peer_add(&mut self, peer: Peer);
    fn peer_remove(&mut self, peer_addr: PeerAddr);
    fn pull(&mut self) -> Option<Action>;
    fn push(&mut self, action: Action);
    fn push_error(&mut self, stream_id: StreamId, error_kind: ErrorKind);
    fn get_tunnel_info(&mut self) -> Option<TunnelInfo>;
    fn wakeup_deadline(&self) -> Deadline;
    fn notify_network_change(&mut self);
}

pub(crate) struct PvpnClientImpl<'a> {
    c: Client<'a>,
    need_pull: bool,
    wakeup_deadline: Deadline
}
impl <'a> PvpnClientImpl<'a> {
    pub(crate) fn new() -> Self {
        PvpnClientImpl { c: Client::new(now()), need_pull: true, wakeup_deadline: None }
    }

    fn handle_result<T>(&mut self, result: &PvpnReturn<T>) {
        self.need_pull = matches!(result.task, Task::NeedPull);
        self.wakeup_deadline = result.wakeup_deadline;
    }
}
impl <'a> PvpnClient for PvpnClientImpl<'a> {
    fn set_private_key(&mut self, private_key: &WireguardPrivateKey) {
        let result = &self.c.set_wg_private_key(private_key);
        self.handle_result(result);
    }

    fn set_time(&mut self, time_ns: u64) {
        let result = &self.c.set_time(time_ns);
        self.handle_result(result);
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

    fn push(&mut self, action: Action) {
        let result = &self.c.push(action);
        if let Err(e) = &result.value {
            log::error!("client.push error: {e:?}");
        }
        self.handle_result(result);
    }

    fn push_error(&mut self, stream_id: StreamId, error_kind: ErrorKind) {
        let result = &self.c.push(Action::error(stream_id, error_kind_to_socket_err(error_kind)));
        self.handle_result(result);
    }

    fn notify_network_change(&mut self) {
        let result = &self.c.notify_network_change();
        self.handle_result(result);
    }
    
    fn get_tunnel_info(&mut self) -> Option<TunnelInfo> {
        let tunnel_info = self.c.tunnel_info();
        self.handle_result(&tunnel_info);
        tunnel_info.value
    }
}
