// Copyright (c) 2026 Proton AG
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

use std::cmp::min;
use std::io::ErrorKind;
use std::time::Duration;
use pvpnclient::os_interface::time::{Instant, InstantFactory};
use pvpnclient::StreamId;
use crate::api::connection::ConnectivityEvent;
use crate::connection::constants::MAX_DELAYED_NETWORK_CHANGE_DURATION;
use crate::connection::time::ClientMonotonicFactory;

pub(crate) const INITIAL_DELAYED_NETWORK_CHANGE_DURATION : Duration = Duration::from_secs(1);

// Logic to handle race conditions between socket errors and system network state changes.
// On some devices, the system might notify about the network being back prematurely.
// When sockets continue to fail with network down errors, we'll keep trying to recover
// (by calling pvpnclient's notify_network_change) with exponential backoff.
pub(crate) struct NetworkRecoveryHandler {
    send_delayed_network_change_at: Option<<ClientMonotonicFactory as InstantFactory>::Instant>,
    delayed_network_change_duration: Duration,
    network_available: bool, // current system network state, recovery will happen only if true
    initial_duration: Duration,
    max_duration: Duration,
}

impl NetworkRecoveryHandler {
    pub(crate) fn new(network_available: bool) -> Self {
        Self {
            send_delayed_network_change_at: None,
            delayed_network_change_duration: INITIAL_DELAYED_NETWORK_CHANGE_DURATION,
            network_available,
            initial_duration: INITIAL_DELAYED_NETWORK_CHANGE_DURATION,
            max_duration: MAX_DELAYED_NETWORK_CHANGE_DURATION,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_tests(network_available: bool, initial_duration: Duration, max_duration: Duration) -> Self {
        Self {
            send_delayed_network_change_at: None,
            delayed_network_change_duration: initial_duration,
            network_available,
            initial_duration,
            max_duration,
        }
    }

    pub(crate) fn is_network_available(&self) -> bool {
        self.network_available
    }

    pub(crate) fn on_resumed(&mut self, now: Instant, notify_network_change: impl FnOnce()) {
        if self.network_available && let Some(notify_at) = self.send_delayed_network_change_at && now >= notify_at {
            log::info!("applying delayed network change after {:?}...", self.delayed_network_change_duration);
            self.send_delayed_network_change_at = None;
            self.delayed_network_change_duration = min(self.delayed_network_change_duration * 2, self.max_duration);
            notify_network_change()
        }
    }

    // Returns the duration until the next network change should be sent.
    pub(crate) fn wakeup_delay(&self, now: impl FnOnce() -> Instant) -> Option<Duration> {
        if self.network_available && let Some(notify_at) = self.send_delayed_network_change_at {
            let now = now();
            Some(if notify_at > now { notify_at - now } else { Duration::default() })
        } else {
            None
        }
    }

    pub(crate) fn on_successful_socket_open(&mut self) {
        // Let's not notify about network change if we managed to open a socket successfully but
        // keep delay value for exponential backoff if the socket will fail on read/write.
        self.send_delayed_network_change_at = None;
    }

    pub(crate) fn on_connected(&mut self) {
        self.send_delayed_network_change_at = None;
        self.delayed_network_change_duration = self.initial_duration;
    }

    pub(crate) fn on_connectivity_change(&mut self, event: ConnectivityEvent) {
        self.send_delayed_network_change_at = None;
        self.delayed_network_change_duration = self.initial_duration;

        match event {
            ConnectivityEvent::Up => {
                log::info!("network is now available");
                self.network_available = true;
            }
            ConnectivityEvent::NetworkSwitch => {
                log::info!("network adapters changed. resetting connection...");
                self.network_available = true;
            }
            ConnectivityEvent::Down => {
                log::info!("network lost");
                self.network_available = false;
            }
        }
    }

    pub(crate) fn on_stream_error(&mut self, stream_id: StreamId, err: &std::io::Error, now: Instant) {
        if self.network_available {
            match err.kind() {
                ErrorKind::NetworkUnreachable | ErrorKind::NetworkDown => {
                    self.send_delayed_network_change_at = Some(now + self.delayed_network_change_duration);
                    log::error!("network down on stream {:?}: {:?}. Will retry in {:?}",
                        stream_id, err, self.delayed_network_change_duration);
                },
                _ => {}
            };
        }
    }
}