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

use pvpnclient::os_interface::rand::CryptoSeedProvider;
use crate::connection::time::{ClientMonotonicFactory, ClientRealtimeFactory};
use crate::{
    api::connection::{Connection, InitialConnectionConfig, StateChangedCallback},
    connection::{mio::{socket_factory_unix::SocketFactoryUnix, streams::MioStreams}, pvpn_client::PvpnClientImpl, pvpn_connection::PvpnMessage},
};
use crate::api::connection::ConnectionStatsCallback;

#[cfg(feature = "apple")]
type TunStreamUnixType = crate::connection::mio::tun_apple::TunStreamApple;

#[cfg(all(feature = "unix", not(feature = "apple")))]
type TunStreamUnixType = crate::connection::mio::tun_unix::TunStreamUnix;

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Connection {

    /// Unix-specific constructor for Connection.
    /// Expects file descriptor of tun device that Connection will take ownership of.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn unix_connect(
        config: InitialConnectionConfig,
        tun_fd: i32,
        state_change_callback: Box<dyn StateChangedCallback>,
        socket_fd_available_callback: Option<Box<dyn OnSocketFdAvailableCallback>>,
        stats_callback: Box<dyn ConnectionStatsCallback>
    ) -> Self {
        let socket_factory = Box::new(SocketFactoryUnix::new(socket_fd_available_callback));
        let (poll, waker) = MioStreams::create_mio_poll_with_waker().expect("Failed to create mio poll");
        Self::connect_internal(
            Box::new(waker),
            move || {
                let tun_stream = Box::new(TunStreamUnixType::new(tun_fd));
                let streams = MioStreams::new(tun_stream, socket_factory, poll).expect("Failed to create mio streams");
                Ok(Box::new(streams))
            },
            move || {
                Box::new(
                    PvpnClientImpl::new(
                        ClientMonotonicFactory::new(),
                        ClientRealtimeFactory::new(),
                        || CryptoSeedProvider::new(rand::rng()).into()
                    )
                )
            },
            state_change_callback.into(),
            stats_callback,
            config,
        ).0
    }

    /// Notifies library that file descriptor for tun device has changed.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_unix_tun(&self, tun_fd: i32) {
        (self.send_pvpn_message)(PvpnMessage::UpdateTun(Box::new(move || Box::new(TunStreamUnixType::new(tun_fd)))));
    }
}

/// Platform callback to notify that server connection socket file descriptor is available.
/// Android uses it to protect server connection socket from being routed via tun device.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait OnSocketFdAvailableCallback: Send + Sync {
    fn on_socket_fd_available(&self, socket_fd: i32);
}
