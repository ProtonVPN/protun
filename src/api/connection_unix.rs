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

use crate::api::connection::PersistentCache;
use crate::connection::mio::streams::MioStream;
use crate::connection::pvpn_connection::PvpnDependencies;
use crate::connection::time::{ClientMonotonicFactory, ClientRealtimeFactory};
use crate::{
    api::connection::{Connection, EventCallback, InitialConnectionConfig, StateChangedCallback},
    connection::{mio::{socket_factory_unix::SocketFactoryUnix, streams::MioStreams}, pvpn_client::PvpnClientImpl, pvpn_connection::PvpnMessage},
};
use mio::Poll;
use pvpnclient::os_interface::rand::CryptoSeedProvider;
use std::io;

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
        tun_fd: Option<i32>,
        state_change_callback: Box<dyn StateChangedCallback>,
        event_callback: Box<dyn EventCallback>,
        socket_fd_available_callback: Option<Box<dyn OnSocketFdAvailableCallback>>,
        cache: Box<dyn PersistentCache>,
    ) -> Self {
        let (poll, waker) = MioStreams::create_mio_poll_with_waker().expect("Failed to create mio poll");
        Self::connect_internal(
            Box::new(waker),
            move || {
                create_pvpn_dependencies(
                    poll,
                    config,
                    tun_fd,
                    state_change_callback,
                    socket_fd_available_callback,
                    event_callback,
                    cache,
                )
            }
        )
    }

    /// Notifies library that file descriptor for tun device has changed.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_unix_tun(&self, tun_fd: Option<i32>) {
        (self.send_pvpn_message)(PvpnMessage::UpdateTun(
            Box::new(move || {
                if let Some(tun_fd) = tun_fd {
                    Some(Box::new(TunStreamUnixType::new(tun_fd)))
                } else {
                    None
                }
            }))
        );
    }
}

/// Platform callback to notify that server connection socket file descriptor is available.
/// Android uses it to protect server connection socket from being routed via tun device.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait OnSocketFdAvailableCallback: Send + Sync {
    fn on_socket_fd_available(&self, socket_fd: i32);
}

/// Blanket implementation to allow using closures as state change callbacks.
impl<F> OnSocketFdAvailableCallback for F
where
    F: Send + Sync + Fn(i32) + 'static
{
    fn on_socket_fd_available(&self, socket_fd: i32) {
        self(socket_fd);
    }
}

fn create_pvpn_dependencies(
    poll: Poll,
    config: InitialConnectionConfig,
    tun_fd: Option<i32>,
    state_change_callback: Box<dyn StateChangedCallback>,
    socket_fd_available_callback: Option<Box<dyn OnSocketFdAvailableCallback>>,
    event_callback: Box<dyn EventCallback>,
    cache: Box<dyn PersistentCache>,
) -> Result<PvpnDependencies, io::Error> {
    let socket_factory =
        Box::new(SocketFactoryUnix::new(socket_fd_available_callback));

    let tun_stream: Option<Box<dyn MioStream>> = if let Some(tun_fd) = tun_fd {
        Some(Box::new(TunStreamUnixType::new(tun_fd)))
    } else {
        None
    };

    let streams = MioStreams::new(tun_stream, socket_factory, poll)
        .expect("Failed to create mio streams");

    let pvpn_client = PvpnClientImpl::new(
        ClientMonotonicFactory::new(),
        ClientRealtimeFactory::new(),
        config.connection_mode.to_pvpn_client_mode(&cache)?,
        || CryptoSeedProvider::new(rand::rng()).into()
    )?;

    Ok(
        PvpnDependencies {
            config,
            streams: Box::new(streams),
            client: Box::new(pvpn_client),
            state_change_callback,
            event_callback,
            cache,
        }
    )
}
