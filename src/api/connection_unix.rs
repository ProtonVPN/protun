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

use crate::api::connection::{ConfigUpdate, PersistentCache, TunStreamInfo};
use crate::connection::mio::streams::{MioStream, TunStreamUnixType};
use crate::connection::pvpn_connection::PvpnDependencies;
use crate::connection::time::{ClientMonotonicFactory, ClientRealtimeFactory, MonotonicClock, RealtimeClock};
use crate::{
    api::connection::{Connection, EventCallback, InitialConnectionConfig, StateChangedCallback},
    connection::{mio::{socket_factory_unix::SocketFactoryUnix, streams::MioStreams}, pvpn_client::PvpnClientImpl},
};
use mio::Poll;
use pvpnclient::os_interface::rand::CryptoSeedProvider;
use std::io;
use pvpnclient::os_interface::time::{SinceEpoch, SystemTimeFactory};

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
        socket_protector: Option<Box<dyn SocketProtector>>,
        cache: Box<dyn PersistentCache>,
    ) -> Self {
        let (poll, waker) = MioStreams::create_mio_poll_with_waker().expect("Failed to create mio poll");
        Self::connect_internal(
            Box::new(waker),
            move |_| {
                create_pvpn_dependencies(
                    poll,
                    config,
                    tun_fd,
                    state_change_callback,
                    socket_protector,
                    event_callback,
                    cache,
                )
            }
        )
    }

    /// Notifies library that file descriptor for tun device has changed.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_unix_tun(&self, tun_fd: TunStreamInfo) {
        self.update(ConfigUpdate {
            peers: None,
            #[cfg(feature = "local-agent")]
            settings: None,
            tun: Some(tun_fd),
        })
    }
}

/// Keeps socket connections to a VPN server from being routed through the VPN
/// tunnel by mistake. ProTUN will ask the holder of the connection to "protect"
/// each socket before the socket connects, typically by binding it to
/// a physical network interface.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait SocketProtector: Send + Sync {
    /// Returns whether the socket has been "protected," i.e. bound to an
    /// interface that is not the tunnel.
    fn protect_socket(&self, socket_fd: i32) -> bool;
}

/// Simple wrapper for using closures with the `protect_socket` interface.
impl<F> SocketProtector for F
where
    F: Send + Sync + Fn(i32) -> bool + 'static
{
    fn protect_socket(&self, socket_fd: i32) -> bool {
        self(socket_fd)
    }
}

fn create_pvpn_dependencies(
    poll: Poll,
    config: InitialConnectionConfig,
    tun_fd: Option<i32>,
    state_change_callback: Box<dyn StateChangedCallback>,
    socket_protector: Option<Box<dyn SocketProtector>>,
    event_callback: Box<dyn EventCallback>,
    cache: Box<dyn PersistentCache>,
) -> Result<PvpnDependencies, io::Error> {
    let monotonic_factory = ClientMonotonicFactory::new();
    let realtime_factory = ClientRealtimeFactory::new();

    let socket_factory =
        Box::new(SocketFactoryUnix::new(socket_protector, monotonic_factory.clone()));

    let tun_stream: Option<Box<dyn MioStream>> = if let Some(tun_fd) = tun_fd {
        Some(Box::new(TunStreamUnixType::new(tun_fd)))
    } else {
        None
    };

    // FIXME: plumb this error through to the caller
    // nosemgrep: panic-in-function-returning-result
    let streams = MioStreams::new(tun_stream, socket_factory, poll)
        .expect("Failed to create mio streams");

    let pvpn_client = PvpnClientImpl::new(
        monotonic_factory.clone(),
        realtime_factory.clone(),
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
            monotonic_clock: MonotonicClock(Box::new(move || monotonic_factory.duration_since_initial())),
            realtime_clock: RealtimeClock(Box::new(move || realtime_factory.now().duration_since_epoch())),
            cache,
        }
    )
}
