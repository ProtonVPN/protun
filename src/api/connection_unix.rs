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

use crate::{
    api::connection::{Connection, InitialConnectionConfig, StateChangedCallback},
    connection::factory_unix::create_unix_streams,
};

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
    ) -> Self {
        Self::connect_internal(
            move || create_unix_streams(tun_fd, socket_fd_available_callback),
            state_change_callback.into(),
            config,
        )
    }

    /// Notifies library that file descriptor for tun device has changed.
    #[cfg_attr(feature = "uniffi", uniffi::method)]
    pub fn update_unix_tun(&self, tun_fd: i32) {
        todo!()
    }
}

/// Platform callback to notify that server connection socket file descriptor is available.
/// Android uses it to protect server connection socket from being routed via tun device.
#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait OnSocketFdAvailableCallback: Send + Sync {
    fn on_socket_fd_available(&self, socket_fd: i32);
}
