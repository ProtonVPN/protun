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

use crate::{api::connection_unix::OnSocketFdAvailableCallback, connection::streams::{Stream, Streams}};

pub(crate) fn create_unix_tun(
    tun_fd: i32,
) -> Box<dyn Stream> {
    todo!()
}

pub(crate) fn create_unix_streams(
    tun_fd: i32,
    socket_fd_available_callback: Option<Box<dyn OnSocketFdAvailableCallback>>,
) -> Box<dyn Streams> {
    todo!()
}