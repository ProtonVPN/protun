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

#[cfg(feature = "mio")]
use crate::connection::mio::streams::MioStream;

mod network_recovery_handler;

#[cfg(test)]
mod tests;

mod constants;
pub(crate) mod pcap_stream;
pub(crate) mod pvpn_client;
pub(crate) mod pvpn_connection;
pub(crate) mod streams;
pub(crate) mod time;
pub(crate) mod util;

#[cfg(feature = "mio")]
pub(crate) mod mio;

#[cfg(feature = "mio")]
pub(crate) type CreateTunStream = Box<dyn FnOnce () -> Box<dyn MioStream> + Send + 'static>;

#[cfg(feature = "windows")]
pub(crate) mod windows;