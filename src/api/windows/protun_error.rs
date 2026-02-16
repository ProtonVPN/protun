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

use thiserror::Error;

#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[derive(Debug, Error)]
pub enum ProTunFatalError {
    #[error("Local IP address not found: {0}")]
    NoLocalIp(String),

    #[error("Failed to create a Windows HANDLE: {0}")]
    HandleCreationFailed(String),

    #[error("Failed to start Winsock: {0}")]
    WinsockStartFailed(String),

    #[error("Failed to load the Wintun library: {0}")]
    WintunLibraryLoadingFailed(String),

    #[error("Failed to create Wintun interface: {0}")]
    WintunInterfaceCreationFailed(String),

    #[error("Failed to get the Wintun adapter index: {0}")]
    WintunAdapterIndexFetchFailed(String),

    #[error("Failed to create Wintun session: {0}")]
    WintunSessionCreationFailed(String),

    #[error("Could not set a valid IP address for the Wintun interface: {0}")]
    WintunIpAddressSetupFailed(String),

    #[error("Failed to create the Wintun stream handle: {0}")]
    WintunSessionHandleCreationFailed(String),
}