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

use windows::Win32::Networking::WinSock::{WSACleanup, WSADATA, WSAStartup};

use crate::api::windows::protun_error::ProTunFatalError;

#[derive(Clone)]
pub(crate) struct Winsock {}

unsafe impl Send for Winsock {}
unsafe impl Sync for Winsock {}

impl Winsock {
    pub(crate) fn create() -> Result<Self, ProTunFatalError> {
        log::info!("Initializing Winsock (WSAStartup)");
        let mut data: WSADATA = WSADATA::default();

        unsafe {
            let result: i32 = WSAStartup(0x202, &mut data);
            if result == 0 {
                Ok(Winsock {})
            } else {
                Err(ProTunFatalError::WinsockStartFailed(format!("Winsock startup (WSAStartup) failed. Error code: {result}")))
            }
        }
    }
}

impl Drop for Winsock {
    fn drop(&mut self) {
        log::info!("Terminating Winsock (WSACleanup)");
        unsafe { WSACleanup(); }
    }
}