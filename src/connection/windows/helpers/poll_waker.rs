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

use std::ptr;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{CreateEventW, ResetEvent, SetEvent};

use crate::api::windows::protun_error::ProTunFatalError;
use crate::connection::streams::PollWaker;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowsPollWaker {
    pub(crate) handle: HANDLE,
}

impl WindowsPollWaker {
    pub(crate) fn new() -> Result<Self, ProTunFatalError> {
        let handle: HANDLE = unsafe {
            CreateEventW(Some(ptr::null()), true, false, None)
                .map_err(|e| ProTunFatalError::HandleCreationFailed(format!("Cannot create waker: CreateEventW failed. Win32 error code: {}", e.code())))?
        };
        
        Ok(WindowsPollWaker { handle })
    }

    pub(crate) fn reset(&self) {
        unsafe {
            if let Err(err) = ResetEvent(self.handle) {
                log::error!("Error when resetting the waker handle: {err}");
            }
        }
    }
}

impl PollWaker for WindowsPollWaker {
    fn wake(&self) {
        unsafe {
            if let Err(err) = SetEvent(self.handle) {
                log::error!("Error on wake: {err}");
            }
        }
    }
}

// Awaiting and setting events using the Windows API support multi-thread usage
unsafe impl Send for WindowsPollWaker {}
unsafe impl Sync for WindowsPollWaker {}
