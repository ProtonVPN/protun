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

use std::io::{self, ErrorKind};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Networking::WinSock::{FD_READ, FD_WRITE, SOCKET, WSACloseEvent, WSACreateEvent, WSAEVENT, WSAEnumNetworkEvents, WSAEventSelect, WSANETWORKEVENTS};

pub(crate) struct SocketHandle {
    pub(crate) raw_socket: SOCKET,
    pub(crate) handle: HANDLE,
    pub(crate) event: WSAEVENT,
}

pub(crate) struct SocketEvent {
    pub(crate) is_readable: bool,
    pub(crate) is_writable: bool,
}

impl SocketHandle {
    pub fn new(raw_socket: SOCKET) -> io::Result<SocketHandle> {
        let event: WSAEVENT = match unsafe { WSACreateEvent() } {
            Ok(event) => event,
            Err(error) => {
                log::error!("Cannot create socket event handle: WSACreateEvent failed");
                return Err(io::Error::new(ErrorKind::Other, error));
            }
        };

        let handle: HANDLE = HANDLE(event.0 as *mut _);
        let select_result: i32 = unsafe { WSAEventSelect(raw_socket, Some(event), (FD_READ | FD_WRITE) as i32) };

        if select_result == 0 {
            Ok(SocketHandle {
                raw_socket: raw_socket,
                handle: handle,
                event: event,
            })
        } else {
            Err(io::Error::new(
                ErrorKind::Other,
                "Cannot create socket event handle: WSAEventSelect failed",
            ))
        }
    }

    pub fn get_events(&mut self) -> SocketEvent {
        unsafe {
            let mut network_events: WSANETWORKEVENTS = std::mem::zeroed();
            WSAEnumNetworkEvents(
                self.raw_socket,
                self.event,
                &mut network_events as *mut WSANETWORKEVENTS,
            );
            
            SocketEvent {
                is_readable: network_events.lNetworkEvents & FD_READ as i32 != 0,
                is_writable: network_events.lNetworkEvents & FD_WRITE as i32 != 0,
            }
        }
    }
}

impl Drop for SocketHandle {
    fn drop(&mut self) {
        match unsafe { WSACloseEvent(self.event) } {
            Ok(_) => log::info!("Socket WSAEVENT successfully closed"),
            Err(error) => log::error!("Failed to close socket WSAEVENT: {error}")
        };
    }
}