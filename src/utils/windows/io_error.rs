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

use std::io::{Error, ErrorKind};

// UDP - WouldBlock / TCP - WouldBlock
// const WSAEINTR: i32 = 10004; // Interrupted function call.
// const WSAEWOULDBLOCK: i32 = 10035; // Resource temporarily unavailable.
// const WSAEINPROGRESS: i32 = 10036; // Operation now in progress.
// const WSAEALREADY: i32 = 10037; // Operation already in progress.
// const WSAEMSGSIZE: i32 = 10040; // Message too long.
// const WSAENOPROTOOPT: i32 = 10042; // Bad protocol option.
// const WSAENOBUFS: i32 = 10055; // No buffer space available.
// const WSAEISCONN: i32 = 10056; // Socket is already connected.
// const WSAENOTCONN: i32 = 10057; // Socket is not connected.

// UDP - WouldBlock / TCP - Fatal
const WSAEACCES: i32 = 10013; // Permission denied.
const WSAENETUNREACH: i32 = 10051; // Network is unreachable.
const WSAENETRESET: i32 = 10052; // Network dropped connection on reset.
const WSAECONNABORTED: i32 = 10053; // Software caused connection abort.
const WSAECONNRESET: i32 = 10054; // Connection reset by peer.
const WSAETIMEDOUT: i32 = 10060; // Connection timed out.
const WSAECONNREFUSED: i32 = 10061; // Connection refused.
const WSAEHOSTUNREACH: i32 = 10065; // No route to host.

// UDP - Fatal / TCP - Fatal
const WSA_INVALID_HANDLE: i32 = 6; // Specified event object handle is invalid.
const WSAEBADF: i32 = 10009; // File handle is not valid.
const WSAEFAULT: i32 = 10014; // Bad address.
const WSAEINVAL: i32 = 10022; // Invalid argument.
const WSAEMFILE: i32 = 10024; // Too many open files.
const WSAENOTSOCK: i32 = 10038; // Socket operation on nonsocket.
const WSAEDESTADDRREQ: i32 = 10039; // Destination address required.
const WSAEPROTONOSUPPORT: i32 = 10043; // Protocol not supported.
const WSAESOCKTNOSUPPORT: i32 = 10044; // Socket type not supported.
const WSAEOPNOTSUPP: i32 = 10045; // Operation not supported.
const WSAEAFNOSUPPORT: i32 = 10047; // Address family not supported by protocol family.
const WSAEADDRINUSE: i32 = 10048; // Address already in use.
const WSAEADDRNOTAVAIL: i32 = 10049; // Cannot assign requested address.
const WSAENETDOWN: i32 = 10050; // Network is down.
const WSAESHUTDOWN: i32 = 10058; // Cannot send after socket shutdown.
const WSAEPROCLIM: i32 = 10067; // Too many processes.
const WSASYSNOTREADY: i32 = 10091; // Network subsystem is unavailable.
const WSAVERNOTSUPPORTED: i32 = 10092; // Winsock.dll version out of range.
const WSANOTINITIALISED: i32 = 10093; // Successful WSAStartup not yet performed.
const WSAEPROVIDERFAILEDINIT: i32 = 10106; // Service provider failed to initialize.

pub enum Transport {
    UDP,
    TCP
}

pub enum SocketErrorAction {
    FatalSocketError,
    WouldBlock
}

pub trait OsErrorToSocketErrorAction {
    fn to_socket_error_action(&self, transport: Transport) -> SocketErrorAction;
}

impl OsErrorToSocketErrorAction for Error {

    /// For the given OS socket error, returns whether the error is:
    /// - Unrecoverable (FatalSocketError)
    /// - Temporary error / Invalid packet (WouldBlock)
    fn to_socket_error_action(&self, transport: Transport) -> SocketErrorAction {
        if self.kind() == ErrorKind::WouldBlock {
            return SocketErrorAction::WouldBlock
        }
        return if let Some(err_code) = self.raw_os_error() {
            match transport {
                Transport::UDP => match err_code {
                    WSA_INVALID_HANDLE | WSAEBADF | WSAEFAULT | WSAEINVAL | WSAEMFILE | WSAENOTSOCK | WSAEDESTADDRREQ |
                    WSAEPROTONOSUPPORT | WSAESOCKTNOSUPPORT | WSAEOPNOTSUPP | WSAEAFNOSUPPORT | WSAEADDRINUSE |
                    WSAEADDRNOTAVAIL | WSAENETDOWN | WSAESHUTDOWN | WSAEPROCLIM | WSASYSNOTREADY | WSAVERNOTSUPPORTED |
                    WSANOTINITIALISED | WSAEPROVIDERFAILEDINIT => SocketErrorAction::FatalSocketError,
                    _ => SocketErrorAction::WouldBlock
                },
                Transport::TCP => match err_code {
                    WSA_INVALID_HANDLE | WSAEBADF | WSAEFAULT | WSAEINVAL | WSAEMFILE | WSAENOTSOCK | WSAEDESTADDRREQ |
                    WSAEPROTONOSUPPORT | WSAESOCKTNOSUPPORT | WSAEOPNOTSUPP | WSAEAFNOSUPPORT | WSAEADDRINUSE |
                    WSAEADDRNOTAVAIL | WSAENETDOWN | WSAESHUTDOWN | WSAEPROCLIM | WSASYSNOTREADY | WSAVERNOTSUPPORTED |
                    WSANOTINITIALISED | WSAEPROVIDERFAILEDINIT | WSAEACCES | WSAENETUNREACH | WSAENETRESET | WSAECONNABORTED |
                    WSAECONNRESET | WSAETIMEDOUT | WSAECONNREFUSED | WSAEHOSTUNREACH => SocketErrorAction::FatalSocketError,
                    _ => SocketErrorAction::WouldBlock
                },
            }
        } else {
            SocketErrorAction::WouldBlock
        }
    }
}