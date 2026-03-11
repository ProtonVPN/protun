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
use std::sync::Arc;
use windows::Win32::Foundation::HANDLE;
use wintun::Packet;

use crate::api::windows::protun_error::ProTunFatalError;
use crate::connection::streams::{Stream, StreamResult};
use crate::connection::windows::streams::{WindowsStream, WindowsStreamState};
use crate::connection::windows::helpers::wintun::wintun_session::WinTunSession;

pub(crate) struct TunStreamWindows {
    tun: Arc<WinTunSession>,
    handle: HANDLE,
}
impl TunStreamWindows {
    pub fn new(tun: Arc<WinTunSession>) -> Result<TunStreamWindows, ProTunFatalError> {
        log::info!("New Tun interface with ID: {}", tun.interface_index);

        match tun.session.get_read_wait_event() {
            Ok(event) => Ok(TunStreamWindows {
                tun,
                handle: HANDLE(event as *mut _),
            }),
            Err(e) => Err(ProTunFatalError::WintunSessionHandleCreationFailed(format!("Failed to create the Wintun session handle: {e}"))),
        }
    }
}

impl WindowsStream for TunStreamWindows {
    fn handle(&mut self) -> HANDLE {
        self.handle
    }

    fn has_error(&self) -> bool {
        false // WinTun doesn't have an error state, it returns errors on actions
    }
    
    fn get_state(&mut self) -> WindowsStreamState {
        WindowsStreamState {
            is_readable: true,
            is_writable: true,
        }
    }
}

impl Stream for TunStreamWindows {
    fn read(&mut self, buf: &mut [u8]) -> StreamResult {
        match self.tun.session.try_receive() {
            Ok(packet) => match packet {
                Some(packet) => {
                    let packet_size = packet.bytes().len();
                    let buf_size: usize = buf.len();
                    let n_bytes = buf_size.min(packet_size);
                    buf[..n_bytes].copy_from_slice(&packet.bytes()[..n_bytes]);

                    if packet_size > buf_size {
                        log::error!("TUN packet size ({packet_size}) is larger than buffer size ({buf_size})");
                    }

                    StreamResult::ok(n_bytes, false, false)
                }
                None => {
                    StreamResult::ok(0, true, false)
                }
            },
            Err(error) => {
                log::debug!("TUN Windows returned an error: {:?}", error);
                StreamResult::Err(io::Error::new(ErrorKind::Other, error))
            },
        }
    }

    fn write(&mut self, data: Vec<u8>) -> StreamResult {
        let mut unwritten_data = &data[..];

        while !unwritten_data.is_empty() {
            let n_bytes_to_allocate: usize = unwritten_data.len().min(u16::MAX.into());
            let mut packet: Packet = match self
                .tun
                .session
                .allocate_send_packet(n_bytes_to_allocate.try_into().unwrap()) // When this variable is created the maximum value is u16::MAX so it should be safe to unwrap()
            {
                Ok(packet) => packet,
                Err(error) => {
                    return wintun_error_to_result(error);
                }
            };

            let packet_bytes: &mut [u8] = packet.bytes_mut();
            let n_packet_bytes: usize = packet_bytes.len();
            packet_bytes[..n_packet_bytes].copy_from_slice(&unwritten_data[..n_packet_bytes]);

            self.tun.session.send_packet(packet);

            unwritten_data = &unwritten_data[n_packet_bytes..];
        }

        StreamResult::ok(data.len(), false, false)
    }

    fn write_from_buffer(&mut self) -> StreamResult {
        StreamResult::ok(0, false, false)
    }
}

fn wintun_error_to_result(error: wintun::Error) -> StreamResult {
    match error {
        wintun::Error::Io(e) => StreamResult::Err(e),
        _ => StreamResult::Err(io::Error::new(io::ErrorKind::Other, error)),
    }
}
