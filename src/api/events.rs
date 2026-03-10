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

use std::time::Duration;
use crate::api::connection::PcapFileInfo;

/// Connection events emitted by the library and delivered via [crate::api::connection::EventCallback]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
pub enum Event {

    ConnectionStats {
        received_bytes: u64,
        sent_bytes: u64,
        time_since_last_handshake: Duration,
        estimated_loss: f32,
        estimated_round_trip_time: Duration,
    },
    
    PacketCaptureStarted { info: PcapFileInfo },
    PacketCaptureStopped { reason: CaptureStopReason },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
pub enum CaptureStopReason {
    Request { file: PcapFileInfo },
    MaxSizeReached { file: PcapFileInfo },
    Disconnected { file: PcapFileInfo },
    AlreadyStopped,
}