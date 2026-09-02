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
        mono_timestamp_ms: i64, //ms since start of the connection
        received_bytes: u64,
        sent_bytes: u64,
        time_since_last_handshake: Duration,
        estimated_loss: f32,
        estimated_round_trip_time: Duration,
    },

    PacketCaptureStarted { info: PcapFileInfo },
    PacketCaptureStopped { reason: CaptureStopReason },

    #[cfg(feature = "local-agent")]
    LocalAgentStats {
        bytes_received: Option<u64>,
        bytes_sent: Option<u64>,
        malicious_blocked: Option<u64>,
        ads_blocked: Option<u64>,
        trackers_blocked: Option<u64>,
        adult_content_blocked: Option<u64>,
        data_saved: Option<u64>,
    },

    #[cfg(feature = "local-agent")]
    LocalAgentError { error: ErrorEvent },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
#[cfg(feature = "local-agent")]
pub enum ErrorEvent {

    /// Client should provide a new fork selector. Care should be taken to not create a forking loop
    /// where a forked session fails repeatedly.
    ForkSelectorNeeded,

    /// API request failure.
    ApiError {
        endpoint: ApiEndpoint,
        http_code: Option<u16>,
        proton_code: Option<i64>,
        message: Option<String>,

        /// As with [ForkSelectorNeeded] clients need to provide new fork selector if true.
        refresh_token_invalid: bool,
    },

    LocalAgentSettingPolicyRefused { setting: LocalAgentSettingType },

    /// Library was unable to refresh the certificate and gave up. Client should close the connection.
    CertificateRefreshFatalError,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
#[cfg(feature = "local-agent")]
pub enum ApiEndpoint {
    Auth,
    CertificateRefresh,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[cfg(feature = "local-agent")]
#[derive(Debug)]
pub enum LocalAgentSettingType {
    NetshieldLevel,
    Bouncing,
    PortForwarding,
    SplitTcp,
    SafeMode,
    RandomNat,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug)]
pub enum CaptureStopReason {
    Request { file: PcapFileInfo },
    MaxSizeReached { file: PcapFileInfo },
    Disconnected { file: PcapFileInfo },
    AlreadyStopped,
}