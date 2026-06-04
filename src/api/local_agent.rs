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

use crate::api::connection::IpAddress;

/// Struct to enable/disable local agent features. When [None] is passed, the feature will use the
/// default value.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LocalAgentSettings {
    pub split_tcp: Option<bool>,
    pub netshield_level: Option<NetshieldLevel>,
    pub soft_jail: Option<bool>,
    pub port_forwarding: Option<bool>,
    pub random_nat: Option<bool>,
    pub circumvention_routing: Option<bool>,
}

/// Netshield level
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum NetshieldLevel {
    /// Netshield is disabled
    None,
    /// Netshield filters Malware
    MalwareFilter,
    /// Netshield filters Malware, Ads and Trackers
    AdsAndMalwareFilter,
    /// Netshield filters Malware, Ads, Trackers and Adult
    AdultAndAdsAndMalwareFilter
}

/// Information available after successful connection to the local agent. None field values
/// indicate that the server didn't provide the value at the moment.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug, PartialEq, Default)]
pub struct AgentConnectionInfo {
    pub server_exit_v4: Option<IpAddress>,
    pub server_exit_v6: Option<IpAddress>,
    pub user_isp_ip: Option<String>,
    pub user_isp_country_code: Option<String>,
    pub user_isp_name: Option<String>,
    pub user_isp_coordinates: Option<Coordinates>,
    pub restrictions: Vec<Restriction>,
    pub groups: Vec<String>,

    /// Settings as applied by the server - may differ from the requested settings.
    pub settings: LocalAgentSettings,
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Clone, Debug, PartialEq)]
pub struct Coordinates {
    pub latitude: f64,
    pub longitude: f64,
}

/// Local agent jails. Most require app/user action to be unjailed ([WaitJailReason::Internal] will
/// be handled internally by the library). Messages are not localized and suitable only for
/// logging/debugging.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum WaitJailReason {
    BadUserBehavior { message: String },
    DisabledUser { message: String },
    LowPlan { message: String },
    Need2FA { message: String },
    PendingInvoice { message: String },
    SessionOverLimit { message: String },
    WaitingClientChallengeReply { message: String },
    
    /// Will be handled internally by the library - no action required by the app.
    Internal { message: String },

    /// Unknown error codes, not supported in this version.
    Other { code: u64, message: String },
}

#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Clone, Debug, PartialEq)]
pub enum Restriction {
    Streaming { reason: String },
    Torrent { reason: String },
    Other { name: String, reason: String },
}
