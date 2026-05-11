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

use std::collections::HashMap;
use proton_vpn_local_agent::types::{HandledJail, NetshieldBlockList, ToHandleJail};
use crate::api::local_agent::{AgentConnectionInfo, Restriction, WaitJailReason};
use crate::api::state::{AgentConnectionWaitReason, ConnectionState, PeerConnectionInfo};
use pvpnclient::{LocalAgentSelector, LocalAgentValue};
use pvpnclient::{Jail, Jails, LocalAgentError, LocalAgentMessage, LocalAgentServerError, UnixTimestamp};
use crate::api::events::{ErrorEvent, Event, LocalAgentSettingType};

pub(crate) struct LocalAgentHandler {
    is_connected: bool,
    last_peer: Option<PeerConnectionInfo>,
    agent_info: AgentConnectionInfo,
    established_ts: Option<UnixTimestamp>,
    exit_label: Option<String>,
    jails: Vec<WaitJailReason>,
    restrictions: Vec<Restriction>,
}

impl LocalAgentHandler {
    pub(crate) fn new() -> Self {
        Self {
            is_connected: false,
            last_peer: None,
            agent_info: AgentConnectionInfo::default(),
            exit_label: None,
            established_ts: None,
            jails: Vec::new(),
            restrictions: Vec::new(),
        }
    }

    pub(crate) fn get_state(&self, peer: PeerConnectionInfo) -> ConnectionState {
        if let Some(wait_reason) = self.get_wait_reason() {
            ConnectionState::ConnectingToLocalAgent { peer, wait_reason: Some(wait_reason) }
        } else if self.is_connected {
            ConnectionState::Connected {
                peer,
                agent_info: Some(self.agent_info.clone()),
            }
        } else {
            ConnectionState::ConnectingToLocalAgent { peer, wait_reason: None }
        }
    }

    pub(crate) fn get_wait_reason(&self) -> Option<AgentConnectionWaitReason> {
        if let Some(true) = self.agent_info.settings.soft_jail {
            Some(AgentConnectionWaitReason::SoftJailed)
        } else if !self.jails.is_empty() {
            Some(AgentConnectionWaitReason::HardJailed { jails: self.jails.clone() })
        } else {
            None
        }
    }

    pub(crate) fn on_connected_to_peer(&mut self, peer: &PeerConnectionInfo) {
        let new_peer = peer.clone();
        if let Some(last_peer) = &self.last_peer && new_peer != *last_peer {
            self.is_connected = false;
            self.established_ts = None;
            self.exit_label = None;
            self.agent_info = AgentConnectionInfo::default();
            self.jails.clear();
        }
        self.last_peer = Some(new_peer);
    }
    
    pub(crate) fn handle_message(&mut self, message: LocalAgentMessage) -> Option<Event> {
        match message {
            LocalAgentMessage::Value(value) => self.handle_value(value),
            LocalAgentMessage::Error(error) => self.handle_error(error),
            LocalAgentMessage::MuonForkSelectorNeeded => {
                Some(Event::Error { error: ErrorEvent::ApiSessionExpired })
            }
            LocalAgentMessage::LocalAgentConnected => {
                self.is_connected = true;
                None
            }
        }
    }

    #[cfg(feature = "local-agent")]
    pub(crate) fn local_agent_selectors_to_watch() -> Vec<LocalAgentSelector> {
        vec![
            LocalAgentSelector::InfoEstablished,
            LocalAgentSelector::InfoGroups,
            // LocalAgentSelector::InfoPlatform,
            LocalAgentSelector::InfoRemote,
            //LocalAgentSelector::Restrictions, //TODO(VPNCORE-112): causes connection error when watched
            LocalAgentSelector::SettingsCircumventionRouting,
            LocalAgentSelector::SettingsLabel,
            LocalAgentSelector::SettingsNetshieldLevel,
            LocalAgentSelector::SettingsPortForwarding,
            LocalAgentSelector::SettingsRandomNat,
            LocalAgentSelector::SettingsSoftjail,
            LocalAgentSelector::SettingsSplitTcp,
            LocalAgentSelector::Jails,
        ]
    }

    fn handle_value(&mut self, value: LocalAgentValue) -> Option<Event> {
        // When adding new values here, list in local_agent_selectors_to_watch should be updated as well.
        match value {
            LocalAgentValue::InfoEstablished(timestamp) =>
                self.established_ts = timestamp,

            LocalAgentValue::InfoGroups(value) =>
                self.agent_info.groups = value.map(|v| v.0).unwrap_or_default(),

            LocalAgentValue::InfoPlatform(_) => {} // not used for now

            LocalAgentValue::InfoRemote(value) =>
                self.agent_info.user_isp_ip = value.map(|v| v.0),

            LocalAgentValue::Restrictions(restrictions) => {
                self.restrictions = if let Some(restrictions)  = restrictions {
                    restrictions.0.into_iter().map(Into::into).collect()
                } else {
                    Vec::new()
                };
            }

            LocalAgentValue::SettingsCircumventionRouting(value) =>
                self.agent_info.settings.circumvention_routing = value.map(|v| v.0),

            LocalAgentValue::SettingsLabel(value) =>
                self.exit_label = value.map(|v| v.0),

            LocalAgentValue::SettingsNetshieldLevel(value) =>
                self.agent_info.settings.netshield_level = value.map(Into::into),

            LocalAgentValue::SettingsPortForwarding(value) =>
                self.agent_info.settings.port_forwarding = value.map(|v| v.0),

            LocalAgentValue::SettingsRandomNat(value) =>
                self.agent_info.settings.random_nat = value.map(|v| v.0),

            LocalAgentValue::SettingsSoftjail(value) =>
                self.agent_info.settings.soft_jail = value.map(|v| v.0),

            LocalAgentValue::SettingsSplitTcp(value) =>
                self.agent_info.settings.split_tcp = value.map(|v| v.0),

            LocalAgentValue::StatsBytesReceived(_) |
            LocalAgentValue::StatsBytesSent(_) => {} // handled in LocalAgentValue::Stats

            LocalAgentValue::StatsNetshieldBlockCountMalicious(_) => {}
            LocalAgentValue::StatsNetshieldBlockCountAds(_) => {}
            LocalAgentValue::StatsNetshieldBlockCountTracking(_) => {}
            LocalAgentValue::StatsNetshieldBlockCountAdult(_) => {} // handled in LocalAgentValue::Stats

            LocalAgentValue::Stats(value) =>
                if let Some(stats) = value {
                    return Some(stats.into())
                },

            //TODO(VPNCORE-108): implement when ready in libvpnclient
            //LocalAnentValue::ExitInfo(_)

            LocalAgentValue::Jails(jails) =>
                return self.handle_jails(jails),
        }
        None
    }
    
    fn handle_jails(&mut self, jails: Option<Jails>) -> Option<Event> {
        self.jails.clear();
        if let Some(jails) = jails {
            jails.0.into_iter().for_each(|jail| {
                let wait_reason: WaitJailReason = match jail {
                    Jail::InternallyHandled(jail) => match jail {
                        HandledJail::SystemError(message) => WaitJailReason::Internal { message },
                        HandledJail::ExpiredCertificate(message) => WaitJailReason::Internal { message },
                        HandledJail::RevokedCertificate(message) => WaitJailReason::Internal { message },
                        HandledJail::KeyAlreadyUsed(message) => WaitJailReason::Internal { message },
                        HandledJail::InvalidCertificateSignature(message) => WaitJailReason::Internal { message },
                    }
                    Jail::ToHandle(jail) => match jail {
                        ToHandleJail::RequireRecent2FA(message) => WaitJailReason::Need2FA { message },
                        ToHandleJail::Expired2FA(message) => WaitJailReason::Need2FA { message },
                        ToHandleJail::Require2FA(message) => WaitJailReason::Need2FA { message },
                        ToHandleJail::WaitingClientChallengeReply(message) => WaitJailReason::WaitingClientChallengeReply { message },

                        ToHandleJail::PolicyViolation1(message) => WaitJailReason::LowPlan { message },
                        ToHandleJail::PolicyViolation2(message) => WaitJailReason::PendingInvoice { message },
                        ToHandleJail::BadUserBehavior(message) => WaitJailReason::BadUserBehavior { message },
                        ToHandleJail::DisabledUser(message) => WaitJailReason::DisabledUser { message },
                        ToHandleJail::SessionOverLimit(message) => WaitJailReason::SessionOverLimit { message },
                        ToHandleJail::FreeSessionOverLimit(message) => WaitJailReason::SessionOverLimit { message },
                        ToHandleJail::BasicSessionOverLimit(message) => WaitJailReason::SessionOverLimit { message },
                        ToHandleJail::PlusSessionOverLimit(message) => WaitJailReason::SessionOverLimit { message },
                        ToHandleJail::VisionarySessionOverLimit(message) => WaitJailReason::SessionOverLimit { message },
                        ToHandleJail::ProSessionOverLimit(message) => WaitJailReason::SessionOverLimit { message },

                        //TODO(VPNCORE-108): should be HandledJail?
                        ToHandleJail::GuestSession(message) => {
                            // should not happen
                            log::warn!("GuestSession: {:?}", message);
                            WaitJailReason::Internal { message }
                        }
                        ToHandleJail::RestrictedServer(message) => WaitJailReason::Internal { message },
                        ToHandleJail::NoCertificateProvided(message) => WaitJailReason::Internal { message },
                        ToHandleJail::SessionInstallationInProgress(message) => WaitJailReason::Internal { message },

                        ToHandleJail::Unknown(code, msg) =>
                            WaitJailReason::Other { code, message: msg },
                    }
                };
                self.jails.push(wait_reason);
            });
        }
        None
    }
    
    fn handle_error(&mut self, error: LocalAgentError) -> Option<Event> {
        match error {
            LocalAgentError::Authentication =>
                return Some(Event::Error { error: ErrorEvent::ApiSessionExpired }),

            LocalAgentError::CertificateFetching =>
                return Some(Event::Error { error: ErrorEvent::CertificateRefreshFatalError }),

            LocalAgentError::ServerError(e) => {
                match e {
                    LocalAgentServerError::UnknownFeatureRequest =>
                        log::warn!("Unknown feature request"),

                    LocalAgentServerError::BadMessageSyntax =>
                        log::warn!("Bad message syntax"),

                    LocalAgentServerError::SessionNotFound =>
                        log::warn!("Session not found"),

                    LocalAgentServerError::SessionError =>
                        log::warn!("Session error"),

                    LocalAgentServerError::NetshieldLevelPolicyRefused =>
                        return policy_refused(LocalAgentSettingType::NetshieldLevel),
                    LocalAgentServerError::BouncingPolicyRefused =>
                        return policy_refused(LocalAgentSettingType::Bouncing),
                    LocalAgentServerError::PortFwPolicyRefused =>
                        return policy_refused(LocalAgentSettingType::PortForwarding),
                    LocalAgentServerError::SplitTcpPolicyRefused =>
                        return policy_refused(LocalAgentSettingType::SplitTcp),
                    LocalAgentServerError::SafeModePolicyRefused =>
                        return policy_refused(LocalAgentSettingType::SafeMode),
                    LocalAgentServerError::RandomNatPolicyRefused =>
                        return policy_refused(LocalAgentSettingType::RandomNat),

                    LocalAgentServerError::NetshieldLevelSystemErr |
                    LocalAgentServerError::NetshieldLevelInvalidInput |
                    LocalAgentServerError::BouncingSystemErr |
                    LocalAgentServerError::BouncingInvalidInput |
                    LocalAgentServerError::PortFwSystemErr |
                    LocalAgentServerError::PortFwInvalidInput |
                    LocalAgentServerError::PortFwNotAvailable |
                    LocalAgentServerError::RandomNatSystemErr |
                    LocalAgentServerError::RandomNatInvalidInput |
                    LocalAgentServerError::SplitTcpSystemErr |
                    LocalAgentServerError::SplitTcpInvalidInput |
                    LocalAgentServerError::SoftJailSystemErr |
                    LocalAgentServerError::SoftJailInvalidInput |
                    LocalAgentServerError::SafeModeSystemErr |
                    LocalAgentServerError::SafeModeInvalidInput |
                    LocalAgentServerError::ConflictBouncingVsRandomNat |
                    LocalAgentServerError::ConflictBouncingVsSplitTcp |
                    LocalAgentServerError::ConflictBouncingVsPortFw => {
                        log::warn!("Server error: {}", e);
                    }

                    LocalAgentServerError::Other(message) =>
                        log::warn!("Server error: {}", message),
                }
            }
        }
        None
    }
}

fn policy_refused(setting: LocalAgentSettingType) -> Option<Event> {
    Some(Event::Error { error: ErrorEvent::LocalAgentSettingPolicyRefused { setting } })
}

impl From<proton_vpn_local_agent::types::Stats> for Event {
    fn from(stats: proton_vpn_local_agent::types::Stats) -> Self {
        let malicious_blocked = get_netshield_stats(&stats.netshield_dnsbl, &NetshieldBlockList::Malicious);
        let ads_blocked = get_netshield_stats(&stats.netshield_dnsbl, &NetshieldBlockList::Ads);
        let trackers_blocked = get_netshield_stats(&stats.netshield_dnsbl, &NetshieldBlockList::Tracking);
        let adult_content_blocked = get_netshield_stats(&stats.netshield_dnsbl, &NetshieldBlockList::Adult);
        Event::LocalAgentStats {
            bytes_received: stats.bytes_received,
            bytes_sent: stats.bytes_sent,
            malicious_blocked,
            ads_blocked,
            trackers_blocked,
            adult_content_blocked,
            data_saved: Some(estimate_data_saved(malicious_blocked, ads_blocked, trackers_blocked, adult_content_blocked)),
        }
    }
}

fn get_netshield_stats(stats: &Option<HashMap<NetshieldBlockList, u64>>, list: &NetshieldBlockList) -> Option<u64> {
    stats.as_ref().map(|bl| bl.get(list).cloned()).flatten()
}

const AVG_AD_SIZE_BYTES: u64 = 200 * 1024;
const AVG_TRACKER_SIZE_BYTES: u64 = 50 * 1024;
const AVG_MALICIOUS_SIZE_BYTES: u64 = 750 * 1024;
const AVG_ADULT_CONTENT_SIZE_BYTES: u64 = 1454 * 1024;

fn estimate_data_saved(
    malicious_blocked: Option<u64>,
    ads_blocked: Option<u64>,
    trackers_blocked: Option<u64>,
    adult_content_blocked: Option<u64>,
) -> u64 {
    let mut saved = 0;
    if let Some(malicious_blocked) = malicious_blocked {
        saved += malicious_blocked * AVG_MALICIOUS_SIZE_BYTES;
    }
    if let Some(ads_blocked) = ads_blocked {
        saved += ads_blocked * AVG_AD_SIZE_BYTES;
    };
    if let Some(trackers_blocked) = trackers_blocked {
        saved += trackers_blocked * AVG_TRACKER_SIZE_BYTES;
    };
    if let Some(adult_content_blocked) = adult_content_blocked {
        saved += adult_content_blocked * AVG_ADULT_CONTENT_SIZE_BYTES;
    };
    saved
}