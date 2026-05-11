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

use crate::api::local_agent::NetshieldLevel;
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use proton_vpn_local_agent::types::{HandledJail, RedisBoolean, ToHandleJail, UnixTimestamp};
use pvpnclient::{Jail, Jails, LocalAgentError, LocalAgentMessage, LocalAgentValue};
use crate::api::connection::IpAddress;
use crate::api::events::{ErrorEvent, Event};
use crate::api::local_agent::WaitJailReason;
use crate::api::state::{AgentConnectionWaitReason, ConnectionState, PeerConnectionInfo, Protocol};
use crate::connection::local_agent_handler::LocalAgentHandler;

#[test]
fn established_transitions_to_connected() {
    let mut handler = LocalAgentHandler::new();

    assert!(matches!(
        handler.get_state(peer("1.2.3.4")),
        ConnectionState::ConnectingToLocalAgent { wait_reason: None, .. }
    ));

    handler.handle_message(LocalAgentMessage::LocalAgentConnected);
    assert!(matches!(
        handler.get_state(peer("1.2.3.4")),
        ConnectionState::Connected { agent_info: Some(_), .. }
    ));
}

#[test]
fn connecting_when_soft_jailed() {
    let mut handler = LocalAgentHandler::new();
    handler.handle_message(LocalAgentMessage::LocalAgentConnected);
    handler.handle_message(LocalAgentMessage::Value(LocalAgentValue::SettingsSoftjail(Some(RedisBoolean(true)))));
    assert!(matches!(
        handler.get_state(peer("1.2.3.4")),
        ConnectionState::ConnectingToLocalAgent {
            wait_reason: Some(AgentConnectionWaitReason::SoftJailed), ..
        }
    ));
}

#[test]
fn connecting_when_hard_jailed() {
    let mut handler = LocalAgentHandler::new();
    handler.handle_message(LocalAgentMessage::LocalAgentConnected);
    handler.handle_message(LocalAgentMessage::Value(LocalAgentValue::Jails(Some(
        Jails(HashSet::from([Jail::ToHandle(ToHandleJail::PolicyViolation1("low plan".to_string()))]))
    ))));
    assert!(matches!(
        handler.get_state(peer("1.2.3.4")),
        ConnectionState::ConnectingToLocalAgent {
            wait_reason: Some(AgentConnectionWaitReason::HardJailed { ref jails }), ..
        } if jails.len() == 1 && matches!(&jails[0], WaitJailReason::LowPlan { .. })
    ));

    // Clearing jail -> connected
    handler.handle_message(LocalAgentMessage::Value(LocalAgentValue::Jails(None)));
    assert!(matches!(handler.get_state(peer("1.2.3.4")), ConnectionState::Connected { .. }));
}

#[test]
fn internal_jails_are_mapped_to_internal_variant() {
    let mut handler = LocalAgentHandler::new();
    handler.handle_message(LocalAgentMessage::LocalAgentConnected);
    handler.handle_message(LocalAgentMessage::Value(LocalAgentValue::Jails(Some(
        Jails(HashSet::from([Jail::InternallyHandled(HandledJail::ExpiredCertificate("cert expired".to_string()))]))
    ))));
    assert!(matches!(
        handler.get_state(peer("1.2.3.4")),
        ConnectionState::ConnectingToLocalAgent {
            wait_reason: Some(AgentConnectionWaitReason::HardJailed { ref jails }), ..
        } if jails.len() == 1 && matches!(&jails[0], WaitJailReason::Internal { .. })
    ));
}

#[test]
fn peer_change_resets_established_and_settings() {
    let mut handler = LocalAgentHandler::new();
    let peer1 = peer("1.1.1.1");
    handler.on_connected_to_peer(&peer1);
    handler.handle_message(LocalAgentMessage::LocalAgentConnected);
    handler.handle_message(LocalAgentMessage::Value(
        LocalAgentValue::SettingsNetshieldLevel(Some(pvpnclient::NetshieldLevel::AdsAndMalwareFilter)))
    );
    assert!(matches!(
        handler.get_state(peer1),
        ConnectionState::Connected { agent_info: Some(agent_info), .. }
            if agent_info.settings.netshield_level == Some(NetshieldLevel::AdsAndMalwareFilter)
    ));

    let peer2 = peer("2.2.2.2");
    handler.on_connected_to_peer(&peer2);
    assert!(matches!(
        handler.get_state(peer2.clone()),
        ConnectionState::ConnectingToLocalAgent { wait_reason: None, .. }
    ));

    handler.handle_message(LocalAgentMessage::LocalAgentConnected);
    assert!(matches!(
        handler.get_state(peer2),
        ConnectionState::Connected { agent_info: Some(agent_info), .. } if agent_info.settings.netshield_level == None
    ));
}

#[test]
fn same_peer_reconnect_preserves_established() {
    let mut handler = LocalAgentHandler::new();
    let p = peer("1.1.1.1");
    handler.on_connected_to_peer(&p);
    handler.handle_message(LocalAgentMessage::LocalAgentConnected);
    handler.on_connected_to_peer(&p);
    assert!(matches!(handler.get_state(p), ConnectionState::Connected { .. }));
}

#[test]
fn auth_error_emits_api_session_expired() {
    let mut handler = LocalAgentHandler::new();
    let event = handler.handle_message(LocalAgentMessage::Error(LocalAgentError::Authentication));
    assert!(matches!(event, Some(Event::Error { error: ErrorEvent::ApiSessionExpired })));
}

#[test]
fn cert_error_emits_certificate_refresh_fatal_error() {
    let mut handler = LocalAgentHandler::new();
    let event = handler.handle_message(LocalAgentMessage::Error(LocalAgentError::CertificateFetching));
    assert!(matches!(event, Some(Event::Error { error: ErrorEvent::CertificateRefreshFatalError })));
}

#[test]
fn muon_fork_selector_needed_emits_api_session_expired() {
    let mut handler = LocalAgentHandler::new();
    let event = handler.handle_message(LocalAgentMessage::MuonForkSelectorNeeded);
    assert!(matches!(event, Some(Event::Error { error: ErrorEvent::ApiSessionExpired })));
}

fn peer(ip: &str) -> PeerConnectionInfo {
    PeerConnectionInfo {
        peer_id: "p".to_string(),
        entry_ip: IpAddress(IpAddr::from_str(ip).unwrap()),
        protocol: Protocol::WireguardUdp,
        port: 1234,
    }
}

fn timestamp() -> UnixTimestamp {
    UnixTimestamp::from_str("0").unwrap()
}