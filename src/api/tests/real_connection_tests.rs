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

use crate::api::test_utils::muon_test_auth::get_session_fork_selector;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use crate::api::state::{ConnectionState, VpnState};
use crate::api::connection::{CacheKey, Connection};
use crate::api::events::{ErrorEvent, Event};
use crate::api::local_agent::{LocalAgentSettings, NetshieldLevel};
use crate::api::test_utils::test_config_parser::{parse_ini_config, ParsedConfig, ParsedForkConfig};
use crate::api::tests::test_helpers::InMemoryCache;
use std::collections::HashMap;
use std::sync::RwLock;
use crate::api::state::Protocol;

enum TestMessage {
    Event(Event),
    State(VpnState),
}

#[test_log::test]
fn happy_path_unix_connection() {
    let (config, fork_config) = get_config();

    connection_test_template(config, fork_config, |connection, receiver, fork_config| {
        await_state(&receiver, &connection, &fork_config, |state| state.connection_state.is_connected());

        // Enable netshield
        let mut new_settings = LocalAgentSettings::default();
        new_settings.netshield_level = Some(NetshieldLevel::AdsAndMalwareFilter);
        connection.update_local_agent_settings(new_settings);

        // Verify that netshield is enabled
        await_state(&receiver, &connection, &fork_config, |state| match &state.connection_state {
            ConnectionState::Connected { agent_info: Some(agent_info), .. } =>
                agent_info.settings.netshield_level == Some(NetshieldLevel::AdsAndMalwareFilter),
            _ => false
        });
    });
}

#[test_log::test]
fn connect_tcp() {
    let (mut config, fork_config) = get_config();
    let mut peer = config.initial_connection_config.peers[0].clone();
    peer.udp_ports = vec![];
    peer.tcp_ports = vec![443];
    peer.tls_ports = vec![];
    config.initial_connection_config.peers = vec![peer];

    connection_test_template(config, fork_config, |connection, receiver, fork_config| {
        await_state(&receiver, &connection, &fork_config, |state| match &state.connection_state {
            ConnectionState::Connected { peer, .. } => peer.protocol == Protocol::WireguardTcp,
            _ => false
        });
    });
}

#[test_log::test]
fn connect_stealth() {
    let (mut config, fork_config) = get_config();
    let mut peer = config.initial_connection_config.peers[0].clone();
    peer.udp_ports = vec![];
    peer.tcp_ports = vec![];
    peer.tls_ports = vec![443];
    config.initial_connection_config.peers = vec![peer];

    connection_test_template(config, fork_config, |connection, receiver, fork_config| {
        await_state(&receiver, &connection, &fork_config, |state| match &state.connection_state {
            ConnectionState::Connected { peer, .. } => peer.protocol == Protocol::Stealth,
            _ => false
        });
    });
}

fn get_config() -> (ParsedConfig, Option<ParsedForkConfig>) {
    let config_path = std::env::var("REAL_CONNECTION_CONFIG")
        .unwrap_or("./config.ini".to_string());
    parse_ini_config(config_path).expect("Failed to parse config")
}

fn connection_test_template(
    config: ParsedConfig,
    fork_config: Option<ParsedForkConfig>,
    block: fn(&Connection, &Receiver<TestMessage>, &Option<ParsedForkConfig>) -> (),
) {
    let (sender, receiver) = std::sync::mpsc::channel();
    let sender_clone = sender.clone();

    let cache_map = Arc::new(RwLock::new(HashMap::new()));
    let cache = Box::new(InMemoryCache { cache: cache_map.clone() });

    let connection = Connection::unix_connect(
        config.initial_connection_config,
        None, // no TUN
        Box::new(move |s| { let _ = sender_clone.send(TestMessage::State(s)); }),
        Box::new(move |e| { let _ = sender.send(TestMessage::Event(e)); }),
        None,
        cache,
    );

    block(&connection, &receiver, &fork_config);

    connection.disconnect_and_wait();

    // Verify that the cache is populated with session info.
    let cache_unlocked = cache_map.read().unwrap();
    assert!(cache_unlocked.get(&CacheKey::Certificate).is_some());
    assert!(cache_unlocked.get(&CacheKey::PrivateKey).is_some());
    assert!(cache_unlocked.get(&CacheKey::ApiSession).is_some());
}

fn await_state(
    receiver: &Receiver<TestMessage>,
    connection: &Connection,
    fork_config: &Option<ParsedForkConfig>,
    predicate: fn(&VpnState) -> bool
) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while let Ok(msg) = receiver.recv_timeout(deadline - std::time::Instant::now()) {
        match msg {
            TestMessage::Event(event) => {
                match event {
                    Event::Error { error: ErrorEvent::ApiSessionExpired } => {
                        if let Some(fork_config) = fork_config {
                            let user = fork_config.username.clone();
                            let pass = fork_config.password.clone();
                            let fork_selector = get_session_fork_selector(
                                &fork_config.app_version, &user, &pass).into();
                            connection.provide_api_fork_selector(fork_selector);
                        }
                    }
                    _ => {}
                }
            }
            TestMessage::State(state) => {
                if predicate(&state) {
                    return;
                }
            }
        }
    }
    if std::time::Instant::now() >= deadline {
        panic!("Timed out waiting for state");
    }
}