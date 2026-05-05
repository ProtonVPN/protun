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
use base64::Engine;
use ini::ini;
use crate::api::connection::{ConnectionMode, InitialConnectionConfig, IpAddress, PeerInfo, WgClientPrivateKey, WgPeerPublicKey, PEER_PUB_KEY_SIZE_BYTES};

/// Example ini file format (for local agent mode):
/// ```ini
/// [mode]
/// with_local_agent=true
/// user_agent=ProtonVPN/1.0
/// app_version=1.0.0
/// tun_interface_name=protun0
///
/// [peer.server1]
/// server_ip=1.2.3.4
/// server_public_key=base64encodedpublickey==
/// udp_ports=51820,443
/// tcp_ports=443,80
/// tls_ports=443
/// priority=0
/// exit_label=1
///
/// [peer.server2]
/// server_ip=5.6.7.8
/// server_public_key=anotherbase64key==
/// udp_ports=51820
/// tcp_ports=443
/// priority=1
///
/// [fork]
/// username=username
/// password=userpassword
/// ```
pub fn parse_ini_config(path: String) -> Result<(ParsedConfig, Option<ParsedForkConfig>), String> {
    let ini_config = ini!(&path);

    let peers = parse_ini_peers(&ini_config);

    let local_agent: bool = ini_config["mode"]["with_local_agent"].clone().unwrap().parse().unwrap();
    let connection_mode = if local_agent {
        let user_agent = ini_config["mode"]["user_agent"].clone().unwrap();
        let app_version = ini_config["mode"]["app_version"].clone().unwrap();
        ConnectionMode::LocalAgent {
            user_agent,
            app_version,
            settings: Default::default(),
        }
    } else {
        let key = ini_config["mode"]["client_private_key"].clone().unwrap();
        let wg_private_key = WgClientPrivateKey(
            byte_slice_from_base64(&key).try_into().unwrap()
        );
        ConnectionMode::NoLocalAgent { wg_private_key }
    };

    let fork_config = if let ConnectionMode::LocalAgent { app_version, .. } = &connection_mode {
        let fork_ini = ini_config.get("fork");
        if let Some(fork) = fork_ini {
            let username = fork["username"].clone().unwrap();
            let password = fork["password"].clone().unwrap();
            Some(ParsedForkConfig { username, password, app_version: app_version.clone() })
        } else {
            None
        }
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    let tun_interface_name = ini_config["mode"].get("tun_interface_name").cloned().flatten();
    let initial_connection_config = InitialConnectionConfig {
        peers,
        network_available: true,
        pcap_file: None,
        connection_mode,
    };

    Ok((ParsedConfig {
        initial_connection_config,
        #[cfg(target_os = "linux")]
        tun_interface_name
    }, fork_config))
}

fn parse_ini_peers(ini_config: &HashMap<String, HashMap<String, Option<String>>>) -> Vec<PeerInfo> {
    let mut peers: Vec<PeerInfo> = vec![];
    ini_config.iter().for_each(|section| {
        let section_name = section.0;
        let section_fields = section.1;
        if section_name.starts_with("peer.") {
            let peer_id = section_name.strip_prefix("peer.").unwrap().to_string();
            let server_ip = IpAddress(section_fields["server_ip"].clone().unwrap().parse().unwrap());
            let server_public_key = wg_peer_public_key_from_b64(&section_fields["server_public_key"].clone().unwrap());
            let udp_ports = section_fields.get("udp_ports").cloned().flatten().map(|s| parse_ports(&s)).unwrap_or_default();
            let tcp_ports = section_fields.get("tcp_ports").cloned().flatten().map(|s| parse_ports(&s)).unwrap_or_default();
            let tls_ports = section_fields.get("tls_ports").cloned().flatten().map(|s| parse_ports(&s)).unwrap_or_default();
            let priority = section_fields["priority"].clone().map(|s| s.parse().unwrap()).unwrap_or(0);
            let exit_label = section_fields.get("exit_label").cloned().flatten();
            peers.push(PeerInfo {
                peer_id,
                server_ip,
                server_public_key,
                udp_ports,
                tcp_ports,
                tls_ports,
                priority,
                exit_label,
            })
        }
    });
    peers
}

fn parse_ports(ports: &str) -> Vec<u16> {
    ports.split(',')
        .map(|s| s.parse().unwrap())
        .collect()
}

pub struct ParsedForkConfig {
    pub username: String,
    pub password: String,
    pub app_version: String,
}

pub struct ParsedConfig {
    pub initial_connection_config: InitialConnectionConfig,
    #[cfg(target_os = "linux")]
    pub tun_interface_name: Option<String>,
}

fn wg_peer_public_key_from_b64(s: &str) -> WgPeerPublicKey {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .expect("server public key: invalid base64");
    let arr: [u8; PEER_PUB_KEY_SIZE_BYTES] = bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| {
            panic!(
                "server public key: expected {PEER_PUB_KEY_SIZE_BYTES} bytes after decode, got {}",
                v.len()
            )
        });
    WgPeerPublicKey(arr)
}

fn byte_slice_from_base64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .unwrap()
}