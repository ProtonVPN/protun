// Copyright (c) 2025 Proton AG
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

use std::{io, net::IpAddr, str::FromStr};

use pvpnclient::{stats::TunnelStats, vpn::{WireguardPrivateKey, WireguardPublicKey}};

use crate::api::connection::{CLIENT_PRIV_KEY_SIZE_BYTES, IpAddress, PEER_PUB_KEY_SIZE_BYTES, WgClientPrivateKey, WgPeerPublicKey, ConnectionMode, CacheKey, PersistentCache};
use crate::api::events::Event;
use crate::connection::pvpn_client::PvpnClientMode;

#[cfg(feature = "local-agent")]
use crate::api::local_agent::{LocalAgentSettings, NetshieldLevel, Restriction};
#[cfg(feature = "local-agent")]
use pvpnclient::{Ed25519PrivateKey, LocalAgentCertificate, MuonAuth, SessionSettings};

#[cfg(feature = "uniffi")]
uniffi::custom_type!(WgClientPrivateKey, Vec<u8>);
#[cfg(feature = "uniffi")]
uniffi::custom_type!(WgPeerPublicKey, Vec<u8>);

#[derive(Debug)]
pub struct KeyConversionError(String);
impl std::fmt::Display for KeyConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for KeyConversionError {}

impl TryFrom<Vec<u8>> for WgClientPrivateKey {
    type Error = KeyConversionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.try_into()
            .map(|bytes| WgClientPrivateKey(bytes))
            .map_err(|_| KeyConversionError(format!("private key must be {} bytes", CLIENT_PRIV_KEY_SIZE_BYTES)))
    }
}

impl From<WgClientPrivateKey> for Vec<u8> {
    fn from(value: WgClientPrivateKey) -> Self {
        value.0.to_vec()
    }
}

impl TryFrom<Vec<u8>> for WgPeerPublicKey {
    type Error = KeyConversionError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        value.try_into()
            .map(|bytes| WgPeerPublicKey(bytes))
            .map_err(|_| KeyConversionError(format!("peer public key must be {} bytes", PEER_PUB_KEY_SIZE_BYTES)))
    }
}

impl From<WgPeerPublicKey> for Vec<u8> {
    fn from(value: WgPeerPublicKey) -> Self {
        value.0.to_vec()
    }
}

impl From<WgClientPrivateKey> for WireguardPrivateKey {
    fn from(value: WgClientPrivateKey) -> Self {
        WireguardPrivateKey { key: value.0 }
    }
}

impl From<WgPeerPublicKey> for WireguardPublicKey {
    fn from(value: WgPeerPublicKey) -> Self {
        WireguardPublicKey { key: value.0 }
    }
}

#[cfg(feature = "uniffi")]
uniffi::custom_type!(IpAddress, String);

impl TryFrom<String> for IpAddress {
    type Error = std::net::AddrParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(IpAddress(IpAddr::from_str(&value)?))
    }
}

impl From<IpAddress> for String {
    fn from(value: IpAddress) -> Self {
        value.0.to_string()
    }
}

impl Event {
    pub(crate) fn from_tunnel_stats(value: TunnelStats, timestamp_ms: i64) -> Self {
        Event::ConnectionStats {
            timestamp_ms,
            received_bytes: value.rx,
            sent_bytes: value.tx,
            time_since_last_handshake: value.time_since_last_handshake,
            estimated_loss: value.estimated_loss,
            estimated_round_trip_time: value.estimated_rtt,
        }
    }
}

#[cfg(feature = "local-agent")]
impl From<LocalAgentSettings> for SessionSettings {
    fn from(value: LocalAgentSettings) -> Self {
        SessionSettings {
            split_tcp: value.split_tcp,
            netshield_level: value.netshield_level.map(Into::into),
            softjail: value.soft_jail,
            port_forwarding: value.port_forwarding,
            random_nat: value.random_nat,
            circumvention_routing: value.circumvention_routing,
        }
    }
}

#[cfg(feature = "local-agent")]
impl From<NetshieldLevel> for pvpnclient::NetshieldLevel {
    fn from(value: NetshieldLevel) -> Self {
        match value {
            NetshieldLevel::None => pvpnclient::NetshieldLevel::None,
            NetshieldLevel::MalwareFilter => pvpnclient::NetshieldLevel::MalwareFilter,
            NetshieldLevel::AdsAndMalwareFilter => pvpnclient::NetshieldLevel::AdsAndMalwareFilter,
        }
    }
}

#[cfg(feature = "local-agent")]
impl From<pvpnclient::NetshieldLevel> for NetshieldLevel {
    fn from(value: pvpnclient::NetshieldLevel) -> Self {
        match value {
            pvpnclient::NetshieldLevel::None => NetshieldLevel::None,
            pvpnclient::NetshieldLevel::MalwareFilter => NetshieldLevel::MalwareFilter,
            pvpnclient::NetshieldLevel::AdsAndMalwareFilter => NetshieldLevel::AdsAndMalwareFilter,
        }
    }
}

#[cfg(feature = "local-agent")]
impl From<proton_vpn_local_agent::types::Restriction> for Restriction {
    fn from(value: proton_vpn_local_agent::types::Restriction) -> Self {
        match value {
            proton_vpn_local_agent::types::Restriction::Streaming(reason) =>
                Restriction::Streaming { reason },
            proton_vpn_local_agent::types::Restriction::Torrent(reason) =>
                Restriction::Torrent { reason },
            proton_vpn_local_agent::types::Restriction::Other { name, reason } =>
                Restriction::Other { name, reason },
        }
    }
}

impl ConnectionMode {

    pub(crate) fn to_pvpn_client_mode(self: &ConnectionMode, cache: &Box<dyn PersistentCache>) -> Result<PvpnClientMode, io::Error> {
        Ok(match self {
            ConnectionMode::NoLocalAgent { wg_private_key } => PvpnClientMode::NoLocalAgent {
                wg_private_key: wg_private_key.clone().into(),
            },

            #[cfg(feature = "local-agent")]
            ConnectionMode::LocalAgent {
                settings: _local_agent_settings,
                app_version,
                user_agent
            } => PvpnClientMode::LocalAgent {
                app_version: app_version.clone(),
                user_agent: user_agent.clone(),
                private_key: cache.get(CacheKey::PrivateKey).map(to_private_key).transpose()?,
                certificate: cache.get(CacheKey::Certificate).map(to_certificate).transpose()?,
                muon_auth: cache.get(CacheKey::ApiSession).map(to_muon_auth).transpose()?,
            }
        })
    }
}

#[cfg(feature = "local-agent")]
fn to_certificate(data: Vec<u8>) -> Result<LocalAgentCertificate, io::Error> {
    let result = LocalAgentCertificate::from_pem(&data);
    match result {
        Ok(cert) => Ok(cert),
        Err(e) =>
            Err(io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse certificate: {e:?}"))),
    }
}

#[cfg(feature = "local-agent")]
fn to_private_key(data: Vec<u8>) -> Result<Ed25519PrivateKey, io::Error> {
    let result = Ed25519PrivateKey::from_pem(&data);
    match result {
        Ok(key) => Ok(key),
        Err(e) =>
            Err(io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse private key: {e:?}"))),
    }
}

#[cfg(feature = "local-agent")]
fn to_muon_auth(data: Vec<u8>) -> Result<MuonAuth, io::Error> {
    let result = MuonAuth::try_from(data.as_slice());
    match result {
        Ok(key) => Ok(key),
        Err(e) =>
            Err(io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse muon auth: {e:?}"))),
    }
}