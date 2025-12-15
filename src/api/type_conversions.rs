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

use std::{net::IpAddr, str::FromStr};

use pvpnclient::vpn::{WireguardPublicKey, WireguardPrivateKey};

use crate::api::connection::{CLIENT_PRIV_KEY_SIZE_BYTES, PEER_PUB_KEY_SIZE_BYTES, IpAddress, WgClientPrivateKey, WgPeerPublicKey};

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