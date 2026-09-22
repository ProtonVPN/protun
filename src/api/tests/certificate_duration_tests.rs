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

use pvpnclient::CertificateApiDuration;
use crate::api::connection::{CertificateDuration, ConnectionMode, MuonEnv, PersistentCache};
use crate::api::tests::test_helpers::InMemoryCache;
use crate::connection::pvpn_client::PvpnClientMode;

fn local_agent_mode(certificate_duration: Option<CertificateDuration>) -> ConnectionMode {
    ConnectionMode::LocalAgent {
        user_agent: "protun-test".to_string(),
        app_version: "android-vpn@0.0.0".to_string(),
        settings: Default::default(),
        muon_env: MuonEnv::Prod,
        certificate_duration,
    }
}

/// What the client mode carries for the pvpnclient builder.
fn duration_for_builder(mode: &ConnectionMode) -> Option<CertificateApiDuration> {
    let cache: Box<dyn PersistentCache> = Box::new(InMemoryCache::new());
    match mode.to_pvpn_client_mode(&cache).expect("an empty cache converts") {
        PvpnClientMode::LocalAgent { certificate_duration, .. } => certificate_duration,
        PvpnClientMode::NoLocalAgent { .. } => panic!("expected the local agent mode"),
    }
}

#[test]
fn the_api_picks_the_lifetime_unless_the_config_names_one() {
    assert!(duration_for_builder(&local_agent_mode(None)).is_none());
}

/// Every unit reaches the request in the words the API expects.
#[test]
fn the_configured_lifetime_reaches_the_pvpnclient_builder() {
    let cases = [
        (CertificateDuration::Seconds { count: 90 }, "90 seconds"),
        (CertificateDuration::Minutes { count: 30 }, "30 minutes"),
        (CertificateDuration::Hours { count: 8 }, "8 hours"),
        (CertificateDuration::Days { count: 365 }, "365 days"),
    ];
    for (configured, expected) in cases {
        let for_builder = duration_for_builder(&local_agent_mode(Some(configured)))
            .expect("the configured lifetime is kept");
        assert_eq!(String::from(for_builder), expected);
    }
}
