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

use std::path::{Path, PathBuf};
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_ALL_ACCESS, KEY_READ};

use crate::connection::windows::helpers::wintun::constants::ADAPTER_NAME;
use crate::utils::vector::VecDistinctString;

pub fn set_network_adapter_status_text(text: &String) {
    log::debug!("Writing network adapter status '{text}' to registry");

    let profiles_subkey: RegKey = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&get_profiles_path(), KEY_ALL_ACCESS) {
        Ok(subkey) => subkey,
        Err(_) => return,
    };

    let mut num_edits: u32 = 0;
    for key in profiles_subkey.enum_keys() {
        if let Ok(profile_key) = key {
            if let Ok(profile_subkey) = profiles_subkey.open_subkey_with_flags(profile_key, KEY_ALL_ACCESS) {
                if let Ok(description) = profile_subkey.get_value::<String, &str>("Description") && description.eq(ADAPTER_NAME) {
                    match profile_subkey.set_value("ProfileName", text) {
                        Ok(_) => num_edits = num_edits + 1,
                        Err(err) => log::error!("Could not edit adapter profile name in the registry. Error: {}", err),
                    }
                }
            }
        }
    }

    log::debug!("Finished writing network adapter status '{text}' to registry (Profiles edited: {num_edits})");
}

fn get_profiles_path() -> PathBuf {
    Path::new("SOFTWARE")
        .join("Microsoft")
        .join("Windows NT")
        .join("CurrentVersion")
        .join("NetworkList")
        .join("Profiles")
}

pub fn get_created_routes() -> Vec<String> {
    log::info!("Fetching created routes from registry");

    let path: PathBuf = get_protun_path();
    let protun_subkey: RegKey = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(&path, KEY_READ) {
        Ok(subkey) => subkey,
        Err(_) => {
            log::error!("Failed to fetch routes from the registry subkey.");
            return vec![];
        },
    };

    match protun_subkey.get_value::<Vec<String>,&str>("RoutingTable") {
        Ok(routes_as_strings) => {
            let result: Vec<String> = routes_as_strings.iter().filter(|s| s.len() > 0).cloned().collect::<Vec<String>>().distinct();
            log::info!("Successfully fetched {} routes from the registry and returning {} non-empty routes.", routes_as_strings.len(), result.len());
            result
        },
        Err(err) => {
            log::error!("Failed to fetch routes from the registry key. Error: {}", err);
            vec![]
        },
    }
}

fn get_protun_path() -> PathBuf {
    Path::new("SOFTWARE")
        .join("Proton AG")
        .join("Proton VPN")
        .join("ProTUN")
}

pub fn set_created_routes(routes: Vec<String>) {
    let routes: Vec<String> = routes.iter().filter(|s| s.len() > 0).cloned().collect::<Vec<String>>().distinct();
    log::info!("Writing {} non-empty created routes to registry:", routes.len());

    let path: PathBuf = get_protun_path();
    let protun_subkey: RegKey = match RegKey::predef(HKEY_LOCAL_MACHINE).create_subkey_with_flags(&path, KEY_ALL_ACCESS) {
        Ok((subkey, _)) => subkey,
        Err(_) => return,
    };

    match protun_subkey.set_value("RoutingTable", &routes) {
        Ok(_) => log::info!("Successfully wrote {} routes to registry", routes.len()),
        Err(err) => log::error!("Could not write routes in the registry. Error: {}", err),
    }
}