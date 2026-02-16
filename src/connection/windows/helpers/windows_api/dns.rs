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

use std::iter::once;
use std::net::{Ipv4Addr, Ipv6Addr};
use windows::core::{GUID, PWSTR};
use windows::Win32::Foundation::{NO_ERROR, WIN32_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{DNS_INTERFACE_SETTINGS, DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER, SetInterfaceDnsSettings};

use crate::utils::vector::{VecDistinct, VecIpv4Addr, VecIpv6Addr};

pub(crate) fn set_adapter_ipv4_dns_servers(interface_guid: GUID, ips: &mut Vec<Ipv4Addr>) -> Result<(), WIN32_ERROR> {
    if ips.is_empty() {
        return Ok(());
    }
    ips.distinct_mut();

    let mut settings: DNS_INTERFACE_SETTINGS = create_settings();
    settings.Flags = DNS_SETTING_NAMESERVER.into();    
    let ips_as_string: String = ips.to_comma_separated_string();
    let mut buffer: Vec<u16> = vec![];
    settings.NameServer = ips_string_to_pwstr(&ips_as_string, &mut buffer);

    set_dns_server(interface_guid, &ips_as_string, &settings)
}

fn create_settings() -> DNS_INTERFACE_SETTINGS {
    let mut settings: DNS_INTERFACE_SETTINGS = DNS_INTERFACE_SETTINGS::default();
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;

    settings
}

fn ips_string_to_pwstr(ips_as_string: &String, buffer: &mut Vec<u16>) -> PWSTR {
    *buffer = ips_as_string.encode_utf16().chain(once(0)).collect();
    PWSTR(buffer.as_ptr() as *mut u16)
}

fn set_dns_server(interface_guid: GUID, ips_as_string: &String, settings: &DNS_INTERFACE_SETTINGS) -> Result<(), WIN32_ERROR> {
    let status: WIN32_ERROR = unsafe { SetInterfaceDnsSettings(interface_guid, settings) };
    if status == NO_ERROR {
        log::info!("DNS servers set successfully ({ips_as_string})");
        Ok(())
    } else {
        log::error!("Failed to set DNS servers ({ips_as_string}). Error status: {}", status.0);
        Err(status)
    }
}

pub(crate) fn set_adapter_ipv6_dns_servers(interface_guid: GUID, ips: &mut Vec<Ipv6Addr>) -> Result<(), WIN32_ERROR> {
    if ips.is_empty() {
        return Ok(());
    }
    ips.distinct_mut();

    let mut settings: DNS_INTERFACE_SETTINGS = create_settings();
    settings.Flags = (DNS_SETTING_IPV6 | DNS_SETTING_NAMESERVER).into();
    let ips_as_string: String = ips.to_comma_separated_string();
    let mut buffer: Vec<u16> = vec![];
    settings.NameServer = ips_string_to_pwstr(&ips_as_string, &mut buffer);

    set_dns_server(interface_guid, &ips_as_string, &settings)
}