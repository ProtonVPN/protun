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

use windows::core::GUID;

pub const WINTUN_FILE_NAME: &'static str = "wintun.dll";

pub const ADAPTER_GUID_STR: &str = "{9BEB3451-4026-4F8A-8762-8F608B124FEC}";
pub const ADAPTER_GUID_U128: u128 = 207251590231051553767137937883512590316u128; // Obtained from Uuid::parse_str(ADAPTER_GUID_STR).unwrap().as_u128()
pub const ADAPTER_GUID: GUID = GUID::from_u128(ADAPTER_GUID_U128);

pub const ADAPTER_NAME: &'static str = "ProTUN";
pub const ADAPTER_DESCRIPTION: &'static str = "Proton VPN Windows";
