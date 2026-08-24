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

use std::fmt;
use serde::{Deserialize, Serialize};
use windows::Win32::NetworkManagement::Ndis;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct Luid(pub u64);

impl Luid {
    pub fn interface_luid_index(&self) -> u32 {
        ((self.0 >> 24) & 0xFF_FFFF) as u32
    }

    pub fn interface_type(&self) -> u16 {
        ((self.0 >> 48) & 0xFFFF) as u16
    }

    pub fn to_net_luid_lh(&self) -> Ndis::NET_LUID_LH {
        Ndis::NET_LUID_LH { Value: self.0 }
    }
}

impl From<Ndis::NET_LUID_LH> for Luid {
    fn from(luid: Ndis::NET_LUID_LH) -> Self {
        Luid(unsafe { luid.Value })
    }
}

impl From<wintun::NET_LUID_LH> for Luid {
    fn from(luid: wintun::NET_LUID_LH) -> Self {
        Luid(unsafe { luid.Value })
    }
}

impl fmt::Debug for Luid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Interface LUID")
            .field("Value", &format_args!("{:#018x}", &self.0))
            .field("Interface LUID index", &self.interface_luid_index())
            .field("Interface type", &self.interface_type())
            .finish()
    }
}

impl fmt::Display for Luid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{:#018x} (Index: {}, Type: {})",
            &self.0,
            &self.interface_luid_index(),
            &self.interface_type()
        )
    }
}