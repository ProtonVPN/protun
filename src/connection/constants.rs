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

use std::time::Duration;

// Maximum delay for exponential backoff used to recover from network down errors. Every platform
// might be comfortable with different delays, depending on:
// - how reliably we know the state of networking in the system
// - how battery-conscious a given platform is
#[cfg(not(feature = "android"))]
pub(crate) const MAX_DELAYED_NETWORK_CHANGE_DURATION : Duration = Duration::from_secs(10);

// Android have a relatively reliable way of detecting network state changes, but it's also
// battery-conscious, so we'll use a longer max delay to avoid excessive battery drain.
#[cfg(feature = "android")]
pub(crate) const MAX_DELAYED_NETWORK_CHANGE_DURATION : Duration = Duration::from_secs(30);