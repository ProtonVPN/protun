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
use pvpnclient::os_interface::time::{FromDuration, Instant, InstantFactory, Monotonic, SystemTime, SystemTimeFactory};

pub(crate) struct RealtimeClock(pub Box<dyn Fn() -> Duration>);
pub(crate) struct MonotonicClock(pub Box<dyn Fn() -> Duration>);

#[derive(Clone)]
pub(crate) struct ClientRealtimeFactory;
impl SystemTimeFactory for ClientRealtimeFactory {
    type SystemTime = SystemTime;

    fn now(&self) -> Self::SystemTime {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Invalid SystemTime value");
        SystemTime::from_duration(duration)
    }
}

impl ClientRealtimeFactory {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[derive(Clone)]
pub(crate) struct ClientMonotonicFactory {
    pub(crate) initial_instant: std::time::Instant
}

impl ClientMonotonicFactory {
    pub(crate) fn new() -> Self {
        Self {
            initial_instant: std::time::Instant::now()
        }
    }

    pub(crate) fn duration_since_initial(&self) -> std::time::Duration {
        std::time::Instant::now().duration_since(self.initial_instant)
    }
}

unsafe impl Monotonic for ClientMonotonicFactory {}
impl InstantFactory for ClientMonotonicFactory {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant::from_duration(self.initial_instant.elapsed())
    }
}