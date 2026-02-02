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

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct TestMonotonicClock {
    current_duration: Arc<Mutex<Duration>>,
}

impl TestMonotonicClock {
    pub(crate) fn new() -> Self {
        Self {
            current_duration: Arc::new(Mutex::new(Duration::from_nanos(0))),
        }
    }

    pub(crate) fn now(&self) -> Duration {
        self.current_duration.lock().unwrap().clone()
    }

    pub(crate) fn set(&self, value: Duration) {
        *self.current_duration.lock().unwrap() = value;
    }

    pub(crate) fn advance(&self, duration: Duration) {
        *self.current_duration.lock().unwrap() += duration;
    }
}

#[derive(Clone)]
pub(crate) struct TestRealtimeClock {
    current_time_ns: Arc<Mutex<u128>>,
}

impl TestRealtimeClock {
    pub(crate) fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        Self {
            current_time_ns: Arc::new(Mutex::new(now)),
        }
    }

    pub(crate) fn now_nanos(&self) -> u128 {
        *self.current_time_ns.lock().unwrap()
    }

    pub(crate) fn set_nanos(&self, time_ns: u128) {
        *self.current_time_ns.lock().unwrap() = time_ns;
    }

    pub(crate) fn advance_nanos(&self, duration_ns: u128) {
        *self.current_time_ns.lock().unwrap() += duration_ns;
    }

    pub(crate) fn advance(&self, duration: Duration) {
        *self.current_time_ns.lock().unwrap() += duration.as_nanos();
    }
}
