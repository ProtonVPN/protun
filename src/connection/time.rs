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

/// UNIX monotonic clock that keeps advancing while the system is suspended.
///
/// Darwin: CLOCK_MONOTONIC includes time asleep (CLOCK_UPTIME_RAW, which backs
/// `std::time::Instant`, does not).
/// Linux/Android: CLOCK_BOOTTIME includes time suspended (CLOCK_MONOTONIC does not).

#[cfg(all(feature = "unix", target_vendor = "apple"))]
pub(crate) const CLOCK_ID: libc::clockid_t = libc::CLOCK_MONOTONIC;

#[cfg(all(feature = "unix", any(target_os = "linux", target_os = "android")))]
pub(crate) const CLOCK_ID: libc::clockid_t = libc::CLOCK_BOOTTIME;

#[cfg(feature = "unix")]
fn monotonic_now() -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let res = unsafe { libc::clock_gettime(CLOCK_ID, &mut ts) };
    if res != 0 {
        log::error!("clock_gettime({CLOCK_ID}) failed: {:?}", std::io::Error::last_os_error());
    }
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// FIXME: windows suspend-inclusive clocks will be introduced in a follow-up
#[cfg(not(feature = "unix"))]
fn monotonic_now() -> Duration {
    use std::sync::OnceLock;
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed()
}

#[derive(Clone)]
pub(crate) struct ClientMonotonicFactory {
    initial: Duration,
}

impl ClientMonotonicFactory {
    pub(crate) fn new() -> Self {
        Self {
            initial: monotonic_now()
        }
    }

    pub(crate) fn duration_since_initial(&self) -> Duration {
        monotonic_now().saturating_sub(self.initial)
    }
}

unsafe impl Monotonic for ClientMonotonicFactory {}
impl InstantFactory for ClientMonotonicFactory {
    type Instant = Instant;

    fn now(&self) -> Self::Instant {
        Instant::from_duration(self.duration_since_initial())
    }
}