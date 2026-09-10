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
use pvpnclient::os_interface::time::{InstantFactory, Since};
use crate::connection::time::ClientMonotonicFactory;

#[test]
fn advances_while_running() {
    let factory = ClientMonotonicFactory::new();

    let first = factory.now();
    std::thread::sleep(Duration::from_millis(20));
    let second = factory.now();

    assert!(
        second.duration_since(first) >= Duration::from_millis(20),
        "clock advanced by {:?}, expected at least 20ms",
        second.duration_since(first)
    );
}

#[test]
fn starts_near_zero_and_tracks_elapsed_time() {
    let outer_factory = ClientMonotonicFactory::new();
    let before = outer_factory.now();

    let factory = ClientMonotonicFactory::new();
    let duration_since_intial = factory.duration_since_initial();
    let elapsed = outer_factory.now() - before;

    // The factory reports time relative to its own construction, not since boot.
    assert!(
        duration_since_intial <= elapsed,
        "expected a fresh factory to start near zero, got {:?}",
        duration_since_intial
    );

    std::thread::sleep(Duration::from_millis(20));
    assert!(factory.duration_since_initial() >= Duration::from_millis(20));
}
