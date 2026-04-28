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

use std::io::{Error, ErrorKind};
use std::time::Duration;
use pvpnclient::os_interface::time::Instant;
use pvpnclient::StreamId;
use crate::api::connection::ConnectivityEvent;
use crate::connection::network_recovery_handler::NetworkRecoveryHandler;

fn instant(secs: u64) -> Instant {
    Instant::from_duration(Duration::from_secs(secs))
}

fn instant_ms(ms: u64) -> Instant {
    Instant::from_duration(Duration::from_millis(ms))
}

fn new_handler() -> NetworkRecoveryHandler {
    NetworkRecoveryHandler::new_for_tests(true, Duration::from_secs(1), Duration::from_secs(60))
}

fn network_error() -> Error { Error::new(ErrorKind::NetworkUnreachable, "test") }

fn test_on_resumed(handler: &mut NetworkRecoveryHandler, now: Instant) -> bool {
    let mut notified = false;
    handler.on_resumed(now, || notified = true);
    notified
}

#[test]
fn should_notify_returns_false_before_deadline() {
    let mut handler = new_handler();
    let now = instant(0);

    // Trigger a no network error to schedule notification
    handler.on_stream_error(StreamId::from(1), &network_error(), now);

    // Before deadline should return false and true after
    assert!(!test_on_resumed(&mut handler, instant_ms(999)));
    assert!(test_on_resumed(&mut handler, instant(1)));
}

#[test]
fn should_notify_clears_pending_after_true() {
    let mut handler = new_handler();
    let now = instant(0);

    handler.on_stream_error(StreamId::from(1), &network_error(), now);

    // First call returns true and clears pending
    assert!(test_on_resumed(&mut handler, instant(1)));
    // Second call returns false (no error in the meantime)
    assert!(!test_on_resumed(&mut handler, instant(10)));
}

#[test]
fn should_notify_returns_false_when_network_unavailable() {
    let mut handler = new_handler();
    let now = instant(0);

    handler.on_stream_error(StreamId::from(1), &network_error(), now);

    // Network becomes unavailable
    handler.on_connectivity_change(ConnectivityEvent::Down);

    // Even after deadline, should return false because network is unavailable
    assert!(!test_on_resumed(&mut handler, instant(2)));
}

#[test]
fn wakeup_delay_returns_remaining_time() {
    let mut handler = new_handler();
    assert!(handler.wakeup_delay(|| instant(1)).is_none());
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(1));
    assert_eq!(handler.wakeup_delay(|| instant_ms(1500)), Some(Duration::from_millis(500)));
}

#[test]
fn wakeup_delay_returns_zero_past_deadline() {
    let mut handler = new_handler();
    let now = instant(0);

    handler.on_stream_error(StreamId::from(1), &network_error(), now);

    // Past deadline, should return zero duration
    assert_eq!(handler.wakeup_delay(|| instant(10)), Some(Duration::default()));
}

#[test]
fn on_successful_socket_open_cancels_pending() {
    let mut handler = new_handler();
    let now = instant(0);

    handler.on_stream_error(StreamId::from(1), &network_error(), now);
    assert!(handler.wakeup_delay(|| instant(0)).is_some());

    handler.on_successful_socket_open();

    // No notification should be scheduled
    assert!(handler.wakeup_delay(|| instant(0)).is_none());
    assert!(!test_on_resumed(&mut handler, instant(2)));
}

#[test]
fn on_connected_resets_state() {
    let mut handler = new_handler();
    let now = instant(0);

    // Trigger error and let it notify to increase backoff
    handler.on_stream_error(StreamId::from(1), &network_error(), now);
    handler.on_resumed(instant(1), || {}); // This doubles the backoff to 2s

    // Trigger another error
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(1));
    assert_eq!(handler.wakeup_delay(|| instant(1)), Some(Duration::from_secs(2)));

    handler.on_connected();

    // Everything should be reset
    assert!(handler.wakeup_delay(|| instant(0)).is_none());

    // Trigger new error - backoff should be back to 1 second
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(0));
    let delay = handler.wakeup_delay(|| instant(0)).unwrap();
    assert_eq!(delay, Duration::from_secs(1));
}

#[test]
fn on_connectivity_change_resets_pending_and_backoff() {
    let mut handler = new_handler();
    let now = instant(0);

    // Build up some backoff
    handler.on_stream_error(StreamId::from(1), &network_error(), now);
    test_on_resumed(&mut handler, instant(1));
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(1));

    // Connectivity change should reset
    handler.on_connectivity_change(ConnectivityEvent::NetworkSwitch);

    assert!(handler.wakeup_delay(|| instant(0)).is_none());

    // New error should use initial backoff
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(0));
    let delay = handler.wakeup_delay(|| instant(0)).unwrap();
    assert_eq!(delay, Duration::from_secs(1));
}

#[test]
fn on_stream_error_only_schedules_for_network_errors() {
    let mut handler = new_handler();
    let now = instant(0);

    // Non-network errors should not schedule
    handler.on_stream_error(StreamId::from(1), &Error::new(ErrorKind::TimedOut, "test"), now);
    assert!(handler.wakeup_delay(|| instant(0)).is_none());

    // NetworkUnreachable should schedule
    handler.on_stream_error(StreamId::from(1), &network_error(), now);
    assert!(handler.wakeup_delay(|| instant(0)).is_some());
}

#[test]
fn on_stream_error_ignored_when_network_unavailable() {
    let mut handler = NetworkRecoveryHandler::new(false);
    let now = instant(0);

    handler.on_stream_error(StreamId::from(1), &network_error(), now);

    // Should not schedule because network is already marked unavailable
    assert!(handler.wakeup_delay(|| instant(0)).is_none());
}

#[test]
fn exponential_backoff() {
    let mut handler = new_handler();

    // First error: 1 second backoff
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(0));
    assert_eq!(handler.wakeup_delay(|| instant(0)).unwrap(), Duration::from_secs(1));

    // Trigger notify (this doubles backoff)
    assert!(test_on_resumed(&mut handler, instant(1)));

    // Second error: 2 second backoff
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(1));
    assert_eq!(handler.wakeup_delay(|| instant(1)).unwrap(), Duration::from_secs(2));

    // Trigger notify again
    assert!(test_on_resumed(&mut handler, instant(3)));

    // Third error: 4 second backoff
    handler.on_stream_error(StreamId::from(1), &network_error(), instant(3));
    assert_eq!(handler.wakeup_delay(|| instant(3)).unwrap(), Duration::from_secs(4));
}

#[test]
fn backoff_capped_at_max() {
    let mut handler = new_handler();
    let stream_id = StreamId::from(1);
    let error = network_error();
    let max_backoff = Duration::from_secs(60);

    // Simulate many iterations to hit the cap
    let mut time = 0u64;
    for _ in 0..10 {
        handler.on_stream_error(stream_id, &error, instant(time));
        let delay = handler.wakeup_delay(|| instant(time)).unwrap();
        time += delay.as_secs() + 1;
        test_on_resumed(&mut handler, instant(time));
    }

    // After many iterations, should be capped at max
    handler.on_stream_error(StreamId::from(1), &error, instant(time));
    let delay = handler.wakeup_delay(|| instant(time)).unwrap();
    assert_eq!(delay, max_backoff);
}
