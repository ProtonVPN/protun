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
use mio::{Events, Poll, Token};
use crate::connection::mio::poll_timer::SuspendInclusivePollTimer;

const TIMER_TOKEN: Token = Token(1);
/// Generous upper bound on every poll below: we only care that the timer, and not
/// this timeout, is what ends the poll.
const POLL_FALLBACK_TIMEOUT: Duration = Duration::from_secs(5);

fn poll_with_timer() -> (Poll, SuspendInclusivePollTimer, Events) {
    let poll = Poll::new().expect("failed to create poll");
    let timer = SuspendInclusivePollTimer::new(poll.registry(), TIMER_TOKEN);
    (poll, timer, Events::with_capacity(8))
}

fn tokens(events: &Events) -> Vec<Token> {
    events.iter().map(|event| event.token()).collect()
}

/// Deadlines handed to the poll come from a suspend-inclusive clock, so they must
/// not be served by a poll timeout measured against an uptime clock - the timer
/// takes over and the poll blocks indefinitely.
#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod suspend_inclusive_timer {
    use super::*;

    fn poll_until_timer_expires(poll: &mut Poll, timeout: Option<Duration>, events: &mut Events) {
        poll.poll(events, timeout.or(Some(POLL_FALLBACK_TIMEOUT))).expect("poll failed");
    }

    #[test]
    fn takes_over_the_poll_timeout() {
        let (_poll, mut timer, _events) = poll_with_timer();

        assert_eq!(timer.arm(Some(Duration::from_secs(30))), None);
        assert_eq!(timer.arm(None), None);
    }

    #[test]
    fn wakes_up_the_poll_when_the_deadline_passes() {
        let (mut poll, mut timer, mut events) = poll_with_timer();

        let timeout = timer.arm(Some(Duration::from_millis(50)));
        poll_until_timer_expires(&mut poll, timeout, &mut events);

        assert_eq!(tokens(&events), vec![TIMER_TOKEN]);
    }

    /// A zero deadline means "wake up immediately" - as asked for by
    /// `NetworkRecoveryHandler::wakeup_delay` once a delayed network change is due.
    /// A zero timerfd `it_value` would instead disarm the timer altogether.
    #[test]
    fn wakes_up_the_poll_on_a_zero_deadline() {
        let (mut poll, mut timer, mut events) = poll_with_timer();

        let timeout = timer.arm(Some(Duration::ZERO));
        poll_until_timer_expires(&mut poll, timeout, &mut events);

        assert_eq!(tokens(&events), vec![TIMER_TOKEN]);
    }

    /// Every poll re-arms the timer, so an expiration must not be left behind in a
    /// state that the next poll picks up again.
    #[test]
    fn rearms_after_an_expiration() {
        let (mut poll, mut timer, mut events) = poll_with_timer();

        for _ in 0..3 {
            let timeout = timer.arm(Some(Duration::from_millis(20)));
            poll_until_timer_expires(&mut poll, timeout, &mut events);
            assert_eq!(tokens(&events), vec![TIMER_TOKEN]);
            timer.on_expired();
        }
    }

    #[test]
    fn does_not_wake_up_the_poll_without_a_deadline() {
        let (mut poll, mut timer, mut events) = poll_with_timer();

        // Arm and drain first, so that a stale expiration would show up below.
        let timeout = timer.arm(Some(Duration::from_millis(20)));
        poll_until_timer_expires(&mut poll, timeout, &mut events);
        timer.on_expired();

        assert_eq!(timer.arm(None), None);
        poll.poll(&mut events, Some(Duration::from_millis(50))).expect("poll failed");

        assert_eq!(tokens(&events), Vec::new());
    }

    /// Disarming has to survive the expiration having already been delivered, which
    /// on some platforms drops the timer from the poll behind our back.
    #[test]
    fn disarms_an_already_expired_timer() {
        let (mut poll, mut timer, mut events) = poll_with_timer();

        let timeout = timer.arm(Some(Duration::from_millis(20)));
        poll_until_timer_expires(&mut poll, timeout, &mut events);

        // No `on_expired`: the timer still believes it is armed.
        assert_eq!(timer.arm(None), None);
        poll.poll(&mut events, Some(Duration::from_millis(50))).expect("poll failed");

        assert_eq!(tokens(&events), Vec::new());
    }
}

/// Platforms without a suspend-inclusive timer keep using the poll's own timeout.
#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
mod poll_timeout_fallback {
    use super::*;

    #[test]
    fn leaves_the_deadline_to_the_poll() {
        let (_poll, mut timer, _events) = poll_with_timer();

        assert_eq!(timer.arm(Some(Duration::from_secs(30))), Some(Duration::from_secs(30)));
        assert_eq!(timer.arm(None), None);
    }
}
