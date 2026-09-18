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

//! Source of the suspend-inclusive timeout for [`crate::connection::mio::streams::MioStreams::poll`].
//!
//! - Linux/Android: `epoll_wait`'s timeout is measured against CLOCK_MONOTONIC, so
//!   we use a CLOCK_BOOTTIME timerfd.
//! - Apple: mio polls through the legacy `kevent` syscall, whose timeout xnu turns
//!   into a deadline with `clock_absolutetime_interval_to_deadline`
//!   (`kevent_legacy_get_deadline` in `bsd/kern/kern_event.c`), i.e. against
//!   `mach_absolute_time`, so we use an `EVFILT_TIMER` knote with
//!   `NOTE_MACH_CONTINUOUS_TIME`.
//!
//! Neither timer wakes a suspended device - that would take CLOCK_BOOTTIME_ALARM
//! (CAP_WAKE_ALARM) or a push/background API - they fire as soon as the device
//! resumes, which is when we can act on them anyway.

#[cfg(any(target_os = "linux", target_os = "android"))]
mod boottime_timerfd {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::Duration;
    use mio::unix::SourceFd;
    use mio::{Interest, Registry, Token};
    use pvpnclient::Deadline;

    /// Never let a zero delay disarm the timer: a `Some(Duration::ZERO)` deadline
    /// means "wake up immediately", while an all-zero `it_value` means "never".
    const MIN_DELAY: Duration = Duration::from_nanos(1);

    pub(crate) struct SuspendInclusivePollTimer {
        /// `None` if this kernel refused a CLOCK_BOOTTIME timerfd; we then fall
        /// back to the poll's own (suspend-non-inclusive) timeout.
        fd: Option<OwnedFd>,
        armed: bool,
    }

    impl SuspendInclusivePollTimer {
        pub(crate) fn new(registry: &Registry, token: Token) -> Self {
            Self { fd: create_timer_fd(registry, token), armed: false }
        }

        /// Arms the timer for `deadline` and returns the timeout to pass to the poll.
        pub(crate) fn arm(&mut self, deadline: Deadline) -> Deadline {
            let Some(fd) = &self.fd else { return deadline };

            let delay = match deadline {
                Some(delay) => delay.max(MIN_DELAY),
                // Disarming is only needed if a previous poll left the timer armed.
                None if self.armed => Duration::ZERO,
                None => return None,
            };
            match set_time(fd, delay) {
                Ok(()) => {
                    self.armed = !delay.is_zero();
                    None
                }
                Err(e) => {
                    log::error!("failed to arm poll timer for {delay:?}: {e:?}");
                    deadline
                }
            }
        }

        /// Drains an expiration reported on the timer's token, so that the
        /// descriptor stops being readable.
        pub(crate) fn on_expired(&mut self) {
            self.armed = false;
            let Some(fd) = &self.fd else { return };

            let mut expiration_count = [0u8; 8];
            let res = unsafe {
                libc::read(fd.as_raw_fd(), expiration_count.as_mut_ptr().cast(), expiration_count.len())
            };
            if res < 0 {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::WouldBlock {
                    log::error!("failed to read poll timer: {err:?}");
                }
            }
        }
    }

    fn create_timer_fd(registry: &Registry, token: Token) -> Option<OwnedFd> {
        let raw_fd = unsafe {
            libc::timerfd_create(libc::CLOCK_BOOTTIME, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC)
        };
        if raw_fd < 0 {
            log::error!("failed to create CLOCK_BOOTTIME timerfd, poll timeouts will \
                not account for suspended time: {:?}", io::Error::last_os_error());
            return None;
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        if let Err(e) = registry.register(&mut SourceFd(&fd.as_raw_fd()), token, Interest::READABLE) {
            log::error!("failed to register poll timer: {e:?}");
            return None;
        }
        Some(fd)
    }

    /// Arms the timer `delay` from now, or disarms it when `delay` is zero.
    fn set_time(fd: &OwnedFd, delay: Duration) -> io::Result<()> {
        let spec = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 }, // Zero interval -> fire once.
            it_value: libc::timespec {
                tv_sec: libc::time_t::try_from(delay.as_secs()).unwrap_or(libc::time_t::MAX),
                tv_nsec: delay.subsec_nanos() as libc::c_long,
            },
        };
        let res = unsafe { libc::timerfd_settime(fd.as_raw_fd(), 0, &spec, std::ptr::null_mut()) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_vendor = "apple")]
mod continuous_time_kqueue {
    use std::io;
    use std::os::fd::{AsRawFd, RawFd};
    use std::time::Duration;
    use mio::{Registry, Token};
    use pvpnclient::Deadline;

    pub(crate) struct SuspendInclusivePollTimer {
        /// The poll's kqueue, borrowed rather than owned: the timer lives in the
        /// same `MioStreams` as the poll and is never used after it.
        kqueue_fd: RawFd,
        /// `ident` of our knote, and the token the poll reports its expiration under.
        token: Token,
        armed: bool,
    }

    impl SuspendInclusivePollTimer {
        pub(crate) fn new(registry: &Registry, token: Token) -> Self {
            Self { kqueue_fd: registry.as_raw_fd(), token, armed: false }
        }

        /// Arms the timer for `deadline` and returns the timeout to pass to the poll.
        pub(crate) fn arm(&mut self, deadline: Deadline) -> Deadline {
            let change = match deadline {
                Some(delay) => timer_change(self.token, libc::EV_ADD | libc::EV_ONESHOT, delay),
                // Deleting is only needed if a previous poll left the timer armed.
                None if self.armed => timer_change(self.token, libc::EV_DELETE, Duration::ZERO),
                None => return None,
            };
            match apply(self.kqueue_fd, &change) {
                Ok(()) => {
                    self.armed = deadline.is_some();
                    None
                }
                Err(e) => {
                    log::error!("failed to arm poll timer for {deadline:?}: {e:?}");
                    deadline
                }
            }
        }

        /// Reports an expiration the poll signalled. Nothing to drain: the kernel
        /// deletes an `EV_ONESHOT` knote once its expiration has been retrieved.
        pub(crate) fn on_expired(&mut self) {
            self.armed = false;
        }
    }

    fn timer_change(token: Token, flags: u16, delay: Duration) -> libc::kevent {
        libc::kevent {
            ident: token.0 as libc::uintptr_t,
            filter: libc::EVFILT_TIMER,
            flags,
            // NOTE_MACH_CONTINUOUS_TIME is what makes the knote tick across sleep;
            // by default an EVFILT_TIMER does not.
            fflags: libc::NOTE_NSECONDS | libc::NOTE_MACH_CONTINUOUS_TIME,
            // Ignored by EV_DELETE. A zero delay expires the timer immediately,
            // which is what a zero deadline asks for.
            data: isize::try_from(delay.as_nanos()).unwrap_or(isize::MAX),
            // mio reads the event's token back out of `udata`.
            udata: token.0 as *mut libc::c_void,
        }
    }

    fn apply(kqueue_fd: RawFd, change: &libc::kevent) -> io::Result<()> {
        let res = unsafe {
            libc::kevent(kqueue_fd, change, 1, std::ptr::null_mut(), 0, std::ptr::null())
        };
        if res < 0 {
            let err = io::Error::last_os_error();
            // The only knote we delete is a one-shot one, which the kernel may have
            // already removed on delivery - that is not a failure to disarm.
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(err);
            }
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use boottime_timerfd::SuspendInclusivePollTimer;

#[cfg(target_vendor = "apple")]
pub(crate) use continuous_time_kqueue::SuspendInclusivePollTimer;

