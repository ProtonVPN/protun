// Copyright (c) 2025 Proton AG
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

use std::{env, panic, sync::RwLock};
use std::backtrace::Backtrace;
use std::sync::Once;
use log::Log;

static INIT_ONCE: Once = Once::new();
static LOGGER: ProTunLogger = ProTunLogger;
static CLIENT_LOGGER: RwLock<Option<Box<dyn ClientLogger>>> = RwLock::new(None);
static mut MAX_LOG_LEVEL: log::Level = log::Level::Info;

/// Initialize the logger and backtrace. It's thread safe and can be called multiple times, but
/// only the first call will succeed, all subsequent calls will be ignored.
/// [level] min log level to be logged.
/// [logger] callback for the client to receive log messages.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn init_logger(level: LogLevel, logger: Box<dyn ClientLogger>) {
    let mut initialized = false;
    INIT_ONCE.call_once(|| {
        initialized = true;
        unsafe {
            env::set_var("RUST_BACKTRACE", "full");
            MAX_LOG_LEVEL = level.clone().into();
        };
        let previous_panic_hook = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            log::error!("Panic in rust:\n{info}");
            let backtrace = Backtrace::capture();
            log::error!("Rust backtrace:\n{backtrace}");
            previous_panic_hook(info);
        }));
        CLIENT_LOGGER.write().unwrap().replace(logger);
        log::set_logger(&LOGGER).unwrap();
        let max_level = match level {
            LogLevel::Trace => log::LevelFilter::Trace,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
        };
        log::set_max_level(max_level);
    });
    if !initialized {
        log::warn!("init_logger: Already initialized. Ignoring.");
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export(callback_interface))]
pub trait ClientLogger: Send + Sync {
    fn log(&self, level: LogLevel, message: String);
}

struct ProTunLogger;
impl Log for ProTunLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= unsafe { MAX_LOG_LEVEL }
    }

    fn log(&self, record: &log::Record) {
        let message = format!("{}: {}", record.module_path().unwrap_or(""), record.args());
        if let Some(logger) = CLIENT_LOGGER.read().unwrap().as_ref() {
            logger.log(record.level().into(), message);
        } else {
            println!("{}", message);
        }
    }

    fn flush(&self) {}
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
impl From<log::Level> for LogLevel {
    fn from(level: log::Level) -> Self {
        match level {
            log::Level::Trace => LogLevel::Trace,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Info => LogLevel::Info,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Error => LogLevel::Error,
        }
    }
}
impl Into<log::Level> for LogLevel {
    fn into(self) -> log::Level {
        match self {
            LogLevel::Trace => log::Level::Trace,
            LogLevel::Debug => log::Level::Debug,
            LogLevel::Info => log::Level::Info,
            LogLevel::Warn => log::Level::Warn,
            LogLevel::Error => log::Level::Error,
        }
    }
}
