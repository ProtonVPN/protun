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

use crate::binary_blob_file::BinaryBlobFile;
use protun::api::connection::{CacheKey, Connection, PersistentCache};
use protun::api::events::{ErrorEvent, Event};
use protun::api::logger::{init_logger, ClientLogger, LogLevel};
use std::path::Path;
use std::sync::RwLock;
use std::thread;

#[cfg(target_os = "linux")]
use libc::{ioctl, open, O_NONBLOCK, O_RDWR};
#[cfg(target_os = "linux")]
use std::{ffi::c_void, io};
use protun::api::test_utils::muon_test_auth::get_session_fork_selector;
use protun::api::test_utils::test_config_parser::{parse_ini_config, ParsedConfig};

mod binary_blob_file;

/// Get the file descriptor of the TUN interface
#[cfg(target_os = "linux")]
fn get_tun_fd(name: &str) -> io::Result<i32> {
    let tun_fd = unsafe {
        open(
            b"/dev/net/tun\0".as_ptr() as *const i8,
            O_RDWR | O_NONBLOCK,
            0,
        )
    };

    if tun_fd == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr = [0u8; 18];
    let name_bytes = name.as_bytes();
    let copy_len = std::cmp::min(name_bytes.len(), 16);
    ifr[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
    const IFF_TUN: u16 = 0x0001;
    const IFF_NO_PI: u16 = 0x1000;
    const TUNSETIFF: u64 = 0x400454ca;
    let flags = IFF_TUN | IFF_NO_PI;
    ifr[16] = (flags & 0xff) as u8;
    ifr[17] = ((flags >> 8) & 0xff) as u8;
    let result = unsafe {
        ioctl(
            tun_fd,
            TUNSETIFF,
            ifr.as_ptr() as *const c_void,
        )
    };

    if result == -1 {
        unsafe { libc::close(tun_fd); }
        return Err(io::Error::last_os_error());
    }

    Ok(tun_fd)
}

struct Logger;
impl ClientLogger for Logger {
    fn log(&self, level: LogLevel, message: String) {
        println!("[{level:?}] {message}");
    }
}

struct Cache {
    cert_stream: RwLock<BinaryBlobFile>,
    private_key_stream: RwLock<BinaryBlobFile>,
    api_session_stream: RwLock<BinaryBlobFile>,
}
impl Cache {
    pub fn new(
        cert_file_path: &str,
        private_key_file_path: &str,
        api_session_file_path: &str,
    ) -> Self {
        Self {
            cert_stream: RwLock::new(BinaryBlobFile::new(Path::new(cert_file_path))),
            private_key_stream: RwLock::new(BinaryBlobFile::new(Path::new(private_key_file_path))),
            api_session_stream: RwLock::new(BinaryBlobFile::new(Path::new(api_session_file_path))),
        }
    }

    fn get_bytes(&self, stream: &RwLock<BinaryBlobFile>) -> Option<Vec<u8>> {
        stream.write().unwrap().get().unwrap()
    }
}
impl PersistentCache for Cache {
    fn put(&self, key: CacheKey, data: Vec<u8>) {
        let _ = match key {
            CacheKey::Certificate => self.cert_stream.write().unwrap().put(&data),
            CacheKey::PrivateKey => self.private_key_stream.write().unwrap().put(&data),
            CacheKey::ApiSession => self.api_session_stream.write().unwrap().put(&data),
        };
    }

    fn get(&self, key: CacheKey) -> Option<Vec<u8>> {
        match key {
            CacheKey::Certificate => self.get_bytes(&self.cert_stream),
            CacheKey::PrivateKey => self.get_bytes(&self.private_key_stream),
            CacheKey::ApiSession => self.get_bytes(&self.api_session_stream),
        }
    }

    fn clear(&self) {
        let _ = self.cert_stream.write().unwrap().clear();
        let _ = self.private_key_stream.write().unwrap().clear();
        let _ = self.api_session_stream.write().unwrap().clear();
    }
}

fn main()  {
    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1).cloned().unwrap_or("./config.ini".to_string());
    if !Path::new(&config_path).exists() {
        println!("Config file not found: {}", config_path);
        return;
    }

    init_logger(
        LogLevel::Info,
        Box::new(Logger),
    );

    let cache = Box::new(Cache::new(
        "./protun_cert",
        "./protun_privatekey",
        "./protun_muon"
    ));

    let (config, fork_config) = parse_ini_config(config_path).unwrap();
    let (state_channel_sender, state_channel_receiver) = std::sync::mpsc::channel();
    let (event_channel_sender, event_channel_receiver) = std::sync::mpsc::channel();

    let tun_fd = tun_fd(&config);
    let connection = Connection::unix_connect(
        config.initial_connection_config,
        tun_fd,
        Box::new(move |s| { let _ = state_channel_sender.send(s); }),
        Box::new(move |e| { let _ = event_channel_sender.send(e); }),
        None,
        cache,
    );

    thread::spawn(move || {
        if let Some(fork_config) = fork_config {
            while let Ok(event) = event_channel_receiver.recv() {
                match event {
                    Event::Error { error: ErrorEvent::ApiSessionExpired } => {
                        let user = fork_config.username.clone();
                        let pass = fork_config.password.clone();
                        let fork_selector = get_session_fork_selector(
                            &fork_config.app_version, &user, &pass).into();
                        connection.provide_api_fork_selector(fork_selector);
                    }
                    _ => {}
                }
            }
        };
    });

    while let Ok(state) = state_channel_receiver.recv() {
        println!("{:?}", state);
    };
}

fn tun_fd(config: &ParsedConfig) -> Option<i32> {
    #[cfg(target_os = "linux")]
    let fd = config.tun_interface_name.clone().map(|tun_name| get_tun_fd(&tun_name).ok()).flatten();
    #[cfg(not(target_os = "linux"))]
    let fd = None;
    fd
}
