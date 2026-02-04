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

use std::fs::File;
use std::io::Write;
#[cfg(feature = "unix")]
use std::os::fd::FromRawFd;
use crate::api::connection::{FileWriteMode, PcapFileInfo};

pub(crate) struct PcapStream {
    file: File,
}
impl PcapStream {

    pub(crate) fn new(file_info: PcapFileInfo) -> Self {
        Self {
            file: match file_info {
                PcapFileInfo::Path { path, mode } => {
                    let append = match mode {
                        FileWriteMode::Append => true,
                        FileWriteMode::Overwrite => false,
                    };
                    File::options()
                        .create(true)
                        .write(true)
                        .append(append)
                        .open(path)
                        .unwrap()
                },
                #[cfg(feature = "unix")]
                PcapFileInfo::Fd(fd) => unsafe { File::from_raw_fd(fd) }
            }
        }
    }

    pub(crate) fn write(&mut self, data: &[u8]) {
        let result = self.file.write_all(data);
        if let Err(e) = result {
            log::error!("failed to write to pcap file: {:?}", e);
        }
    }
}
impl Drop for PcapStream {
    fn drop(&mut self) {
        let result = self.file.sync_all();
        if let Err(e) = result {
            log::error!("pcap stream dropped with error: {e:?}");
        } else {
            log::info!("pcap stream dropped");
        }
    }
}