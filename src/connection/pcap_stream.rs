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

use std::fs::{File, create_dir_all};
use std::path::Path;
use std::io;
use std::io::Write;
#[cfg(feature = "unix")]
use std::os::fd::FromRawFd;
use crate::api::connection::{FileWriteMode, PcapFileInfo, PcapFile};

pub(crate) struct PcapStream {
    pub file_info: PcapFileInfo,
    file: File,
    size: u64,
    max_bytes: Option<u64>,
    pub at_max_size: bool,
}
impl PcapStream {

    pub(crate) fn new(file_info: PcapFileInfo) -> Result<Self, io::Error> {
        log::info!("starting pcap: {:?}", file_info);
        let file = match &file_info.file {
            PcapFile::Path { path, mode } => {
                let append = match mode {
                    FileWriteMode::Append => true,
                    FileWriteMode::Overwrite => false,
                };

                let path: &Path = Path::new(&path);
                if let Some(parent) = path.parent() {
                    create_dir_all(parent)?;
                }

                File::options()
                    .create(true)
                    .write(true)
                    .append(append)
                    .open(path)?
            },
            #[cfg(feature = "unix")]
            PcapFile::Fd(fd) => unsafe { File::from_raw_fd(*fd) },
        };
        let size = file.metadata()?.len();
        let max_bytes = file_info.max_bytes;
        Ok(Self { file_info, file, size, max_bytes, at_max_size: false })
    }

    pub(crate) fn write(&mut self, data: &[u8]) {
        if self.at_max_size {
            return
        }
        if let Some(max_size) = self.max_bytes && (self.size + data.len() as u64) > max_size {
            log::info!("pcap file reached max size, stopping writing");
            self.at_max_size = true;
            return
        }
        let result = self.file.write_all(data);
        if let Err(e) = result {
            log::error!("failed to write to pcap file: {:?}", e);
        } else {
            self.size += data.len() as u64;
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