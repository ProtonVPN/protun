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
use std::io::{Read, Seek, Write};

pub(crate) struct BinaryBlobFile {
    file: File,
}
impl BinaryBlobFile {
    pub(crate) fn new(path: &Path) -> Self {
        if let Some(parent) = path.parent() {
            create_dir_all(parent).expect("Failed to create directories for file stream");
        }
        let file = File::options()
            .create(true)
            .write(true)
            .read(true)
            .open(path)
            .expect("Failed to open file");
        Self { file }
    }

    pub fn put(&mut self, data: &[u8]) -> io::Result<()> {
        self.clear()?;
        self.file.write_all(data)?;
        Ok(())
    }

    pub fn get(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.file.seek(io::SeekFrom::Start(0))?;
        let mut buf = Vec::new();
        self.file.read_to_end(&mut buf)?;
        if buf.is_empty() {
            Ok(None)
        } else {
            Ok(Some(buf))
        }
    }
    
    pub fn clear(&mut self) -> io::Result<()> {
        self.file.set_len(0)?;
        self.file.seek(io::SeekFrom::Start(0))?;
        Ok(())
    }
}