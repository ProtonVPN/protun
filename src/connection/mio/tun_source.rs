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

use mio::event;
use mio::unix::SourceFd;

pub(crate) struct TunSourceFd {
    pub(crate) fd: i32,
}

impl event::Source for TunSourceFd {
    fn register(&mut self, registry: &mio::Registry, token: mio::Token, interests: mio::Interest) -> std::io::Result<()> {
        SourceFd(&self.fd).register(registry, token, interests)
    }

    fn reregister(&mut self, registry: &mio::Registry, token: mio::Token, interests: mio::Interest) -> std::io::Result<()> {
        SourceFd(&self.fd).reregister(registry, token, interests)
    }

    fn deregister(&mut self, registry: &mio::Registry) -> std::io::Result<()> {
        SourceFd(&self.fd).deregister(registry)
    }
}
