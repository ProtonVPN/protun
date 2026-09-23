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

use std::fmt::{Display, Formatter};
use std::net::IpAddr;

use crate::utils::windows::luid::Luid;

#[derive(Debug)]
pub enum NetworkObserverEvent {
    InterfacesInUseChanged(Vec<NetworkInterface>),
    RoutingTableChanged(EventParameters),
    InterfaceChanged(EventParameters),
    IpAddressChanged(EventParameters),
}

impl Display for NetworkObserverEvent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkObserverEvent::InterfacesInUseChanged(interfaces) => {
                if interfaces.is_empty() {
                    write!(f, "No interfaces in use.")
                }
                else {
                    let s = interfaces
                        .iter()
                        .map(|i| format!("LUID: {}, Index: {} (IP: {})", i.luid, i.index, i.ip_addr))
                        .collect::<Vec<_>>()
                        .join(", ");
                    write!(f, "Interfaces in use: {}", s)
                }
            },
            NetworkObserverEvent::RoutingTableChanged(event_parameters) => write!(f, "Routing table entry {event_parameters}"),
            NetworkObserverEvent::InterfaceChanged(event_parameters) => write!(f, "Network interface {event_parameters}"),
            NetworkObserverEvent::IpAddressChanged(event_parameters) => write!(f, "IP address {event_parameters}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub luid: Luid,
    pub index: u32,
    pub ip_addr: IpAddr,
}

impl Display for NetworkInterface {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Interface - LUID: {}, Index: {} (IP: {})", self.luid, self.index, self.ip_addr)
    }
}

#[derive(Debug)]
pub struct EventParameters {
    pub(crate) event_type: EventType,
    pub(crate) interface_luid: Luid,
    pub(crate) interface_index: u32,
}

impl EventParameters {
    pub(crate) fn new(event_type: EventType, interface_luid: Luid, interface_index: u32) -> Self {
        EventParameters {
            event_type,
            interface_luid,
            interface_index
        }
    }
}

impl Display for EventParameters {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (Interface - LUID: {}, Index: {})", self.event_type, self.interface_luid, self.interface_index)
    }
}

#[derive(Debug)]
pub enum EventType {
    Initial,
    Create,
    Delete,
    Update,
}

impl Display for EventType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::Initial => write!(f, "listener started"),
            EventType::Create => write!(f, "added"),
            EventType::Delete => write!(f, "removed"),
            EventType::Update => write!(f, "updated"),
        }
    }
}