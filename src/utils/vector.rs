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

use std::collections::HashSet;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::api::connection::IpAddress;

pub trait VecDistinct<T> {
    fn distinct(self) -> Vec<T>;
    fn distinct_mut(&mut self);
}

impl<T: Eq + Hash + Copy> VecDistinct<T> for Vec<T> {
    /// Creates a new vector to only the first of each unique object, without duplicate instances.
    fn distinct(self) -> Vec<T> {
        let mut set: HashSet<T> = HashSet::new();
        self.into_iter().filter(|x| set.insert(*x)).collect()
    }

    /// Changes the vector to only have the first of each unique object, removing duplicate instances.
    fn distinct_mut(&mut self) {
        let mut set: HashSet<T> = HashSet::new();
        self.retain(|x| set.insert(*x));
    }
}

pub trait VecDistinctString {
    fn distinct(self) -> Vec<String>;
    fn distinct_mut(&mut self);
}

impl VecDistinctString for Vec<String> {
    /// Creates a new vector to only the first of each unique object, without duplicate instances.
    fn distinct(self) -> Vec<String> {
        let mut set: HashSet<String> = HashSet::new();
        self.into_iter().filter(|x| set.insert(x.clone())).collect()
    }

    /// Changes the vector to only have the first of each unique object, removing duplicate instances.
    fn distinct_mut(&mut self) {
        let mut set: HashSet<String> = HashSet::new();
        self.retain(|x| set.insert(x.clone()));
    }
}

pub trait VecIpAddress {
    fn split_ips_by_protocol(&self) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>);
}

impl VecIpAddress for Vec<IpAddress> {
    fn split_ips_by_protocol(&self) -> (Vec<Ipv4Addr>, Vec<Ipv6Addr>) {
        let mut ipv4_addresses: Vec<Ipv4Addr> = vec![];
        let mut ipv6_addresses: Vec<Ipv6Addr> = vec![];

        for ip in self {
            match ip.0 {
                IpAddr::V4(ipv4_addr) => ipv4_addresses.push(ipv4_addr),
                IpAddr::V6(ipv6_addr) => ipv6_addresses.push(ipv6_addr),
            }
        }

        (ipv4_addresses, ipv6_addresses)
    }
}

pub trait VecIpv4Addr<Ipv4Addr> {
    fn to_comma_separated_string(&self) -> String;
}

impl VecIpv4Addr<Ipv4Addr> for Vec<Ipv4Addr> {
    fn to_comma_separated_string(&self) -> String {
        self.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}

pub trait VecIpv6Addr<Ipv6Addr> {
    fn to_comma_separated_string(&self) -> String;
}

impl VecIpv6Addr<Ipv6Addr> for Vec<Ipv6Addr> {
    fn to_comma_separated_string(&self) -> String {
        self.iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(",")
    }
}