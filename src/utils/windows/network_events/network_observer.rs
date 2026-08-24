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

use std::net::IpAddr::{V4, V6};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{self, Sender};

use crate::api::connection::ConnectivityEvent;
use crate::connection::windows::helpers::internet_interface_finder::{InterfaceFinderLogMode, Ipv4InternetInterface, Ipv6InternetInterface, get_internet_interfaces};
use crate::utils::windows::network_events::network_event_listener::NetworkChangesListener;
use crate::utils::windows::network_events::network_observer_events::{NetworkInterface, NetworkObserverEvent};
use crate::utils::windows::debouncer::Debouncer;

const DEBOUNCING_DELAY: Duration = Duration::from_millis(500);

pub(crate) type OnNetworkObserverTriggerType = Box<dyn Fn(ConnectivityEvent) + Send + Sync + 'static>;

pub struct NetworkObserver {
    _network_changes_listener: NetworkChangesListener,
    current_interface_mutex: Arc<Mutex<Option<NetworkInterface>>>,
    network_event_sender: Sender<NetworkObserverEvent>,
}

impl NetworkObserver {
    pub fn start_new_thread(trigger_func: OnNetworkObserverTriggerType) -> NetworkObserver {
        let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkObserverEvent>();

        let network_changes_listener: NetworkChangesListener = NetworkChangesListener::start(network_event_sender.clone());

        let current_interface_mutex: Arc<Mutex<Option<NetworkInterface>>> = Arc::new(Mutex::new(None));
        let debouncer_current_interface_mutex = Arc::clone(&current_interface_mutex);
        
        thread::spawn(move || {
            Debouncer::start(network_event_receiver, DEBOUNCING_DELAY, move |_| {
                let current_interface: Option<NetworkInterface> = if let Ok(current_interface_lock) = debouncer_current_interface_mutex.lock() {
                    current_interface_lock.clone()
                } else {
                    return;
                };
                handle_debouncer_trigger(current_interface, &trigger_func);
            });
        });
        
        NetworkObserver {
            _network_changes_listener: network_changes_listener,
            current_interface_mutex: current_interface_mutex,
            network_event_sender: network_event_sender,
        }
    }

    pub fn send_current_interface(&self, current_interface: Option<NetworkInterface>) {
        if let Ok(mut current_interface_lock) = self.current_interface_mutex.lock() {
            let current_interface_clone = current_interface.clone();
            *current_interface_lock = current_interface;
            let _ = self.network_event_sender.send(NetworkObserverEvent::InterfaceSelected(current_interface_clone));
        }
    }
}

fn handle_debouncer_trigger(current_interface: Option<NetworkInterface>, trigger_func: &OnNetworkObserverTriggerType) {
    let (new_ipv4_interface, new_ipv6_interface) = get_internet_interfaces(&InterfaceFinderLogMode::ErrorsOnly);

    if new_ipv4_interface.is_none() && new_ipv6_interface.is_none() {
        handle_no_internet_connectivity(current_interface, trigger_func);
    }
    else if new_ipv6_interface.is_none() {
        handle_ipv4_internet_connectivity(new_ipv4_interface.unwrap(), current_interface, trigger_func);
    }
    else if new_ipv4_interface.is_none() {
        handle_ipv6_internet_connectivity(new_ipv6_interface.unwrap(), current_interface, trigger_func);
    }
    else {
        handle_ipv4_and_ipv6_internet_connectivity(new_ipv4_interface.unwrap(), new_ipv6_interface.unwrap(), current_interface, trigger_func);
    }
}

fn handle_no_internet_connectivity(current_interface: Option<NetworkInterface>, trigger_func: &OnNetworkObserverTriggerType) {
    match current_interface {
        Some(current_interface) => {
            log::warn!("Internet connectivity lost (Current interface: {current_interface})");
            trigger_func(ConnectivityEvent::Down);
        },
        None => log::debug!("No internet connectivity"),
    }
}

fn handle_ipv4_internet_connectivity(new_ipv4_interface: Ipv4InternetInterface,
    current_interface: Option<NetworkInterface>, trigger_func: &OnNetworkObserverTriggerType) {
    match current_interface {
        Some(current_interface) => {
            if current_interface.luid == new_ipv4_interface.interface_luid &&
                let V4(current_interface_ipv4_addr) = current_interface.ip_addr && current_interface_ipv4_addr == new_ipv4_interface.local_ip
            {
                log::debug!("Best IPv4 internet interface already selected ({current_interface})");
            }
            else {
                log::warn!("Best internet interface changed. Requesting switch. \
                    (Current interface: {current_interface}) \
                    (Suggested interface: {new_ipv4_interface})");
                trigger_func(ConnectivityEvent::NetworkSwitch);
            }
        },
        None => handle_internet_connectivity_regained(trigger_func),
    }
}

fn handle_internet_connectivity_regained(trigger_func: &OnNetworkObserverTriggerType) {
    log::warn!("Internet connectivity regained");
    trigger_func(ConnectivityEvent::Up);
}

fn handle_ipv6_internet_connectivity(new_ipv6_interface: Ipv6InternetInterface,
    current_interface: Option<NetworkInterface>, trigger_func: &OnNetworkObserverTriggerType) {
    match current_interface {
        Some(current_interface) => {
            if current_interface.luid == new_ipv6_interface.interface_luid &&
                let V6(current_interface_ipv6_addr) = current_interface.ip_addr && current_interface_ipv6_addr == new_ipv6_interface.local_ip
            {
                log::debug!("Best IPv6 internet interface already selected ({current_interface})");
            }
            else {
                log::warn!("Best internet interface changed. Requesting switch. \
                    (Current interface: {current_interface}) \
                    (Suggested interface: {new_ipv6_interface})");
                trigger_func(ConnectivityEvent::NetworkSwitch);
            }
        },
        None => handle_internet_connectivity_regained(trigger_func),
    }
}

fn handle_ipv4_and_ipv6_internet_connectivity(new_ipv4_interface: Ipv4InternetInterface, new_ipv6_interface: Ipv6InternetInterface,
    current_interface: Option<NetworkInterface>, trigger_func: &OnNetworkObserverTriggerType) {
    match current_interface {
        Some(current_interface) => {
            if current_interface.luid == new_ipv4_interface.interface_luid &&
                let V4(current_interface_ipv4_addr) = current_interface.ip_addr && current_interface_ipv4_addr == new_ipv4_interface.local_ip
            {
                log::debug!("Best IPv4 internet interface already selected. IPv6 is available. ({current_interface})");
            }
            else if current_interface.luid == new_ipv6_interface.interface_luid &&
                let V6(current_interface_ipv6_addr) = current_interface.ip_addr && current_interface_ipv6_addr == new_ipv6_interface.local_ip
            {
                log::debug!("Best IPv6 internet interface already selected. IPv4 is available. ({current_interface})");
            }
            else {
                log::warn!("Best internet interface changed. Requesting switch. \
                    (Current interface: {current_interface}) \
                    (Suggested IPv4 interface: {new_ipv4_interface}) \
                    (Suggested IPv6 interface: {new_ipv6_interface})");
                trigger_func(ConnectivityEvent::NetworkSwitch);
            }
        },
        None => handle_internet_connectivity_regained(trigger_func),
    }
}