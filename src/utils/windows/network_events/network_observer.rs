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

use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;
use std::sync::mpsc::{self, Sender};

use crate::api::connection::ConnectivityEvent;
use crate::connection::windows::helpers::internet_interface_finder::{InterfaceFinderLogMode, InternetInterfaces, Ipv4InternetInterface, Ipv6InternetInterface, get_internet_interfaces};
use crate::utils::windows::network_events::network_event_listener::NetworkChangesListener;
use crate::utils::windows::network_events::network_observer_events::{NetworkInterface, NetworkObserverEvent};
use crate::utils::windows::debouncer::Debouncer;

const DEBOUNCING_DELAY: Duration = Duration::from_millis(500);

pub(crate) type OnNetworkObserverTriggerType = Box<dyn Fn(ConnectivityEvent) + Send + Sync + 'static>;

pub struct NetworkObserver {
    _network_changes_listener: NetworkChangesListener,
    network_event_sender: Sender<NetworkObserverEvent>,

    internet_interfaces: Arc<Mutex<InternetInterfaces>>,
    internet_interfaces_in_use: Arc<Mutex<Vec<NetworkInterface>>>
}

impl NetworkObserver {
    pub(crate) fn start_new_thread(trigger_func: OnNetworkObserverTriggerType) -> NetworkObserver {
        let (network_event_sender, network_event_receiver) = mpsc::channel::<NetworkObserverEvent>();

        let network_changes_listener: NetworkChangesListener = NetworkChangesListener::start(network_event_sender.clone());

        let initial_internet_interfaces: InternetInterfaces = get_internet_interfaces(&InterfaceFinderLogMode::create_verbose("NetworkObserver initialization"));
        log::info!("NetworkObserver initialized. Internet connectivity is {} - {initial_internet_interfaces}", initial_internet_interfaces.get_state_as_string());

        let internet_interfaces_mutex: Arc<Mutex<InternetInterfaces>> = Arc::new(Mutex::new(initial_internet_interfaces));
        let debouncer_internet_interfaces_mutex: Arc<Mutex<InternetInterfaces>> = Arc::clone(&internet_interfaces_mutex);

        let internet_interfaces_in_use_mutex: Arc<Mutex<Vec<NetworkInterface>>> = Arc::new(Mutex::new(Vec::new()));
        let debouncer_internet_interfaces_in_use_mutex = Arc::clone(&internet_interfaces_in_use_mutex);
        
        thread::spawn(move || {
            Debouncer::start(network_event_receiver, DEBOUNCING_DELAY, move |_| {
                let new_internet_interfaces: InternetInterfaces = get_internet_interfaces(&InterfaceFinderLogMode::ErrorsOnly);

                if let Ok(internet_interfaces_in_use_lock) = debouncer_internet_interfaces_in_use_mutex.lock() &&
                   let Ok(internet_interfaces_lock) = debouncer_internet_interfaces_mutex.lock() {
                    handle_debouncer_trigger(internet_interfaces_lock, internet_interfaces_in_use_lock, new_internet_interfaces, &trigger_func);
                }
            });
        });
        
        NetworkObserver {
            _network_changes_listener: network_changes_listener,
            network_event_sender: network_event_sender,
            internet_interfaces: internet_interfaces_mutex,
            internet_interfaces_in_use: internet_interfaces_in_use_mutex,
        }
    }

    pub(crate) fn send_interfaces_in_use(&self, internet_interfaces_in_use: Vec<NetworkInterface>) {
        if let Ok(mut internet_interfaces_in_use_lock) = self.internet_interfaces_in_use.lock() {
            let internet_interfaces_in_use_clone = internet_interfaces_in_use.clone();
            *internet_interfaces_in_use_lock = internet_interfaces_in_use;
            let _ = self.network_event_sender.send(NetworkObserverEvent::InterfacesInUseChanged(internet_interfaces_in_use_clone));
        }
    }

    pub(crate) fn get_ipv4_internet_interface(&self) -> Option<Ipv4InternetInterface> {
        if let Ok(internet_interfaces_lock) = self.internet_interfaces.lock() {
            internet_interfaces_lock.v4.clone()
        } else {
            None
        }
    }

    pub(crate) fn get_ipv6_internet_interface(&self) -> Option<Ipv6InternetInterface> {
        if let Ok(internet_interfaces_lock) = self.internet_interfaces.lock() {
            internet_interfaces_lock.v6.clone()
        } else {
            None
        }
    }

    pub(crate) fn is_network_available(&self) -> bool {
        match self.internet_interfaces.lock() {
            Ok(internet_interfaces) => internet_interfaces.is_up(),
            Err(_) => false,
        }
    }
}

fn handle_debouncer_trigger(
    mut old_internet_interfaces_lock: MutexGuard<'_, InternetInterfaces>,
    internet_interfaces_in_use: MutexGuard<'_, Vec<NetworkInterface>>,
    new_internet_interfaces: InternetInterfaces,
    trigger_func: &OnNetworkObserverTriggerType) {
    
    let was_network_up = old_internet_interfaces_lock.is_up();
    let is_network_up = new_internet_interfaces.is_up();

    let event: Option<ConnectivityEvent> = if was_network_up != is_network_up { // Network availability changed, emit state change
        match is_network_up {
            true => {
                log::warn!("Internet connectivity is up ({})", get_interfaces_in_use_string(&internet_interfaces_in_use));
                Some(ConnectivityEvent::Up)
            },
            false => {
                log::warn!("Internet connectivity is down ({})", get_interfaces_in_use_string(&internet_interfaces_in_use));
                Some(ConnectivityEvent::Down)
            },
        }
    }
    else if was_network_up && is_network_up { // Network availability continues to be up
        let has_best_interface_changed: bool = internet_interfaces_in_use
            .iter()
            .any(|interface| !is_best_interface(interface, &new_internet_interfaces));

        if has_best_interface_changed {
            log::warn!("Best internet interface changed. Requesting switch. Best internet interfaces: {new_internet_interfaces}, {}", get_interfaces_in_use_string(&internet_interfaces_in_use));
            Some(ConnectivityEvent::NetworkSwitch)
        } else {
            None
        }
    } else {
        None
    };

    *old_internet_interfaces_lock = new_internet_interfaces;

    // Release both locks before notifying, so trigger_func() can safely re-enter the network observer
    drop(old_internet_interfaces_lock);
    drop(internet_interfaces_in_use);

    if let Some(event) = event {
        trigger_func(event);
    }
}

fn is_best_interface(interface_in_use: &NetworkInterface, best_internet_interfaces: &InternetInterfaces) -> bool {
    let is_using_best_v4_interface: bool = best_internet_interfaces.v4.as_ref().is_some_and(|v4| {
        interface_in_use.luid == v4.interface_luid && matches!(interface_in_use.ip_addr, IpAddr::V4(ip) if ip == v4.local_ip)
    });
    let is_using_best_v6_interface: bool = best_internet_interfaces.v6.as_ref().is_some_and(|v6| {
        interface_in_use.luid == v6.interface_luid && matches!(interface_in_use.ip_addr, IpAddr::V6(ip) if ip == v6.local_ip)
    });

    is_using_best_v4_interface || is_using_best_v6_interface
}

fn get_interfaces_in_use_string(internet_interfaces_in_use: &[NetworkInterface]) -> String {
    format!("Interfaces in use: {}",
        if internet_interfaces_in_use.is_empty() {
            "None".to_string()
        } else {
            internet_interfaces_in_use
                .iter()
                .map(|i| format!("{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        }
    )
}
