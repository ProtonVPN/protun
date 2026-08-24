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

use std::ffi::c_void;
use std::sync::mpsc::Sender;

use windows::Win32::Foundation::{HANDLE, NO_ERROR};
use windows::Win32::NetworkManagement::IpHelper::{CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE, MIB_UNICASTIPADDRESS_ROW, MibAddInstance, MibDeleteInstance, MibInitialNotification, MibParameterNotification, NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange};
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use crate::utils::windows::network_events::network_observer_events::{EventParameters, EventType, NetworkObserverEvent};

pub struct NetworkChangesListener {
    routes: ListenerParameters,
    interfaces: ListenerParameters,
    ip_addresses: ListenerParameters,
}

pub struct ListenerParameters {
    handle: HANDLE,
    context: *mut Sender<NetworkObserverEvent>,
}

unsafe impl Send for ListenerParameters {}
unsafe impl Sync for ListenerParameters {}

impl ListenerParameters {
    pub fn new(event_sender: Sender<NetworkObserverEvent>) -> Self {
        ListenerParameters {
            handle: HANDLE::default(),
            context: Box::into_raw(Box::new(event_sender))
        }
    }
}

impl Drop for ListenerParameters {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_invalid() {
                let _ = CancelMibChangeNotify2(self.handle);
            }
            if !self.context.is_null() {
                drop(Box::from_raw(self.context));
            }
        }
    }
}

impl NetworkChangesListener {
    pub(crate) fn start(event_sender: Sender<NetworkObserverEvent>) -> NetworkChangesListener {
        let mut network_changes_listener: NetworkChangesListener = NetworkChangesListener {
            routes: ListenerParameters::new(event_sender.clone()),
            interfaces: ListenerParameters::new(event_sender.clone()),
            ip_addresses: ListenerParameters::new(event_sender),
        };

        listen_to_route_events(&mut network_changes_listener.routes);
        listen_to_interface_events(&mut network_changes_listener.interfaces);
        listen_to_ip_address_events(&mut network_changes_listener.ip_addresses);

        network_changes_listener
    }
}

fn listen_to_route_events(parameters: &mut ListenerParameters) {
    unsafe {
        let result = NotifyRouteChange2(
            AF_UNSPEC, // Both IPv4 and IPv6
            Some(on_route_change),
            parameters.context as *const c_void,
            true,
            &mut parameters.handle,
        );
        if result != NO_ERROR {
            log::error!("Error when requesting to be notified about routing table events. Error code: {}", result.0);
        }
    }
}

unsafe extern "system" fn on_route_change(
    caller_context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    let event_type: Option<EventType> = map_notification_type(notification_type);

    if row.is_null() || event_type.is_none() {
        log::debug!("[Network event] Routing table event listener start notification");
        return;
    }

    let event_type: EventType = event_type.unwrap();
    let row: &MIB_IPFORWARD_ROW2 = unsafe { &*row };
    let message: NetworkObserverEvent = NetworkObserverEvent::RoutingTableChanged(
        EventParameters::new(event_type, row.InterfaceLuid.into(), row.InterfaceIndex));
    send_message(caller_context, message);
}

fn map_notification_type(notification_type: MIB_NOTIFICATION_TYPE) -> Option<EventType> {
    match notification_type {
        t if t == MibAddInstance => Some(EventType::Create),
        t if t == MibDeleteInstance => Some(EventType::Delete),
        t if t == MibParameterNotification => Some(EventType::Update),
        t if t == MibInitialNotification => Some(EventType::Initial),
        _ => None,
    }
}

fn send_message(caller_context: *const c_void, message: NetworkObserverEvent) {
    log::debug!("[Network event] {message}");

    let sender: &Sender<NetworkObserverEvent> = unsafe { &*(caller_context as *const Sender<NetworkObserverEvent>) };

    if let Err(e) = sender.send(message) {
        log::error!("Failed to send network observer event to the channel. Listener is disconnected. Error: {e}");
    }
}

fn listen_to_interface_events(parameters: &mut ListenerParameters) {
    unsafe {
        let result = NotifyIpInterfaceChange(
            AF_UNSPEC, // Both IPv4 and IPv6
            Some(on_interface_change),
            Some(parameters.context as *const c_void),
            true,
            &mut parameters.handle,
        );
        if result != NO_ERROR {
            log::error!("Error when requesting to be notified about network interface change events. Error code: {}", result.0);
        }
    }
}

unsafe extern "system" fn on_interface_change(
    caller_context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    let event_type: Option<EventType> = map_notification_type(notification_type);

    if row.is_null() || event_type.is_none() {
        log::debug!("[Network event] Interface change event listener start notification");
        return;
    }
    
    let event_type: EventType = event_type.unwrap();
    let row: &MIB_IPINTERFACE_ROW = unsafe { &*row };
    let message: NetworkObserverEvent = NetworkObserverEvent::InterfaceChanged(
        EventParameters::new(event_type, row.InterfaceLuid.into(), row.InterfaceIndex));
    send_message(caller_context, message);
}

fn listen_to_ip_address_events(parameters: &mut ListenerParameters) {
    unsafe {
        let result = NotifyUnicastIpAddressChange(
            AF_UNSPEC, // Both IPv4 and IPv6
            Some(on_ip_address_change),
            Some(parameters.context as *const c_void),
            true,
            &mut parameters.handle,
        );
        if result != NO_ERROR {
            log::error!("Error when requesting to be notified about IP address change events. Error code: {}", result.0);
        }
    }
}

unsafe extern "system" fn on_ip_address_change(
    caller_context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    notification_type: MIB_NOTIFICATION_TYPE,
) {
    let event_type: Option<EventType> = map_notification_type(notification_type);

    if row.is_null() || event_type.is_none() {
        log::debug!("[Network event] IP address change event listener start notification");
        return;
    }

    let event_type: EventType = event_type.unwrap();
    let row: &MIB_UNICASTIPADDRESS_ROW = unsafe { &*row };
    let message: NetworkObserverEvent = NetworkObserverEvent::IpAddressChanged(
        EventParameters::new(event_type, row.InterfaceLuid.into(), row.InterfaceIndex));
    send_message(caller_context, message);
}
