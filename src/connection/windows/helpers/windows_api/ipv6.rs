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

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use windows::Win32::NetworkManagement::NetManagement::{IEnumNetCfgBindingPath, INetCfg, INetCfgBindingPath, INetCfgComponent, INetCfgComponentBindings, INetCfgLock};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree, CoUninitialize};
use windows::core::{GUID, HSTRING, Interface, PCWSTR, PWSTR, w};

use crate::connection::windows::helpers::wintun::constants::ADAPTER_GUID_STR;

const LOCK_NAME: PCWSTR = w!("ProTunIpv6Toggler");
const MS_TCPIP6: &str = "MS_TCPIP6";
const INETCFG_CLSID: GUID = GUID::from_u128(0x5b035261_40f9_11d1_aaec_00805fc1270e);
const EBP_BELOW: u32 = 2u32;

pub(crate) fn enable_adapter_ipv6() -> Result<(), String> {
    log::info!("Enabling IPv6 in the adapter");
    let result = toggle_adapter_ipv6(true);
    log_result(&result, "Successfully enabled IPv6 in the adapter");
    result
}

pub(crate) fn disable_adapter_ipv6() -> Result<(), String> {
    log::info!("Disabling IPv6 in the adapter");
    let result = toggle_adapter_ipv6(false);
    log_result(&result, "Successfully disabled IPv6 in the adapter");
    result
}

fn log_result(result: &Result<(), String>, success_msg: &str) {
    match &result {
        Ok(_) => log::info!("{success_msg}"),
        Err(err) => log::error!("{err}"),
    }
}

fn toggle_adapter_ipv6(target_status: bool) -> Result<(), String> {
    unsafe {
        // Initialize the Windows Component Object Model (COM) Library
        if CoInitializeEx(None, COINIT_MULTITHREADED).is_err() {
            return Err("Error when initializing COM".to_string());
        }

        let result = create_inetcfg_instance(target_status);

        // Uninitialize the Windows Component Object Model (COM) Library (it only needs to be Uninitialized when successfully initialized)
        CoUninitialize();

        result
    }
}

fn create_inetcfg_instance(target_status: bool) -> Result<(), String> {
    unsafe {
        let net_cfg: INetCfg = CoCreateInstance(&INETCFG_CLSID, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| format!("Error when creating INetCfg. Code: {}", e.code()))?;

        let result = acquire_write_lock(&net_cfg, target_status);

        let _ = net_cfg.Uninitialize();
        result
    }
}

unsafe fn acquire_write_lock(net_cfg: &INetCfg, target_status: bool) -> Result<(), String> {
    unsafe {
        let net_cfg_lock: INetCfgLock = net_cfg.cast()
            .map_err(|e| format!("Error when casting INetCfg to a lock. Code: {}", e.code()))?;
        let conflict_holder: Option<*mut PWSTR> = Some(PWSTR::null().as_ptr() as *mut PWSTR);
        net_cfg_lock.AcquireWriteLock(5000, LOCK_NAME, conflict_holder)
            .map_err(|e| format!("Error when acquiring INetCfg lock. Code: {}", e.code()))?;

        let result: Result<(), String> = handle_conflict_holder(net_cfg, conflict_holder, target_status);

        let _ = net_cfg_lock.ReleaseWriteLock();
        result
    }
}

unsafe fn handle_conflict_holder(net_cfg: &INetCfg, conflict_holder: Option<*mut PWSTR>, target_status: bool) -> Result<(), String> {
    unsafe {
        let conflict_holder: *mut PWSTR = match conflict_holder {
            Some(p) => p,
            None => return Err("Received no pointer".to_string()),
        };
        
        if !conflict_holder.is_null() {
            let conflict: String = pwstr_to_string(*conflict_holder);
            CoTaskMemFree(Some(conflict_holder as *const _));
            return Err(format!("Access denied. Write lock held by: {conflict}"));
        }

        net_cfg.Initialize(None)
            .map_err(|e| format!("Error when initializing network configuration. Code: {}", e.code()))?;

        find_ipv6_component(net_cfg, target_status)
    }
}

unsafe fn find_ipv6_component(net_cfg: &INetCfg, target_status: bool) -> Result<(), String> {
    unsafe {
        let component_id = HSTRING::from(MS_TCPIP6);
        let ipv6_component: Option<*mut Option<INetCfgComponent>> = Some(&mut None as *mut _);
        match net_cfg.FindComponent(&component_id, ipv6_component) {
            Ok(_) => (),
            Err(e) => return Err(format!("IPv6 component not found. Code: {}", e.code())),
        };

        let ipv6_component: *mut Option<INetCfgComponent> = ipv6_component.ok_or("The IPv6 component is empty (1/2)")?;
        let ipv6_component: &INetCfgComponent = (&*ipv6_component).as_ref().ok_or("The IPv6 component is empty (2/2)")?;

        get_ipv6_component_binding_paths(net_cfg, ipv6_component, target_status)
    }
}

unsafe fn get_ipv6_component_binding_paths(net_cfg: &INetCfg, ipv6_component: &INetCfgComponent, target_status: bool) -> Result<(), String> {
    unsafe {
        let ipv6_bindings: INetCfgComponentBindings = ipv6_component.cast()
            .map_err(|e| format!("Error when casting IPv6 component into bindings. Code: {}", e.code()))?;

        let enum_binding_paths: Option<*mut Option<IEnumNetCfgBindingPath>> = Some(&mut None as *mut _);
        match ipv6_bindings.EnumBindingPaths(EBP_BELOW, enum_binding_paths) {
            Ok(_) => (),
            Err(e) => { return Err(format!("Error when enumerating the binding paths. Code: {}", e.code())); },
        };

        let enum_binding_paths: *mut Option<IEnumNetCfgBindingPath> = enum_binding_paths.ok_or("Enum binding paths are empty (1/2)")?;
        let enum_binding_paths: &IEnumNetCfgBindingPath = (&*enum_binding_paths).as_ref().ok_or("Enum binding paths are empty (2/2)")?;

        iterate_binding_paths(enum_binding_paths, target_status)?;

        net_cfg.Apply()
            .map_err(|e| format!("Error when applying INetCfg changes. Code: {}", e.code()))?;

        log::info!("IPv6 changes applied successfully");
        Ok(())
    }
}

unsafe fn iterate_binding_paths(enum_binding_paths: &IEnumNetCfgBindingPath, target_status: bool) -> Result<(), String> {
    unsafe {
        loop {
            let mut binding_paths: [Option<INetCfgBindingPath>; 1] = [None];
            let mut fetched: u32 = 0;

            let result: windows::core::Result<()> = enum_binding_paths.Next(&mut binding_paths, Some(&mut fetched));
            
            if result.is_err() || fetched == 0 {
                break;
            }

            if let Some(binding_path) = &binding_paths[0] {
                let mut path_token: Vec<u16> = String::new().encode_utf16().chain(std::iter::once(0u16)).collect();
                let mut path_token: PWSTR = PWSTR(path_token.as_mut_ptr());
                let path_token: Option<*mut PWSTR> = Some(&mut path_token as *mut _);
                
                if binding_path.GetPathToken(path_token).is_ok() {
                    if let Some(path_token) = path_token {
                        let path_str: String = pwstr_to_string(*path_token);
                        if path_str.to_uppercase().contains(&ADAPTER_GUID_STR) {
                            return toggle_ipv6_in_binding_path(binding_path, target_status);
                        }
                        //CoTaskMemFree(Some(path_token as *const _));
                    }
                }
            }
        }
    }

    Err("The adapter was not found in any of the binding paths".to_string())
}

unsafe fn toggle_ipv6_in_binding_path(binding_path: &INetCfgBindingPath, target_status: bool) -> Result<(), String> {
    unsafe {
        match binding_path.IsEnabled() {
            Ok(_) => {
                match binding_path.Enable(target_status) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(format!("Error when setting IPv6 to {target_status} in the adapter. Error: {err}")),
                }
            },
            Err(_) => Err("Error when checking if binding path is enabled".to_string()),
        }
    }
}

unsafe fn pwstr_to_string(pwstr: PWSTR) -> String {
    if pwstr.is_null() {
        return String::new();
    }

    unsafe {
        let len = (0..).take_while(|&i| *pwstr.0.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(pwstr.0, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}