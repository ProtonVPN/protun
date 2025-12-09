/*
 * Copyright (c) 2025. Proton AG
 *
 * This file is part of ProtonVPN.
 *
 * ProtonVPN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ProtonVPN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
 */

package me.proton.vpn.sdk.api

import android.os.Parcelable
import kotlinx.coroutines.flow.StateFlow
import kotlinx.parcelize.Parcelize

/**
 * ProtonVPN connection manager. Provides methods to establish, manage and track VPN connection to
 * ProtonVPN servers.
 *
 * Instance of this interface can be obtained from [ProtonVpnSdk].
 *
 * Usage:
 * '''kotlin
 *   // Observe VPN state changes in kotlin
 *   vpnManager.state.onEach { state -> handleState(state) }.launchIn(coroutineScope)
 *   // or with Java-friendly listener
 *   manager.registerStateListener (state -> { ... });
 *
 *   // start initial connection
 *   vpnManager.connect(InitialConfig(...))
 *
 *   // No need (and not recommended) to call disconnect before switching servers
 *   vpnManager.updatePeers(newPeers)
 *
 *   // Update TUN interface configuration on the fly (e.g. add/remove apps to split tunneling)
 *   vpnManager.updateInterfaceConfig(newInterfaceConfig)
 *
 *   vpnManager.disconnect()
 * '''
 */
interface ProtonVpnConnectionManager {
    val state: StateFlow<VpnConnectionState>
    fun connect(config: InitialConfig)
    fun updateInterfaceConfig(interfaceConfig: InterfaceConfig)
    fun updatePeers(peers: List<Peer>)
    fun updateClientPrivateKey(clientED25519PrivateKeyBase64: String)
    fun disconnect()

    /**
     * Java-friendly state listener
     */
    fun registerStateListener(listener: VpnConnectionStateListener)
    fun unregisterStateListener(listener: VpnConnectionStateListener)
}

fun interface VpnConnectionStateListener {
    fun onStateChanged(state: VpnConnectionState)
}

@Parcelize
data class InitialConfig(

    /**
     * TUN interface configuration specifying routes, split tunneling, DNS servers, etc.
     */
    val interfaceConfig: InterfaceConfig,

    /**
     * 32 bytes base64-encoded ED25519 private key.
     */
    val clientED25519PrivateKeyBase64: String,

    /**
     * List of available peers to connect to. The SDK will select best configuration
     * (IP, protocol, ports) based on peer priority and reachability in current network conditions.
     */
    val peers: List<Peer>,
): Parcelable