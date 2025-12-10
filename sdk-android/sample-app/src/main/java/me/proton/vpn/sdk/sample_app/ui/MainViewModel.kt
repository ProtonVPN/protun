/*
 * Copyright (c) 2025 Proton AG
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

package me.proton.vpn.sdk.sample_app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import me.proton.vpn.sdk.api.PeerConnection
import me.proton.vpn.sdk.api.ProtonVpnConnectionManager
import me.proton.vpn.sdk.api.VpnConnectionState
import me.proton.vpn.sdk.sample_app.data.ConfigStore
import me.proton.vpn.sdk.sample_app.data.VpnConfig
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val connectionManager: ProtonVpnConnectionManager,
    private val configStore: ConfigStore,
) : ViewModel() {

    val lastConfig = configStore.data
    val events = MutableSharedFlow<Event>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    val uiState = connectionManager.state.map { state ->
        if (state is VpnConnectionState.Loading) {
            UiState.loading()
        } else {
            val buttonType = when (state) {
                is VpnConnectionState.Disconnected -> ButtonType.Connect
                else -> ButtonType.Disconnect
            }
            val stateLabel = when (state) {
                VpnConnectionState.Loading -> ""
                is VpnConnectionState.Connected -> "Connected: ${state.connection.toDisplay()}"
                is VpnConnectionState.Connecting -> "Connecting..."
                is VpnConnectionState.WaitingForAction -> "Waiting for action: ${state.reason}"
                is VpnConnectionState.Disconnected -> if (state.error != null) {
                    "Disconnected: ${state.error}"
                } else {
                    "Disconnected"
                }
            }
            UiState(
                stateLabel = stateLabel,
                buttonType = buttonType,
            )
        }
    }.stateIn(
        viewModelScope,
        started = SharingStarted.WhileSubscribed(stopTimeoutMillis = 5_000),
        initialValue = UiState.loading()
    )

    fun connect(vpnConfig: VpnConfig) {
        viewModelScope.launch {
            configStore.updateData { vpnConfig }
        }
        try {
            connectionManager.connect(vpnConfig.toInitialConfig())
        } catch (e: IllegalArgumentException) {
            events.tryEmit(Event.ConnectionError("Invalid configuration: ${e.message}") )
        }
    }

    fun disconnect() {
        connectionManager.disconnect()
    }

    fun onPermissionError(error: VpnPermissionError) {
        val message = when (error) {
            VpnPermissionError.PermissionDenied -> "VPN permission denied"
            VpnPermissionError.VpnNotSupported-> "VPN not supported on this device"
        }
        events.tryEmit(Event.ConnectionError(message))
    }
}

enum class ButtonType {
    Loading,
    Connect,
    Disconnect,
}

data class UiState(
    val stateLabel: String,
    val buttonType: ButtonType,
) {
    companion object {
        fun loading() = UiState(
            stateLabel = "",
            buttonType = ButtonType.Loading,
        )
    }
}

sealed interface Event {
    data class ConnectionError(val message: String) : Event
}

private fun PeerConnection.toDisplay() =
    "${entryAddr.toString().removePrefix("/")} $protocol id=$id"