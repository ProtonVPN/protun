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

package me.proton.vpn.core.sample_app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import me.proton.vpn.core.api.PeerConnection
import me.proton.vpn.core.api.ProtonVpnConnectionManager
import me.proton.vpn.core.api.VpnConnectionEvent
import me.proton.vpn.core.api.VpnConnectionState
import me.proton.vpn.core.sample_app.data.ConfigStore
import me.proton.vpn.core.sample_app.data.VpnConfig
import me.proton.vpn.core.sample_app.ui.Event.ShowMessage
import uniffi.protun.getSessionForkSelector
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val connectionManager: ProtonVpnConnectionManager,
    private val configStore: ConfigStore,
) : ViewModel() {

    val lastConfig = configStore.data
    val events = MutableSharedFlow<Event>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    val uiState = connectionManager.state.map { state ->
        val connectionState = state.connectionState
        if (connectionState is VpnConnectionState.Loading) {
            UiState.loading()
        } else {
            val buttonType = when (connectionState) {
                is VpnConnectionState.Disconnected -> ButtonType.Connect
                else -> ButtonType.Disconnect
            }
            val stateLabel = when (connectionState) {
                VpnConnectionState.Loading -> ""
                is VpnConnectionState.Connected -> "Connected: ${connectionState.connection.toDisplay()}"
                is VpnConnectionState.Connecting -> "Connecting... ${connectionState.waitReasons}"
                is VpnConnectionState.ConnectingToLocalAgent ->
                    "Connecting to local agent... ${connectionState.waitReason}"
                is VpnConnectionState.Disconnected -> if (connectionState.error != null) {
                    "Disconnected: ${connectionState.error}"
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

    init {
        connectionManager.events.onEach { event ->
            val uiEvent = when (event) {
                is VpnConnectionEvent.PacketCaptureStarted ->
                    Event.ShowMessage("Packet capture started: ${event.info.file}")
                is VpnConnectionEvent.PacketCaptureStopped ->
                    Event.ShowMessage("Packet capture stopped: ${event.reason.javaClass.simpleName}")
                is VpnConnectionEvent.Error ->
                    Event.ShowMessage("Error: ${event.error.javaClass.simpleName}")
            }
            events.emit(uiEvent)
        }.launchIn(viewModelScope)

        // Connection stats updates will come every 1s when state is Connected
        connectionManager.connectionStats.onEach {
            println("Connection stats: $it")
        }.launchIn(viewModelScope)
    }

    fun connect(vpnConfig: VpnConfig) {
        viewModelScope.launch {
            configStore.updateData { vpnConfig }
        }
        try {
            connectionManager.connect(vpnConfig.toInitialConfig())
        } catch (e: IllegalArgumentException) {
            viewModelScope.launch {
                events.emit(Event.ShowMessage("Invalid configuration: ${e.message}"))
            }
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
        viewModelScope.launch { events.emit(Event.ShowMessage(message)) }
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
    data class ShowMessage(val message: String) : Event
}

private fun PeerConnection.toDisplay() =
    "${entryAddr.toString().removePrefix("/")} $protocol id=$id"