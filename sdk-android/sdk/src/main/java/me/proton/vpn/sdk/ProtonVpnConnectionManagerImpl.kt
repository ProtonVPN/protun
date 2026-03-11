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

package me.proton.vpn.sdk

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.launch
import me.proton.vpn.sdk.api.InitialConfig
import me.proton.vpn.sdk.api.InterfaceConfig
import me.proton.vpn.sdk.api.Logger
import me.proton.vpn.sdk.api.PacketCaptureInfo
import me.proton.vpn.sdk.api.Peer
import me.proton.vpn.sdk.api.ProtonVpnConnectionManager
import me.proton.vpn.sdk.api.VpnConnectionEvent
import me.proton.vpn.sdk.api.VpnConnectionState
import me.proton.vpn.sdk.api.VpnDisconnectError
import me.proton.vpn.sdk.internal.toSdk
import me.proton.vpn.sdk.service.ProTunVpnService
import me.proton.vpn.sdk.service.ProTunVpnServiceBinder
import me.proton.vpn.sdk.service.ProTunVpnServiceCallback
import uniffi.protun.Event
import uniffi.protun.LogLevel

internal class ProtonVpnConnectionManagerImpl(
    private val mainScope: CoroutineScope,
    private val context: Context,
    private val logger: Logger,
): ProtonVpnConnectionManager {

    private val serviceConnection: ServiceConnection

    private var bound = false

    private val _eventsInternal = MutableSharedFlow<Event>(
        extraBufferCapacity = 100,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    override val events: Flow<VpnConnectionEvent> = _eventsInternal
        .map { event -> event.toSdk() }
        .filterNotNull()

    private val _state = MutableStateFlow<VpnConnectionState>(VpnConnectionState.Disconnected())
    override val state: StateFlow<VpnConnectionState> = _state

    // Cold flow that request connection stats every second when connected.
    private fun createStatsRequestFlow() = state
        .map { it is VpnConnectionState.Connected }
        .distinctUntilChanged()
        .flatMapLatest { isConnected ->
            if (isConnected) {
                flow {
                    emit(Unit)
                    while (true) {
                        requestConnectionStats()
                        delay(1000)
                    }
                }
            } else {
                emptyFlow()
            }
        }

    override val connectionStats = combine(
        createStatsRequestFlow(),
        _eventsInternal
    ) { _, event -> (event as? Event.ConnectionStats)?.toSdk() }
        .filterNotNull()
        .distinctUntilChanged()
        .shareIn(mainScope, started = SharingStarted.WhileSubscribed(stopTimeoutMillis = 1_000))

    init {
        serviceConnection = object : ServiceConnection {

            private var serviceBinder: ProTunVpnServiceBinder? = null
            val callback = object : ProTunVpnServiceCallback {
                override fun onStateChanged(state: VpnConnectionState) {
                    // Don't accept state changes after disconnecting
                    if (bound)
                        setState(state)
                }

                override fun onEvent(event: Event) {
                    emitEvent(event)
                }
            }

            override fun onBindingDied(name: ComponentName?) {
                bound = false
                _state.value = VpnConnectionState.Disconnected()
                super.onBindingDied(name)
            }

            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                serviceBinder = service as ProTunVpnServiceBinder
                setState(service.getState())
                service.registerCallback(callback)
            }

            override fun onServiceDisconnected(name: ComponentName) {
                serviceBinder?.unregisterCallback(callback)
                setState(VpnConnectionState.Disconnected())
            }
        }
    }

    override fun connect(config: InitialConfig) {
        mainScope.launch {
            if (!bound) {
                bound = context.bindService(
                    Intent(context, ProTunVpnService::class.java),
                    serviceConnection,
                    Context.BIND_ABOVE_CLIENT
                )
            }
            if (!bound) {
                context.unbindService(serviceConnection)
                setState(VpnConnectionState.Disconnected(
                    VpnDisconnectError.ServiceError("Failed to bind to VPN service"))
                )
            } else {
                sendAction(ProTunVpnService.VpnAction.Connect(config))
            }
        }
    }

    override fun updateInterfaceConfig(interfaceConfig: InterfaceConfig) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.Interface(interfaceConfig))
        }
    }

    override fun updatePeers(peers: List<Peer>) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.Peers(peers))
        }
    }

    override fun updateClientPrivateKey(clientED25519PrivateKeyBase64: String) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.ClientPrivateKey(clientED25519PrivateKeyBase64))
        }
    }

    override fun setPacketCaptureEnabled(packetCaptureInfo: PacketCaptureInfo?) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.PacketCapture(packetCaptureInfo))
        }
    }

    private fun requestConnectionStats() {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.RequestConnectionStats)
        }
    }

    override fun disconnect() {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Disconnect)
            context.unbindService(serviceConnection)
            bound = false
            setState(VpnConnectionState.Disconnected())
        }
    }

    private fun sendAction(vpnAction: ProTunVpnService.VpnAction) {
        ContextCompat.startForegroundService(context,ProTunVpnService.actionIntent(context, vpnAction))
    }

    private fun setState(state: VpnConnectionState) {
        _state.value = state
    }

    private fun emitEvent(event: Event) {
        val emitSuccessful = _eventsInternal.tryEmit(event)
        if (!emitSuccessful)
            logger.log(LogLevel.WARN, "Dropping VPN event $event because the buffer is full")
    }
}

private fun Event.toSdk(): VpnConnectionEvent? = when (this) {
    is Event.ConnectionStats -> null // ConnectionStats are exposed in a dedicated flow, not as events
    is Event.PacketCaptureStarted -> VpnConnectionEvent.PacketCaptureStarted(info.toSdk())
    is Event.PacketCaptureStopped -> VpnConnectionEvent.PacketCaptureStopped(reason.toSdk())
}