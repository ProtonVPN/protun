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

package me.proton.vpn.core

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.launch
import me.proton.vpn.core.api.InitialConfig
import me.proton.vpn.core.api.InterfaceConfig
import me.proton.vpn.core.api.LocalAgentSettings
import me.proton.vpn.core.api.Logger
import me.proton.vpn.core.api.PacketCaptureInfo
import me.proton.vpn.core.api.Peer
import me.proton.vpn.core.api.ProtonVpnConnectionManager
import me.proton.vpn.core.api.VpnConnectionEvent
import me.proton.vpn.core.api.VpnConnectionState
import me.proton.vpn.core.api.VpnDisconnectError
import me.proton.vpn.core.api.VpnState
import me.proton.vpn.core.internal.tickFlow
import me.proton.vpn.core.internal.toCoreApi
import me.proton.vpn.core.service.ProTunVpnService
import me.proton.vpn.core.service.ProTunVpnServiceBinder
import me.proton.vpn.core.service.ProTunVpnServiceCallback
import uniffi.protun.Event
import uniffi.protun.LogLevel
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

internal class ProtonVpnConnectionManagerImpl(
    private val mainScope: CoroutineScope,
    private val context: Context,
    private val logger: Logger,
    private val realtimeClockMs: () -> Long = System::currentTimeMillis,
): ProtonVpnConnectionManager {

    private val serviceConnection: ServiceConnection

    private var bound = false

    private val _eventsInternal = MutableSharedFlow<Event>(
        extraBufferCapacity = 100,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    override val events: Flow<VpnConnectionEvent> = _eventsInternal
        .map { event -> event.toCoreApi() }
        .filterNotNull()

    private val _state = MutableStateFlow<VpnState>(VpnState.Disconnected)
    override val state: StateFlow<VpnState> = _state

    // Cold flow that requests stats every second when connected. [request] is invoked once per
    // tick on the main scope; events flow back through [_eventsInternal].
    @OptIn(ExperimentalCoroutinesApi::class)
    private fun createStatsRequestFlow(interval: Duration, request: () -> Unit) = state
        .map { it.connectionState is VpnConnectionState.Connected }
        .distinctUntilChanged()
        .flatMapLatest { isConnected ->
            if (isConnected) {
                tickFlow(interval, realtimeClockMs).onEach { request() }
            } else {
                flowOf(null)
            }
        }

    override val connectionStats = combine(
        createStatsRequestFlow(interval = 1.seconds) { requestConnectionStats() },
        _eventsInternal
    ) { _, event -> (event as? Event.ConnectionStats)?.toCoreApi() }
        .filterNotNull()
        .distinctUntilChanged()
        .shareIn(mainScope, started = SharingStarted.WhileSubscribed(stopTimeoutMillis = 1_000))

    override val localAgentStats = combine(
        createStatsRequestFlow(interval = 5.seconds) { requestLocalAgentStats() },
        _eventsInternal
    ) { _, event -> (event as? Event.LocalAgentStats)?.toCoreApi() }
        .filterNotNull()
        .distinctUntilChanged()
        .shareIn(mainScope, started = SharingStarted.WhileSubscribed(stopTimeoutMillis = 1_000))

    init {
        serviceConnection = object : ServiceConnection {

            private var serviceBinder: ProTunVpnServiceBinder? = null
            val callback = object : ProTunVpnServiceCallback {
                override fun onStateChanged(state: VpnState) {
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
                _state.value = VpnState.Disconnected
                super.onBindingDied(name)
            }

            override fun onServiceConnected(name: ComponentName, service: IBinder) {
                serviceBinder = service as ProTunVpnServiceBinder
                setState(service.getState())
                service.registerCallback(callback)
            }

            override fun onServiceDisconnected(name: ComponentName) {
                serviceBinder?.unregisterCallback(callback)
                setState(VpnState.Disconnected)
            }
        }
    }

    override fun connect(config: InitialConfig) {
        //NOTE: concurrency issues in this class are avoided by delegating all work reading/writing
        //  shared state to the main thread.
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
                setState(
                    VpnState.disconnectedWith(VpnDisconnectError.ServiceError("Failed to bind to VPN service"))
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

    override fun updateLocalAgentSettings(localAgentSettings: LocalAgentSettings) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.Settings(localAgentSettings))
        }
    }

    override fun updateApiSelector(selector: String) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.ApiSelector(selector))
        }
    }

    override fun updatePeers(peers: List<Peer>) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.Peers(peers))
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

    private fun requestLocalAgentStats() {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Update.RequestLocalAgentStats)
        }
    }

    override fun disconnect(error: VpnDisconnectError?) {
        mainScope.launch {
            sendAction(ProTunVpnService.VpnAction.Disconnect)
            if (bound) {
                context.unbindService(serviceConnection)
                bound = false
            }
            setState(if (error == null) VpnState.Disconnected else VpnState.disconnectedWith(error))
        }
    }

    private fun sendAction(vpnAction: ProTunVpnService.VpnAction) {
        ContextCompat.startForegroundService(context,ProTunVpnService.actionIntent(context, vpnAction))
    }

    private fun setState(state: VpnState) {
        _state.value = state
    }

    private fun emitEvent(event: Event) {
        val emitSuccessful = _eventsInternal.tryEmit(event)
        if (!emitSuccessful)
            logger.log(LogLevel.WARN, "Dropping VPN event $event because the buffer is full")
    }
}
