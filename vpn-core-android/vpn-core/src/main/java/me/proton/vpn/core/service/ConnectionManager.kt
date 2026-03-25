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

package me.proton.vpn.core.service

import android.net.Network
import android.net.VpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import me.proton.vpn.core.api.InitialConfig
import me.proton.vpn.core.api.InterfaceConfig
import me.proton.vpn.core.api.Logger
import me.proton.vpn.core.api.PacketCaptureInfo
import me.proton.vpn.core.api.Peer
import me.proton.vpn.core.api.VpnConnectionState
import me.proton.vpn.core.api.VpnWaitReason
import me.proton.vpn.core.internal.WallClockMs
import me.proton.vpn.core.internal.decodeBase64
import me.proton.vpn.core.internal.toCoreApi
import me.proton.vpn.core.internal.toUniFFI
import me.proton.vpn.core.service.usecases.EstablishTun
import me.proton.vpn.core.service.usecases.NetworkObserver
import uniffi.protun.Connection
import uniffi.protun.ConnectivityEvent
import uniffi.protun.EventCallback
import uniffi.protun.InitialConnectionConfig
import uniffi.protun.LogLevel
import uniffi.protun.PrivateKeyUpdateInfo
import uniffi.protun.State
import uniffi.protun.StateChangedCallback
import uniffi.protun.WaitReason
import java.lang.ref.WeakReference
import java.util.Date

internal class ConnectionManager(
    private val networkObserver: NetworkObserver,
    private val establishTun: EstablishTun,
    private val wallClockMs: WallClockMs,
    private val logger: Logger

) {
    data class ActiveConnection(
        val connection: Connection,
        val validatedNetworks: Set<Network>,
        val startedAt: Date,
        val stateChangeCallback: ProTunStateChangedCallback,
    ) {
        fun clear() {
            stateChangeCallback.clear()
            // This will block main thread but should finish quickly. Allows all events to be
            // delivered to the app before service is closed.
            connection.disconnectAndWait()
            connection.destroy()
        }
    }

    private lateinit var serviceScope: CoroutineScope
    var activeConnection: ActiveConnection? = null
        private set

    val state = MutableStateFlow<VpnConnectionState>(VpnConnectionState.Disconnected())

    fun init(serviceScope: CoroutineScope) {
        this.serviceScope = serviceScope
        networkObserver.validatedNetworks.onEach { validatedNetworks ->
            logger.log(LogLevel.INFO, "Validated networks change: $validatedNetworks")
            activeConnection?.let { connection ->
                if (connection.validatedNetworks != validatedNetworks) {
                    val wasUnavailable = connection.validatedNetworks.isEmpty()
                    activeConnection = connection.copy(validatedNetworks = validatedNetworks)
                    connection.connection.onConnectivityChange(
                        when {
                            validatedNetworks.isEmpty() -> ConnectivityEvent.DOWN
                            wasUnavailable -> ConnectivityEvent.UP
                            else -> ConnectivityEvent.NETWORK_SWITCH
                        }
                    )
                }
            }
        }.launchIn(serviceScope)
    }

    fun connect(
        config: InitialConfig,
        builder: VpnService.Builder,
        socketProtectCallback: ProTunSocketProtectCallback,
        eventCallback: EventCallback
    ) {
        if (activeConnection != null)
            clearConnection(VpnConnectionState.Connecting(emptyList()))

        when (val establishResult = establishTun(config.interfaceConfig, builder)) {
            is EstablishTun.Result.Success -> {
                val tunFd = establishResult.fd
                val stateChangeCallback = ProTunStateChangedCallback(WeakReference(this))
                val validatedNetworks = networkObserver.validatedNetworks.value
                val networkAvailable = validatedNetworks.isNotEmpty()
                logger.log(LogLevel.INFO, "pvpn: Starting ProTUN, network available: $networkAvailable")
                val nativeConnection = Connection.unixConnect(
                    config = InitialConnectionConfig(
                        wgPrivateKey = config.clientED25519PrivateKeyBase64.decodeBase64(),
                        peers = config.peers.toUniFFI(),
                        networkAvailable = networkAvailable,
                        pcapFile = config.packetCaptureInfo?.toUniFFI(),
                    ),
                    tunFd = tunFd.detachFd(),
                    stateChangeCallback = stateChangeCallback,
                    socketFdAvailableCallback = socketProtectCallback,
                    eventCallback = eventCallback
                )
                activeConnection = ActiveConnection(
                    connection = nativeConnection,
                    validatedNetworks = validatedNetworks,
                    stateChangeCallback = stateChangeCallback,
                    startedAt = Date(wallClockMs()),
                )
            }
            is EstablishTun.Result.Failure -> {
                state.value = VpnConnectionState.Disconnected(establishResult.reason)
            }
        }
    }

    fun clearConnection(endState: VpnConnectionState = VpnConnectionState.Disconnected()) {
        activeConnection?.clear()
        activeConnection = null
        state.value = endState
    }

    fun updateInterfaceConfig(interfaceConfig: InterfaceConfig, builder: VpnService.Builder) {
        val ongoingConnection = activeConnection
        if (ongoingConnection != null) {
            when (val establishResult = establishTun(interfaceConfig, builder)) {
                is EstablishTun.Result.Failure -> {
                    clearConnection(VpnConnectionState.Disconnected(establishResult.reason))
                }
                is EstablishTun.Result.Success -> {
                    val newTunFd = establishResult.fd
                    logger.log(LogLevel.INFO, "pvpn: Re-established VPN interface ${newTunFd.fd}")
                    ongoingConnection.connection.updateUnixTun(newTunFd.detachFd())
                }
            }
        }
    }

    fun updatePeers(peers: List<Peer>) {
        activeConnection?.connection?.updatePeers(peers.toUniFFI())
    }

    fun updateClientPrivateKey(clientED25519PrivateKeyPem: String) {
        activeConnection?.connection?.updateWgPrivateKey(
            PrivateKeyUpdateInfo(clientED25519PrivateKeyPem.decodeBase64())
        )
    }

    fun setPacketCaptureEnabled(packetCaptureInfo: PacketCaptureInfo?) {
        if (packetCaptureInfo == null)
            activeConnection?.connection?.stopPacketCapture()
        else
            activeConnection?.connection?.startPacketCapture(packetCaptureInfo.toUniFFI())
    }

    fun requestConnectionStats() {
        activeConnection?.connection?.getStats()
    }

    fun onProTunStateChange(proTunState: State) {
        serviceScope.launch {
            val activeConnection = activeConnection
            if (activeConnection == null)
                state.value = VpnConnectionState.Disconnected()
            else {
                val newState = when (proTunState) {
                    is State.Disconnected -> VpnConnectionState.Disconnected(proTunState.error?.toCoreApi())
                    is State.Connecting -> VpnConnectionState.Connecting(proTunState.peers.map { it.toCoreApi() })
                    is State.WaitingForAction -> handleAction(proTunState.reason)
                    is State.Connected -> VpnConnectionState.Connected(
                        proTunState.peer.toCoreApi(),
                        connectedSince = activeConnection.startedAt
                    )
                }
                if (newState != null)
                    state.value = newState
            }

        }
    }

    private fun handleAction(reason: WaitReason): VpnConnectionState? =
        when (reason) {
            is WaitReason.TunIoError -> {
                //TODO(VPNAND-2460): Handle TUN I/O errors properly. Tun fd might invalid because:
                // - another VPN app took over the TUN interface -> disconnect with error
                // - system closed the TUN interface due to resource constraints
                logger.log(LogLevel.ERROR, "TUN I/O error: ${reason.message}")
                null
            }
            WaitReason.WaitingForNetwork ->
                VpnConnectionState.WaitingForAction(VpnWaitReason.WaitingForNetwork)
        }
}

internal class ProTunStateChangedCallback(val weakManager: WeakReference<ConnectionManager>): StateChangedCallback {
    override fun onStateChanged(state: State) {
        weakManager.get()?.onProTunStateChange(state)
    }

    fun clear() {
        weakManager.clear()
    }
}
