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

import android.net.VpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import me.proton.vpn.core.api.ConnectionMode
import me.proton.vpn.core.api.ForkSelectorInfo
import me.proton.vpn.core.api.InitialConfig
import me.proton.vpn.core.api.InterfaceConfig
import me.proton.vpn.core.api.InterfaceState
import me.proton.vpn.core.api.InvalidateRequest
import me.proton.vpn.core.api.LocalAgentSettings
import me.proton.vpn.core.api.Logger
import me.proton.vpn.core.api.PacketCaptureInfo
import me.proton.vpn.core.api.Peer
import me.proton.vpn.core.api.VpnConnectionState
import me.proton.vpn.core.api.VpnState
import me.proton.vpn.core.internal.PersistentCacheStorage
import me.proton.vpn.core.internal.WallClockMs
import me.proton.vpn.core.internal.toCoreApi
import me.proton.vpn.core.internal.toUniFFI
import me.proton.vpn.core.service.usecases.EstablishTun
import me.proton.vpn.core.service.usecases.NetworkObserver
import uniffi.protun.CacheKey
import uniffi.protun.ConfigUpdate
import uniffi.protun.Connection
import uniffi.protun.ConnectionState
import uniffi.protun.EventCallback
import uniffi.protun.InitialConnectionConfig
import uniffi.protun.LogLevel
import uniffi.protun.StateChangedCallback
import uniffi.protun.TunStreamInfo
import java.lang.ref.WeakReference
import java.util.Date

internal class ConnectionManager(
    private val networkObserver: NetworkObserver,
    private val establishTun: EstablishTun,
    private val wallClockMs: WallClockMs,
    private val logger: Logger,
    private val cache: PersistentCacheStorage,
) {
    data class ActiveConnection(
        val connection: Connection,
        val currentConfig: InitialConfig,
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

    private var isAlwaysOn : Boolean? = null
    private var isLockdownEnabled : Boolean? = null

    val state = MutableStateFlow(VpnState.Disconnected)

    fun init(serviceScope: CoroutineScope) {
        this.serviceScope = serviceScope

        // Start observing immediately to not lose any events emitted after this
        serviceScope.launch(start = CoroutineStart.UNDISPATCHED) {
            networkObserver.events.collect { event ->
                activeConnection?.connection?.onConnectivityChange(event)
            }
        }
    }

    fun connect(
        config: InitialConfig,
        invalidateRequest: InvalidateRequest?,
        builder: VpnService.Builder,
        socketProtectCallback: ProTunSocketProtectCallback,
        eventCallback: EventCallback,
    ) {
        val currentConfig = activeConnection?.currentConfig
        val newUserId = config.userId
        if (currentConfig != null) {
            // For local agent mode if there's active connection just update it instead of full restart
            val bothLocalAgentMode = currentConfig.mode is ConnectionMode.LocalAgent && config.mode is ConnectionMode.LocalAgent
            val sameUser = currentConfig.userId == newUserId
            if (bothLocalAgentMode && sameUser && invalidateRequest == null) {
                logger.log(LogLevel.INFO, "pvpn connect: updating live VPN connection")
                activeConnection = activeConnection?.copy(currentConfig = config)

                val interfaceUpdate = if (config.interfaceConfig != currentConfig.interfaceConfig) {
                    when (val establishResult = establishTun(config.interfaceConfig, builder)) {
                        is EstablishTun.Result.Failure -> {
                            clearConnection(VpnConnectionState.Disconnected(establishResult.reason))
                            return
                        }

                        is EstablishTun.Result.Success -> {
                            logger.log(LogLevel.INFO, "pvpn: Re-established VPN interface ${establishResult.fd.fd}")
                            TunStreamInfo.TunFd(establishResult.fd.detachFd())
                        }
                    }
                } else {
                    null
                }

                update(config.peers, config.mode.settings, interfaceUpdate)

                if (currentConfig.packetCaptureInfo != config.packetCaptureInfo)
                    setPacketCaptureEnabled(config.packetCaptureInfo)

                return
            } else {
                logger.log(LogLevel.INFO, "pvpn connect: restarting VPN connection bothLocalAgentMode=$bothLocalAgentMode sameUser=$sameUser invalidateRequest=$invalidateRequest")
            }

            clearConnection(VpnConnectionState.Connecting(connections = emptyList(), waitReasons = emptyList()))
        }

        val userCache = cache.cacheFor(newUserId ?: "")
        if (invalidateRequest != null) {
            when (invalidateRequest) {
                InvalidateRequest.Certificate -> userCache.remove(CacheKey.CERTIFICATE)
                InvalidateRequest.All -> userCache.clearAll()
            }
        }

        when (val establishResult = establishTun(config.interfaceConfig, builder)) {
            is EstablishTun.Result.Success -> {
                val tunFd = establishResult.fd
                val stateChangeCallback = ProTunStateChangedCallback(WeakReference(this))
                val networkAvailable = networkObserver.isNetworkAvailable
                logger.log(LogLevel.INFO, "pvpn: Starting ProTUN, network available: $networkAvailable")
                val nativeConnection = Connection.unixConnect(
                    config = InitialConnectionConfig(
                        peers = config.peers.toUniFFI(),
                        networkAvailable = networkAvailable,
                        pcapFile = config.packetCaptureInfo?.toUniFFI(),
                        connectionMode = config.mode.toUniFFI(),
                        sniStrategy = config.sniStrategy.toUniFFI(),
                    ),
                    tunFd = tunFd.detachFd(),
                    stateChangeCallback = stateChangeCallback,
                    socketFdAvailableCallback = socketProtectCallback,
                    eventCallback = eventCallback,
                    cache = userCache,
                )
                activeConnection = ActiveConnection(
                    connection = nativeConnection,
                    stateChangeCallback = stateChangeCallback,
                    startedAt = Date(wallClockMs()),
                    currentConfig = config,
                )
            }

            is EstablishTun.Result.Failure -> {
                state.value = VpnState.disconnectedWith(establishResult.reason)
            }
        }
    }

    fun updateAlwaysOn(
        isAlwaysOn: Boolean,
        isLockdownEnabled: Boolean,
    ) {
        this.isAlwaysOn = isAlwaysOn
        this.isLockdownEnabled = isLockdownEnabled
        state.value = state.value.copy(alwaysOn = isAlwaysOn, isLockdownEnabled = isLockdownEnabled)
    }

    fun debugLog() {
        activeConnection?.connection?.debugLog()
    }

    fun clearConnection(endState: VpnConnectionState = VpnConnectionState.Disconnected()) {
        activeConnection?.clear()
        activeConnection = null
        state.value = VpnState(InterfaceState.Down(null), endState, null, null)
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
                    ongoingConnection.connection.updateUnixTun(TunStreamInfo.TunFd(newTunFd.detachFd()))
                }
            }
        }
    }

    fun updatePeers(peers: List<Peer>) {
        activeConnection?.connection?.updatePeers(peers.toUniFFI())
    }

    fun updateLocalAgentSettings(settings: LocalAgentSettings) {
        activeConnection?.connection?.updateLocalAgentSettings(settings.toUniFFI())
    }

    fun update(peersUpdate: List<Peer>?, settingsUpdate: LocalAgentSettings?, tunUpdate: TunStreamInfo?) {
        activeConnection?.connection?.update(
            ConfigUpdate(
                peersUpdate?.toUniFFI(),
                settingsUpdate?.toUniFFI(),
                tunUpdate
            )
        )
    }

    fun provideApiForkSelector(selector: ForkSelectorInfo) {
        activeConnection?.connection?.provideApiForkSelector(selector.toUniFFI())
    }

    fun invalidateCertificate(userId: String) {
        val connection = activeConnection
        if (connection?.currentConfig?.userId == userId) {
            connection.connection.invalidateCertificate()
        }
    }

    fun setPacketCaptureEnabled(packetCaptureInfo: PacketCaptureInfo?) {
        if (packetCaptureInfo == null)
            activeConnection?.connection?.stopPacketCapture()
        else
            activeConnection?.connection?.startPacketCapture(packetCaptureInfo.toUniFFI())
    }

    fun requestLocalAgentStats() {
        activeConnection?.connection?.requestLocalAgentStats()
    }

    fun requestConnectionStats() {
        activeConnection?.connection?.requestStats()
    }

    fun onProTunStateChange(proTunState: uniffi.protun.VpnState) {
        serviceScope.launch {
            val activeConnection = activeConnection
            if (activeConnection != null) {
                val connectionState = when (val connectionState = proTunState.connectionState) {
                    is ConnectionState.Disconnected ->
                        VpnConnectionState.Disconnected(connectionState.error?.toCoreApi())

                    is ConnectionState.Connecting -> VpnConnectionState.Connecting(
                        connectionState.peers.map { it.toCoreApi() },
                        connectionState.waitReasons.map { it.toCoreApi() },
                    )

                    is ConnectionState.ConnectingToLocalAgent -> VpnConnectionState.ConnectingToLocalAgent(
                        connectionState.peer.toCoreApi(),
                        connectionState.waitReason?.toCoreApi(),
                    )

                    is ConnectionState.Connected -> VpnConnectionState.Connected(
                        connectionState.peer.toCoreApi(),
                        connectedSince = activeConnection.startedAt,
                        agentConnectionInfo = connectionState.agentInfo?.toCoreApi()
                    )
                }
                //TODO(VPNAND-2460): Handle TUN I/O errors properly. Tun fd might invalid because:
                // - another VPN app took over the TUN interface -> disconnect with error
                // - system closed the TUN interface due to resource constraints
                val ipV6Enabled = activeConnection.currentConfig.interfaceConfig.supportInTunnelIPv6
                state.value = VpnState(
                    proTunState.interfaceState.toCoreApi(ipV6Enabled),
                    connectionState,
                    isAlwaysOn,
                    isLockdownEnabled
                )
            }
        }
    }
}

internal class ProTunStateChangedCallback(val weakManager: WeakReference<ConnectionManager>): StateChangedCallback {

    override fun onStateChanged(state: uniffi.protun.VpnState) {
        weakManager.get()?.onProTunStateChange(state)
    }

    fun clear() {
        weakManager.clear()
    }
}

private val InitialConfig.userId: String? get() =
    (this.mode as? ConnectionMode.LocalAgent)?.userId