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

package me.proton.vpn.sdk.service

import android.net.Network
import android.net.VpnService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import me.proton.vpn.sdk.api.InitialConfig
import me.proton.vpn.sdk.api.InterfaceConfig
import me.proton.vpn.sdk.api.Logger
import me.proton.vpn.sdk.api.PcapFile
import me.proton.vpn.sdk.api.Peer
import me.proton.vpn.sdk.api.PeerConnection
import me.proton.vpn.sdk.api.VpnConnectionState
import me.proton.vpn.sdk.api.VpnDisconnectError
import me.proton.vpn.sdk.api.VpnProtocol
import me.proton.vpn.sdk.api.VpnWaitReason
import me.proton.vpn.sdk.internal.WallClockMs
import me.proton.vpn.sdk.service.usecases.EstablishTun
import me.proton.vpn.sdk.service.usecases.NetworkObserver
import uniffi.protun.Connection
import uniffi.protun.ConnectivityEvent
import uniffi.protun.DisconnectReason
import uniffi.protun.FileWriteMode
import uniffi.protun.InitialConnectionConfig
import uniffi.protun.LogLevel
import uniffi.protun.PcapFileInfo
import uniffi.protun.PeerConnectionInfo
import uniffi.protun.PeerInfo
import uniffi.protun.PrivateKeyUpdateInfo
import uniffi.protun.Protocol
import uniffi.protun.State
import uniffi.protun.StateChangedCallback
import uniffi.protun.WaitReason
import java.lang.ref.WeakReference
import java.net.InetSocketAddress
import java.util.Date
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

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
            connection.disconnect()
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
        socketProtectCallback: ProTunSocketProtectCallback
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
                        pcapFile = config.pcapFile?.toUniFFI(),
                    ),
                    tunFd = tunFd.detachFd(),
                    stateChangeCallback = stateChangeCallback,
                    socketFdAvailableCallback = socketProtectCallback,
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

    fun setPacketCaptureEnabled(pcapFile: PcapFile?) {
        if (pcapFile == null)
            activeConnection?.connection?.stopPacketCapture()
        else
            activeConnection?.connection?.startPacketCapture(pcapFile.toUniFFI())
    }

    fun onProTunStateChange(proTunState: State) {
        serviceScope.launch {
            val activeConnection = activeConnection
            if (activeConnection == null)
                state.value = VpnConnectionState.Disconnected()
            else {
                val newState = when (proTunState) {
                    is State.Disconnected -> VpnConnectionState.Disconnected(proTunState.error?.toVpnDisconnectReason())
                    is State.Connecting -> VpnConnectionState.Connecting(proTunState.peers.map { it.toPeerConnection() })
                    is State.WaitingForAction -> handleAction(proTunState.reason)
                    is State.Connected -> VpnConnectionState.Connected(
                        proTunState.peer.toPeerConnection(),
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

private fun PeerConnectionInfo.toPeerConnection(): PeerConnection =
    PeerConnection(
        protocol = protocol.toVpnProtocol(),
        id = peerId,
        entryAddr = InetSocketAddress(entryIp, port.toInt())
    )

private fun List<Peer>.toUniFFI(): List<PeerInfo> = map { peer ->
    PeerInfo(
        peerId = peer.id,
        serverIp = requireNotNull(peer.address.hostAddress),
        serverPublicKey = peer.publicKeyX25519Base64.decodeBase64(),
        tcpPorts = peer.ports[VpnProtocol.WireGuardTcp]?.map { it.toUShort() } ?: emptyList(),
        udpPorts = peer.ports[VpnProtocol.WireGuardUdp]?.map { it.toUShort() } ?: emptyList(),
        tlsPorts = peer.ports[VpnProtocol.Stealth]?.map { it.toUShort() } ?: emptyList(),
        priority = peer.priority,
    )
}

private fun PcapFile.toUniFFI(): PcapFileInfo = when (this) {
    is PcapFile.Fd -> PcapFileInfo.Fd(fd)
    is PcapFile.Path -> PcapFileInfo.Path(path.absolutePath, FileWriteMode.OVERWRITE)
}

private fun DisconnectReason.toVpnDisconnectReason(): VpnDisconnectError = when (this) {
    is DisconnectReason.TunEstablishError -> VpnDisconnectError.TunInterfaceError(message)
}

internal class ProTunStateChangedCallback(val weakManager: WeakReference<ConnectionManager>): StateChangedCallback {
    override fun onStateChanged(state: State) {
        weakManager.get()?.onProTunStateChange(state)
    }

    fun clear() {
        weakManager.clear()
    }
}

private fun Protocol.toVpnProtocol(): VpnProtocol = when (this) {
    Protocol.WIREGUARD_UDP -> VpnProtocol.WireGuardUdp
    Protocol.WIREGUARD_TCP -> VpnProtocol.WireGuardTcp
    Protocol.STEALTH -> VpnProtocol.Stealth
}

@OptIn(ExperimentalEncodingApi::class)
private fun String.decodeBase64(): ByteArray = Base64.decode(this)