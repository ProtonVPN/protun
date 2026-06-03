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

package me.proton.vpn.core.api

import android.os.Parcelable
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.parcelize.Parcelize
import java.io.File
import java.time.Duration

/**
 * ProtonVPN connection manager. Provides methods to establish, manage and track VPN connection to
 * ProtonVPN servers.
 *
 * Instance of this interface can be obtained from [ProtonVpnCore].
 *
 * Usage:
 * '''kotlin
 *   // Observe VPN state changes in kotlin
 *   vpnManager.state.onEach { state -> handleState(state) }.launchIn(coroutineScope)
 *
 *   // Observe VPN events (e.g. connection stats, packet capture start/stop) in kotlin
 *   vpnManager.events.onEach { event -> handleEvent(event) }.launchIn(coroutineScope)
 *
 *   // or with Java-friendly listener
 *   manager.registerStateListener (state -> { ... });
 *   manager.registerEventListener (event -> { ... });
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

    val state: StateFlow<VpnState>
    val events: Flow<VpnConnectionEvent>
    val connectionStats: Flow<ConnectionStats>

    /**
     * Stream of local-agent stats. Active only while a [ConnectionMode.LocalAgent] connection is
     * established; emits roughly once per second.
     */
    val localAgentStats: Flow<LocalAgentStats>

    fun connect(config: InitialConfig)
    fun updateInterfaceConfig(interfaceConfig: InterfaceConfig)
    fun updateLocalAgentSettings(localAgentSettings: LocalAgentSettings)
    fun updateApiSelector(selector: String)
    fun updatePeers(peers: List<Peer>)

    /**
     * Enable or disable packet capture of VPN traffic. When enabled, VPN traffic will be logged
     * to the file specified in [packetCaptureInfo]. Only to be used for debugging purposes. To stop
     * capturing, call this method with `null`.
     */
    fun setPacketCaptureEnabled(packetCaptureInfo: PacketCaptureInfo?)

    fun disconnect(error: VpnDisconnectError? = null)
}

@Parcelize
data class InitialConfig(

    /**
     * TUN interface configuration specifying routes, split tunneling, DNS servers, etc.
     */
    val interfaceConfig: InterfaceConfig,

    /**
     * List of available peers to connect to. Connection manager will select best configuration
     * (IP, protocol, ports) based on peer priority and reachability in current network conditions.
     */
    val peers: List<Peer>,

    /**
     * If not null, VPN traffic will be logged to the specified PCAP file. Only to be used for
     * debugging purposes (file will contain unencrypted VPN traffic and affect performance).
     * @see also [ProtonVpnConnectionManager.setPacketCaptureEnabled] for enabling/disabling PCAP
     * capture dynamically.
     */
    val packetCaptureInfo: PacketCaptureInfo? = null,

    val mode: ConnectionMode,
): Parcelable

@Parcelize
sealed interface ConnectionMode: Parcelable {

    data class NoLocalAgent(
        val clientX25519PrivateKeyBase64: String,
    ) : ConnectionMode

    data class LocalAgent(
        val userAgent: String,
        val appVersion: String,
        val settings: LocalAgentSettings,
    ) : ConnectionMode
}

/**
 * Information about packet capture (pcap) file for debugging.
 */
@Parcelize
data class PacketCaptureInfo(val file: PacketCaptureFile, val maxBytes: ULong?) : Parcelable
sealed interface PacketCaptureFile : Parcelable {

    @Parcelize data class Fd(val fd: Int) : PacketCaptureFile
    @Parcelize data class Path(val path: File, val append: Boolean) : PacketCaptureFile
}

/**
 * Current connection stats. Will be emitted in [ProtonVpnConnectionManager.connectionStats].
 */
@Parcelize
data class ConnectionStats(
    val timestampMs: Long, //ms since epoch
    val receivedBytes: ULong,
    val sentBytes: ULong,
    val timeSinceLastHandshake: Duration,
    val estimatedLoss: Float,
    val estimatedRoundTripTime: Duration
) : Parcelable

/**
 * Local-agent settings. Used with [ConnectionMode.LocalAgent.settings] and
 * [ProtonVpnConnectionManager.updateLocalAgentSettings] to set values (null means "use default").
 * When returned in connection state (see [AgentConnectionInfo.settings]) it carries settings as
 * applied by the server (null means "no value provided" in that case).
 */
@Parcelize
data class LocalAgentSettings(
    val splitTcp: Boolean?,
    val netshieldLevel: NetShieldLevel?,
    val softJail: Boolean?,
    val portForwarding: Boolean?,
    val randomNat: Boolean?,
    val circumventionRouting: Boolean?,
) : Parcelable

enum class NetShieldLevel {
    None, MalwareFilter, AdsAndMalwareFilter, AdultAndAdsAndMalwareFilter
}

/**
 * Local-agent traffic / NetShield stats. Will be emitted in
 * [ProtonVpnConnectionManager.localAgentStats] roughly once per second while a local-agent
 * connection is established. Fields are independently nullable: a null value means the server
 * did not report that counter for the current snapshot.
 */
@Parcelize
data class LocalAgentStats(
    val bytesReceived: ULong?,
    val bytesSent: ULong?,
    val maliciousBlocked: ULong?,
    val adsBlocked: ULong?,
    val trackersBlocked: ULong?,
    val adultContentBlocked: ULong?,
    /** Estimated bandwidth saved by NetShield blocks, in bytes. */
    val dataSaved: ULong?,
) : Parcelable
