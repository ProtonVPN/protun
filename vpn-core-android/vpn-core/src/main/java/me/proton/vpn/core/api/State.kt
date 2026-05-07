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
import kotlinx.parcelize.Parcelize
import java.net.InetSocketAddress
import java.util.Date

@Parcelize
data class VpnState(
    val interfaceUp: Boolean,
    val connectionState: VpnConnectionState,
) : Parcelable {
    companion object {

        fun disconnectedWith(error: VpnDisconnectError) = VpnState(
            interfaceUp = false,
            connectionState = VpnConnectionState.Disconnected(error)
        )

        val Disconnected = VpnState(interfaceUp = false, VpnConnectionState.Disconnected())
    }
}

@Parcelize
sealed interface VpnConnectionState : Parcelable {

    /**
     * VPN state is being loaded (VPN service might be running and connected but this information
     * is being collected)
     */
    data object Loading: VpnConnectionState

    data class Disconnected(
        /** != null if the disconnection was due to an error */
        val error: VpnDisconnectError? = null
    ): VpnConnectionState

    data class Connecting(
        val connections: List<PeerConnection>,
        val waitReasons: List<PeerConnectionWaitReason>,
    ): VpnConnectionState

    data class ConnectingToLocalAgent(
        val connection: PeerConnection,
        val waitReason: AgentConnectionWaitReason?,
    ): VpnConnectionState

    data class Connected(
        val connection: PeerConnection,
        val connectedSince: Date,
        val agentConnectionInfo: AgentConnectionInfo?
    ): VpnConnectionState
}

@Parcelize
sealed interface PeerConnectionWaitReason : Parcelable {

    /**
     * Device currently has no network (airplane mode, no signal, etc.)
     */
    data object WaitingForNetwork : PeerConnectionWaitReason
}

@Parcelize
sealed interface AgentConnectionWaitReason : Parcelable {
    data object SoftJailed : AgentConnectionWaitReason
    data class HardJailed(val jails: List<WaitJailReason>) : AgentConnectionWaitReason
}

@Parcelize
sealed interface VpnDisconnectError : Parcelable {

    /**
     * VPN service was revoked. Either by removing VPN in the settings or by starting another VPN app.
     */
    data object ServiceRevoked : VpnDisconnectError

    /**
     * System failure establishing VPN connection involving multiple user profiles (or Dual Messenger).
     * On some Android devices setting up split tunneling can cause this error in multi-user scenarios.
     */
    data object InteractAcrossUsers: VpnDisconnectError

    /**
     * Android's VpnService error. See message for details.
     */
    data class ServiceError(val message: String): VpnDisconnectError

    /**
     * TUN interface couldn't be established or fails when reading/writing packets.
     */
    data class TunInterfaceError(val message: String?): VpnDisconnectError

    /**
     * VPN permission was not granted by the user. Make sure to request VPN permission before
     * attempting to connect.
     */
    data object VpnPermissionMissing: VpnDisconnectError

    /**
     * Custom error that the client app can set on disconnect.
     */
    data class AppError(val e: Throwable): VpnDisconnectError
}

/**
 * Local agent jails. Require app/user action to be unjailed ([WaitJailReason.Internal] will
 * be handled internally by the library). Messages are not localized and suitable only for
 * logging/debugging.
 */
@Parcelize
sealed interface WaitJailReason : Parcelable {
    data class Need2FA(val message: String) : WaitJailReason
    data class BadUserBehavior(val message: String) : WaitJailReason
    data class DisabledUser(val message: String) : WaitJailReason
    data class WaitingClientChallengeReply(val message: String) : WaitJailReason
    data class LowPlan(val message: String) : WaitJailReason
    data class PendingInvoice(val message: String) : WaitJailReason
    data class SessionOverLimit(val message: String) : WaitJailReason

    // Will be handled internally by the library - no action required by the app.
    data class Internal(val message: String) : WaitJailReason

    // Unknown error codes, not supported in this version.
    data class Other(val code: ULong, val message: String) : WaitJailReason
}

@Parcelize
data class PeerConnection(
    val protocol: VpnProtocol,
    val id: String,
    val entryAddr: InetSocketAddress,
): Parcelable

/**
 * Information available after establishing a connection to the local agent. null field values
 * indicate that the server didn't provide the value at the moment.
 */
@Parcelize
data class AgentConnectionInfo(
    val serverExitV4: String?,
    val serverExitV6: String?,
    val userIspIP: String?,
    val userIspCountryCode: String?,
    val userIspName: String?,
    val userIspCoordinates: LocationCoordinates?,
    val settings: LocalAgentSettings, // Actual settings applied by the server.
    val restrictions: List<Restriction>,
) : Parcelable

@Parcelize
data class LocationCoordinates(
    val latitude: Double,
    val longitude: Double,
) : Parcelable

@Parcelize
sealed interface Restriction : Parcelable {
    data class Streaming(val reason: String) : Restriction
    data class Torrent(val reason: String) : Restriction
    data class Other(val reason: String) : Restriction
}