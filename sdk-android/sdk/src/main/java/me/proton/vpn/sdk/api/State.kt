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
import kotlinx.parcelize.Parcelize
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.util.Date

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
        val connections: List<PeerConnection>
    ): VpnConnectionState

    /**
     * Connection attempt requires app, user or system action to proceed.
     */
    data class WaitingForAction(
        val reason: VpnWaitReason
    ): VpnConnectionState

    data class Connected(
        val connection: PeerConnection,
        val connectedSince: Date
    ): VpnConnectionState
}

@Parcelize
sealed interface VpnWaitReason : Parcelable {

    /**
     * Device currently has no network (airplane mode, no signal, etc.)
     */
    object WaitingForNetwork : VpnWaitReason
}

@Parcelize
sealed interface VpnDisconnectError : Parcelable {

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
}

@Parcelize
data class PeerConnection(
    val protocol: VpnProtocol,
    val id: String,
    val entryAddr: InetSocketAddress,
): Parcelable