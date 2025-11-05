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
import java.net.SocketAddress
import java.util.Date

@Parcelize
sealed interface VpnConnectionState : Parcelable {

    // VPN state is being loaded (VPN service might be running and connected but this information
    // is being collected)
    data object Loading: VpnConnectionState

    data object Disconnected: VpnConnectionState

    // Waiting for connectivity in underlying network.
    data object WaitingForNetwork: VpnConnectionState

    data class Connecting(
        val connections: List<PeerConnection>
    ): VpnConnectionState

    data class Connected(
        val connection: PeerConnection,
        val connectedSince: Date
    ): VpnConnectionState

    data class Error(
        val kind: VpnErrorKind,
        val message: String?,

        // true if this is a final error that SDK won't be able to recover from on its own.
        // when false, SDK will keep trying to find reachable peer and reconnect.
        val isFinal: Boolean,
    ): VpnConnectionState
}

enum class VpnErrorKind {

    // System failure establishing VPN connection involving multiple user profiles (or Dual Messenger).
    // On some Android devices setting up split tunneling can cause this error in multi-user scenarios.
    InteractAcrossUsersError,

    // Library can't establish/maintain connection to any of the peers due to either poor network
    // conditions or active blocking.
    PeersUnreachable,

    // Android's VpnService error. See message for details.
    ServiceError,

    // TUN interface couldn't be established or fails when reading/writing packets.
    TunInterfaceError,

    // VPN permission was not granted by the user. Make sure to request VPN permission before
    // attempting to connect.
    VpnPermissionError,
}

@Parcelize
data class PeerConnection(
    val protocol: VpnProtocol,
    val id: String,
    val entryAddr: SocketAddress,
): Parcelable