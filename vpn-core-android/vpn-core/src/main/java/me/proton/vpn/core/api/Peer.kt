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
import java.net.InetAddress

/**
 * VPN peer (server) to connect to.
 */
@Parcelize
data class Peer(

    /**
     * IP address of the peer.
     */
    val address: InetAddress,

    /**
     * Allowed VPN protocols and their respective ports to be used for connection.
     */
    val ports: Map<VpnProtocol, List<Int>>,

    /**
     * 32 bytes base64-encoded X25519 public key of the peer.
     */
    val publicKeyX25519Base64: String,

    /**
     * Lower value means higher priority.
     */
    val priority: Int,

    /**
     * Client-defined identifier for the peer.
     */
    val id: String,
): Parcelable

@Parcelize
enum class VpnProtocol : Parcelable {

    /**
     * Regular WireGuard appropriate for most networks.
     */
    WireGuardUdp,

    /**
     * Protocols designed to work in restricted networks, slower and less reliable in
     * normal conditions.
     */
    WireGuardTcp,
    Stealth
}