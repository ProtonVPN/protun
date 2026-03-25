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

package me.proton.vpn.core.sample_app.data

import me.proton.vpn.core.api.InitialConfig
import me.proton.vpn.core.api.InterfaceConfig
import me.proton.vpn.core.api.Peer
import me.proton.vpn.core.api.VpnProtocol
import kotlinx.serialization.Serializable
import java.net.InetAddress

@Serializable
data class VpnConfig(
    val ip: String,
    val udpPorts: List<Int> = emptyList(),
    val tcpPorts: List<Int> = emptyList(),
    val tlsPorts: List<Int> = emptyList(),
    val peerPublicKey: String,
    val clientPrivateKey: String,
) {
    fun toInitialConfig(): InitialConfig {
        val ports = mapOf(
            VpnProtocol.WireGuardUdp to udpPorts,
            VpnProtocol.WireGuardTcp to tcpPorts,
            VpnProtocol.Stealth to tlsPorts
        )
        if (ports.values.all { it.isEmpty() })
            throw IllegalArgumentException("At least one port must be specified")

        val address = try {
            InetAddress.getByName(ip)
        } catch (e: Exception) {
            throw IllegalArgumentException("Invalid peer address $ip:", e)
        }

        return InitialConfig(
            interfaceConfig = InterfaceConfig(supportInTunnelIPv6 = false),
            clientED25519PrivateKeyBase64 = clientPrivateKey,
            peers = listOf(
                Peer(
                    id = "0",
                    address = address,
                    publicKeyX25519Base64 = peerPublicKey,
                    priority = 0,
                    ports = ports,
                )
            ),
        )
    }
}