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
import java.net.InetAddress

private const val DEFAULT_MTU = 1460
private val FULL_RANGE_IPV4 = IpNetworkPrefix(InetAddress.getByName("0.0.0.0"), 0)
private val FULL_RANGE_IPV6 = IpNetworkPrefix(InetAddress.getByName("::"), 0)

/**
 * Configuration of the TUN interface.
 */
@Parcelize
data class InterfaceConfig(

    /**
     * Should IPv6 traffic be routed through the VPN tunnel.
     */
    val supportInTunnelIPv6: Boolean,

    /**
     * List of custom DNS servers to be used while VPN is active. When empty (default), ProtonVPN
     * own DNS service will be used.
     * Note: features like NetShield provided by ProtonVPN DNS won't be supported when custom DNS
     * servers are set.
     */
    val customDns: List<String> = emptyList(),

    /**
     * List of IP ranges that should be routed through the VPN tunnel. Rest of the traffic
     * will go outside the tunnel, or when system's Kill Switch is enabled, be blocked.
     */
    val routes: List<IpNetworkPrefix> = defaultRoutes(supportInTunnelIPv6),

    /**
     * Split tunneling configuration for apps, either in include or exclude mode. When null
     * (default) all apps traffic (consistent with [routes]) will be go through the VPN tunnel.
     */
    val splitTunnelAppsConfig: SplitTunnelAppsConfig? = null,

    /**
     * MTU value for the TUN interface.
     */
    val mtu: Int = DEFAULT_MTU,
): Parcelable {

    companion object {

        /**
         * Full IPv4 range and optional full IPv6 range.
         */
        fun defaultRoutes(supportInTunnelIPv6: Boolean) = buildList {
            add(FULL_RANGE_IPV4)
            if (supportInTunnelIPv6)
                add(FULL_RANGE_IPV6)
        }
    }
}

/**
 * Custom class for defining network ranges via prefix. Android's own IpPrefix is available from
 * API 33.
 */
@Parcelize
data class IpNetworkPrefix(val address: InetAddress, val prefixLength: Int): Parcelable

enum class SplitTunnelMode {
    Include,
    Exclude
}

@Parcelize
data class SplitTunnelAppsConfig(val mode: SplitTunnelMode, val apps: List<String>): Parcelable