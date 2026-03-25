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

package me.proton.vpn.core.service.usecases

import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import me.proton.vpn.core.api.InterfaceConfig
import me.proton.vpn.core.api.IpNetworkPrefix
import me.proton.vpn.core.api.SplitTunnelAppsConfig
import me.proton.vpn.core.api.SplitTunnelMode
import me.proton.vpn.core.api.VpnDisconnectError

private const val TUNNEL_CLIENT_IP_V4 = "10.2.0.2"
private const val TUNNEL_SERVER_IP_V4 = "10.2.0.1"

private const val TUNNEL_CLIENT_IP_V6 = "2a07:b944::2:2"
private const val TUNNEL_SERVER_IP_V6 = "2a07:b944::2:1"

private const val TUNNEL_PROTON_DNS_IP_V4 = TUNNEL_SERVER_IP_V4
private const val TUNNEL_PROTON_DNS_IP_V6 = TUNNEL_SERVER_IP_V6

internal fun interface EstablishTun {

    sealed interface Result {
        data class Success(val fd: ParcelFileDescriptor) : Result
        data class Failure(val reason: VpnDisconnectError) : Result
    }

    operator fun invoke(
        config: InterfaceConfig,
        builder: VpnService.Builder
    ): Result
}

internal class EstablishTunImpl : EstablishTun {

    override operator fun invoke(
        config: InterfaceConfig,
        builder: VpnService.Builder
    ): EstablishTun.Result {
        val supportIPv6 = config.supportInTunnelIPv6
        builder
            .setSession("protun0")
            .setUnderlyingNetworks(null)
            .setMtu(config.mtu)
            .setupAddresses(supportIPv6)
            .setupDns(supportIPv6, config.customDns)
            .setupRoutes(supportIPv6, config.routes)
            .setupApps(config.splitTunnelAppsConfig)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            builder.setMetered(false)

        fun tunFailure(reason: String?) =
            EstablishTun.Result.Failure(VpnDisconnectError.TunInterfaceError(reason))
        return try {
            val fd = builder.establish()
            if (fd == null)
                EstablishTun.Result.Failure(VpnDisconnectError.VpnPermissionMissing)
            else
                EstablishTun.Result.Success(fd)
        } catch (e: SecurityException) {
            EstablishTun.Result.Failure(
                if (e.message?.contains("INTERACT_ACROSS_USERS") == true)
                    VpnDisconnectError.InteractAcrossUsers
                else
                    VpnDisconnectError.TunInterfaceError(e.localizedMessage)
            )
        } catch (e: IllegalArgumentException) {
            tunFailure(e.localizedMessage)
        } catch (e: IllegalStateException) {
            tunFailure(e.localizedMessage)
        }
    }

    fun VpnService.Builder.setupAddresses(supportIPv6: Boolean) = apply {
        addAddress(TUNNEL_CLIENT_IP_V4, 32)
        if (supportIPv6)
            addAddress(TUNNEL_CLIENT_IP_V6, 128)
    }

    fun VpnService.Builder.setupDns(
        supportIPv6: Boolean,
        customDns: List<String>
    ) = apply {
        customDns.forEach { addDnsServer(it) }
        addDnsServer(TUNNEL_PROTON_DNS_IP_V4)
        if (supportIPv6)
            addDnsServer(TUNNEL_PROTON_DNS_IP_V6)
    }

    fun VpnService.Builder.setupRoutes(supportIPv6: Boolean, routes: List<IpNetworkPrefix>) = apply {
        addRoute(TUNNEL_SERVER_IP_V4, 32)
        if (supportIPv6)
            addRoute(TUNNEL_SERVER_IP_V6, 128)
        routes.forEach { route ->
            addRoute(route.address, route.prefixLength)
        }
    }

    fun VpnService.Builder.setupApps(
        config: SplitTunnelAppsConfig?
    ) = apply {
        when (config?.mode) {
            SplitTunnelMode.Include ->
                config.apps.forEach { packageName -> addAllowedApplication(packageName) }
            SplitTunnelMode.Exclude ->
                config.apps.forEach { packageName -> addDisallowedApplication(packageName) }
            null -> {}
        }
    }
}
