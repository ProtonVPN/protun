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

package me.proton.vpn.sdk.service.usecases

import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import me.proton.vpn.sdk.api.InterfaceConfig
import me.proton.vpn.sdk.api.IpNetworkPrefix
import me.proton.vpn.sdk.api.SplitTunnelAppsConfig
import me.proton.vpn.sdk.api.SplitTunnelMode
import me.proton.vpn.sdk.api.VpnConnectionState
import me.proton.vpn.sdk.api.VpnErrorKind

private const val TUNNEL_CLIENT_IP_V4 = "10.2.0.2"
private const val TUNNEL_SERVER_IP_V4 = "10.2.0.1"

private const val TUNNEL_CLIENT_IP_V6 = "2a07:b944::2:2"
private const val TUNNEL_SERVER_IP_V6 = "2a07:b944::2:1"

private const val TUNNEL_PROTON_DNS_IP_V4 = TUNNEL_SERVER_IP_V4
private const val TUNNEL_PROTON_DNS_IP_V6 = TUNNEL_SERVER_IP_V6

internal fun interface EstablishTun {

    sealed interface Result {
        data class Success(val fd: ParcelFileDescriptor) : Result
        data class Failure(val errorState: VpnConnectionState.Error) : Result
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
            .setupRoutes(config.routes)
            .setupApps(config.splitTunnelAppsConfig)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
            builder.setMetered(false)

        fun failure(kind: VpnErrorKind, message: String?) =
            EstablishTun.Result.Failure(VpnConnectionState.Error(kind, message, isFinal = true))

        return try {
            val fd = builder.establish()
            if (fd == null)
                EstablishTun.Result.Failure(
                    VpnConnectionState.Error(VpnErrorKind.VpnPermissionError, "Missing VPN permission", isFinal = true)
                )
            else
                EstablishTun.Result.Success(fd)
        } catch (e: SecurityException) {
            val (kind, message) = if (e.message?.contains("INTERACT_ACROSS_USERS") == true)
                VpnErrorKind.InteractAcrossUsersError to "VPN service conflict in multi-user system. Try disabling split tunneling."
            else
                VpnErrorKind.TunInterfaceError to e.message
            failure(kind, message)
        } catch (e: IllegalArgumentException) {
            failure(VpnErrorKind.TunInterfaceError, e.message)
        } catch (e: IllegalStateException) {
            failure(VpnErrorKind.TunInterfaceError, e.message)
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

    fun VpnService.Builder.setupRoutes(routes: List<IpNetworkPrefix>) = apply {
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
