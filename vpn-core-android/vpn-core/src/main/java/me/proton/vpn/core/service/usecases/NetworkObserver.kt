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

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import androidx.core.content.getSystemService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

internal interface NetworkObserver {
    val validatedNetworks: StateFlow<Set<Network>>
}

internal class NetworkObserverImpl(
    appContext: Context,
) : NetworkObserver {

    private val connectivityManager = appContext.getSystemService<ConnectivityManager>()

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {

        override fun onAvailable(network: Network) {
            val capabilities = connectivityManager?.getNetworkCapabilities(network)
            updateNetwork(network, capabilities)
            super.onAvailable(network)
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            updateNetwork(network, capabilities)
            super.onCapabilitiesChanged(network, capabilities)
        }

        override fun onLost(network: Network) {
            validatedNetworks.value -= network
            super.onLost(network)
        }
    }

    init {
        if (connectivityManager == null)
            error("ConnectivityManager is not available.")

        connectivityManager.registerNetworkCallback(NetworkRequest.Builder().build(), networkCallback)
    }

    override val validatedNetworks = MutableStateFlow<Set<Network>>(emptySet())

    private fun updateNetwork(network: Network, capabilities: NetworkCapabilities?) {
        val validatedNetwork =
            capabilities != null &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        if (validatedNetwork)
            validatedNetworks.value += network
        else
            validatedNetworks.value -= network
    }
}
