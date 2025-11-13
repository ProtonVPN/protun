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

package me.proton.vpn.sdk.sample_app

import me.proton.vpn.sdk.sample_app.data.ConfigStore
import me.proton.vpn.sdk.sample_app.di.VpnLogger
import me.proton.vpn.sdk.api.ProtonVpnConnectionManager
import me.proton.vpn.sdk.api.SystemEventHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import uniffi.protun.LogLevel
import javax.inject.Inject

class AppSystemEventHandler(
    private val mainScope: CoroutineScope,
    private val connectionManager: ProtonVpnConnectionManager,
    private val configStore: ConfigStore,
    private val logger: VpnLogger
): SystemEventHandler {

    override fun onProcessRestored() {
        // TODO: handle process restore here - if connection is supposed to be restarted, use
        //  sdk to re-connect.
    }

    override fun onAlwaysOnEnabled() {
        mainScope.launch {
            val lastSuccessfulConfig = configStore.data.first()
            if (lastSuccessfulConfig != null) {
                connectionManager.connect(lastSuccessfulConfig.toInitialConfig())
            } else {
                logger.log(LogLevel.ERROR, "No last successful config found to connect for always-on VPN")
            }
        }
    }
}
