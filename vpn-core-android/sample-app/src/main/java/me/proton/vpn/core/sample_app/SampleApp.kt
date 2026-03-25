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

package me.proton.vpn.core.sample_app

import android.app.Application
import dagger.hilt.android.HiltAndroidApp
import me.proton.vpn.core.api.ProtonVpnCore
import javax.inject.Inject

@HiltAndroidApp
class SampleApp : Application() {

    // Trigger vpn-core initialization during onCreate
    @Inject lateinit var vpn: ProtonVpnCore

    override fun onCreate() {
        super.onCreate()
        initializeNotificationChannel()
    }
}