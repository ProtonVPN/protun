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

import android.app.Notification
import android.content.Context

/**
 * Factory for creating client-defined foreground service notifications required when launching
 * VpnService.
 * https://developer.android.com/reference/android/app/Service#startForeground(int,%20android.app.Notification)
 */
interface ForegroundServiceNotificationFactory {
    val notificationId: Int
    fun buildNotification(context: Context, state: VpnConnectionState): Notification
}