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

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.content.getSystemService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import me.proton.vpn.core.api.ForegroundServiceNotificationFactory
import me.proton.vpn.core.api.ProtonVpnConnectionManager
import me.proton.vpn.core.api.VpnConnectionState

private const val VPN_STATE_NOTIFICATION_ID = 10
private const val CHANNEL_ID = "me.proton.vpn.core.sample_app.vpn_connection"

class VpnNotificationFactory(
    private val appContext: Context,
    mainScope: CoroutineScope,
    connectionManager: ProtonVpnConnectionManager,
): ForegroundServiceNotificationFactory {

    private val notificationManager = appContext.getSystemService<NotificationManager>()

    init {
        connectionManager.state.onEach { state ->
            if (state != VpnConnectionState.Loading && !(state is VpnConnectionState.Disconnected && state.error == null)) {
                val notification = buildNotification(appContext, state)
                notificationManager?.notify(VPN_STATE_NOTIFICATION_ID, notification)
            }
        }.launchIn(mainScope)
    }

    override val notificationId: Int get() = VPN_STATE_NOTIFICATION_ID

    override fun buildNotification(context: Context, state: VpnConnectionState): Notification {
        return NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle("ProtonVPN sample app")
            .setContentText(state.javaClass.simpleName)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }
}

fun Context.initializeNotificationChannel() {
    val channelName = "VPN connection status"
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
        val notificationChannel = NotificationChannel(
            CHANNEL_ID,
            channelName,
            NotificationManager.IMPORTANCE_LOW
        )
        notificationChannel.setShowBadge(false)
        val manager = getSystemService<NotificationManager>()
        manager?.createNotificationChannel(notificationChannel)
    }
}