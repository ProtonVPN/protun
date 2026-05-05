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

package me.proton.vpn.core.sample_app.di

import android.content.Context
import android.util.Log
import me.proton.vpn.core.sample_app.AppSystemEventHandler
import me.proton.vpn.core.sample_app.VpnNotificationFactory
import me.proton.vpn.core.sample_app.data.ConfigStore
import me.proton.vpn.core.api.Logger
import me.proton.vpn.core.api.ProtonVpnCore
import me.proton.vpn.core.api.Dependencies
import dagger.Module
import dagger.Provides
import dagger.Reusable
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.MainScope
import uniffi.protun.LogLevel
import javax.inject.Inject
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideMainScope(): CoroutineScope = MainScope()

    @Provides
    @Singleton
    fun provideCore(
        @ApplicationContext appContext: Context,
        mainScope: CoroutineScope,
        configStore: ConfigStore,
        logger: VpnLogger,
    ): ProtonVpnCore = ProtonVpnCore.create(appContext, logger, persistentCacheCipher = null) { vpn ->
        Dependencies(
            notificationFactory =
                VpnNotificationFactory(appContext, mainScope, vpn.connectionManager),
            systemEventHandler =
                AppSystemEventHandler(mainScope, vpn.connectionManager, configStore, logger),
        )
    }

    @Provides
    fun connectionManager(vpn: ProtonVpnCore) = vpn.connectionManager
}

@Reusable
class VpnLogger @Inject constructor() : Logger {
    override fun log(level: LogLevel, message: String) {
        when (level) {
            LogLevel.DEBUG -> Log.d("VpnLogger", message)
            LogLevel.INFO -> Log.i("VpnLogger", message)
            LogLevel.WARN -> Log.w("VpnLogger", message)
            LogLevel.ERROR -> Log.e("VpnLogger", message)
            LogLevel.TRACE -> Log.d("VpnLogger", message)
        }
    }
}