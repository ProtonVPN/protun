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

package me.proton.vpn.sdk.internal

import android.annotation.SuppressLint
import android.content.Context
import androidx.annotation.VisibleForTesting
import me.proton.vpn.sdk.api.ForegroundServiceNotificationFactory
import me.proton.vpn.sdk.api.Logger
import me.proton.vpn.sdk.api.SystemEventHandler
import me.proton.vpn.sdk.service.ConnectionManager
import me.proton.vpn.sdk.service.usecases.EstablishTun
import me.proton.vpn.sdk.service.usecases.EstablishTunImpl
import me.proton.vpn.sdk.service.usecases.NetworkObserver
import me.proton.vpn.sdk.service.usecases.NetworkObserverImpl
import uniffi.protun.ClientLogger
import uniffi.protun.LogLevel
import uniffi.protun.initLogger

fun interface WallClockMs {
    operator fun invoke(): Long
}

/**
 * Simple internal dependency container for the SDK to avoid introducing dependency on DI frameworks.
 * Needed to provide dependencies to system-instantiated components like ProTunVpnService.
 */
internal object DependencyContainer {

    private var _logger: Logger? = null
    private var _notificationFactory: ForegroundServiceNotificationFactory? = null
    private var _systemEventHandler: SystemEventHandler? = null
    @SuppressLint("StaticFieldLeak")
    private var _appContext: Context? = null
    private var _wallClockMs: WallClockMs? = null
    private var _nativeLogLevel: LogLevel? = null

    // Use lazy field to get synchronized initialization of native logger.
    private val nativeLogger by lazy {
        _nativeLogLevel?.let { nativeLogLevel ->
            initLogger(nativeLogLevel, object : ClientLogger {
                override fun log(level: LogLevel, message: String) {
                    logger.log(level, message)
                }
            })
        }
    }

    fun initialize(
        context: Context,
        logger: Logger,
        notificationFactory: ForegroundServiceNotificationFactory,
        systemEventHandler: SystemEventHandler,
        wallClockMs: WallClockMs = WallClockMs { System.currentTimeMillis() },
        nativeLogLevel: LogLevel?
    ) {
        _appContext = context.applicationContext
        _logger = logger
        _notificationFactory = notificationFactory
        _systemEventHandler = systemEventHandler
        _wallClockMs = wallClockMs
        _nativeLogLevel = nativeLogLevel
    }

    fun ensureNativeLogInitialized() {
        // Access lazy field to make sure it's initialized.
        nativeLogger
    }

    val isInitialized get() = _appContext != null

    // Method to clear the dependencies to be used for test cleanup.
    @VisibleForTesting
    fun clear() {
        _appContext = null
        _logger = null
        _notificationFactory = null
        _systemEventHandler = null
        _wallClockMs = null
    }

    // Lazy-initialized internal dependencies
    private val networkObserver: NetworkObserver by lazy {
        NetworkObserverImpl(appContext)
    }

    private val establishTun: EstablishTun by lazy {
        EstablishTunImpl()
    }

    val connectionManager: ConnectionManager by lazy {
        ConnectionManager(
            networkObserver = networkObserver,
            establishTun = establishTun,
            wallClockMs = wallClockMs,
            logger = logger
        )
    }

    val appContext: Context get() =
        _appContext ?: error("DependencyContainer not initialized. Call ProtonVpnSdk.create() first.")

    val logger: Logger get() =
        _logger ?: error("DependencyContainer not initialized. Call ProtonVpnSdk.create() first.")

    val notificationFactory: ForegroundServiceNotificationFactory get() =
        _notificationFactory ?: error("DependencyContainer not initialized. Call ProtonVpnSdk.create() first.")

    val eventHandler: SystemEventHandler get() =
        _systemEventHandler ?: error("DependencyContainer not initialized. Call ProtonVpnSdk.create() first.")

    val wallClockMs: WallClockMs get() =
        _wallClockMs ?: error("DependencyContainer not initialized. Call ProtonVpnSdk.create() first.")
}

