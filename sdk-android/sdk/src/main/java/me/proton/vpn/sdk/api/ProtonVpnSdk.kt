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

import android.content.Context
import kotlinx.coroutines.MainScope
import me.proton.vpn.sdk.ProtonVpnConnectionManagerImpl
import me.proton.vpn.sdk.internal.DependencyContainer
import uniffi.protun.ClientLogger
import uniffi.protun.LogLevel
import uniffi.protun.initLogger

/**
 * Central point for SDK initialization and APIs access. Client apps should maintain a single
 * instance of this class.
 *
 * Usage:
 * ```kotlin
 * // Initialize the SDK. Needs to happen in Application's onCreate.
 * val sdk = ProtonVpnSdk.create(appContext = applicationContext) { sdk ->
 *     SdkDependencies(...)
 * }
 * // Access connection manager
 * val connectionManager = sdk.connectionManager
 * connectionManager.connect(initialConfig)
 * ...
 * ```
 */
class ProtonVpnSdk private constructor(
    val connectionManager: ProtonVpnConnectionManager,
) {
    companion object {

        /**
         * Create and initialize the ProtonVPN SDK.
         * NOTE: this method needs to be called in Application's onCreate - otherwise VpnService
         *  launched automatically by the system will be missing required dependencies.
         *  SDK-dependencies should be lightweight (e.g. via lazy) to avoid slowing-down app startup.
         *
         * @param context Application context
         * @param logger Logger implementation
         * @param includeNativeLogs Whether to include logs from the rust layer. Set it to false if
         *    you already handle rust `log::set_logger` in the app.
         * @param nativeLogLevel Minimum log level for native logs
         * @param initDependencies Function to provide SDK dependencies (see [SdkDependencies])
         *    that need to be implemented by consumers. Makes [ProtonVpnSdk] instance available for
         *    dependencies that need it.
         *
         * @return Initialized ProtonVpnSdk instance
         */
        fun create(
            context: Context,
            logger: Logger,
            includeNativeLogs: Boolean = true,
            nativeLogLevel: LogLevel = LogLevel.INFO,
            initDependencies: (ProtonVpnSdk) -> SdkDependencies,
        ): ProtonVpnSdk {
            val appContext = context.applicationContext
            val mainScope = MainScope()

            val sdk = ProtonVpnSdk(
                ProtonVpnConnectionManagerImpl(mainScope, appContext, logger)
            )

            val dependencies = initDependencies(sdk)

            // Initialize the dependency container for system-instantiated components
            DependencyContainer.initialize(
                context = appContext,
                logger = logger,
                notificationFactory = dependencies.notificationFactory,
                systemEventHandler = dependencies.systemEventHandler,
                nativeLogLevel = nativeLogLevel.takeIf { includeNativeLogs },
            )

            return sdk
        }
    }
}

/**
 * Dependencies required by the SDK to operate within the host application.
 *
 * @param notificationFactory Factory for creating VPN notifications
 * @param systemEventHandler Handler for system events (e.g. connectivity changes)
 */
class SdkDependencies(
    val notificationFactory: ForegroundServiceNotificationFactory,
    val systemEventHandler: SystemEventHandler
)
