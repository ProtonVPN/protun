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

import android.content.Context
import kotlinx.coroutines.MainScope
import me.proton.vpn.core.ProtonVpnConnectionManagerImpl
import me.proton.vpn.core.internal.DependencyContainer
import me.proton.vpn.core.internal.PersistentCacheStorage
import uniffi.protun.CacheKey
import uniffi.protun.LogLevel

/**
 * Central point for initialization and core APIs access. Client apps should maintain a single
 * instance of this class.
 *
 * Usage:
 * ```kotlin
 * // Initialization needs to happen in Application's onCreate.
 * val vpn = ProtonVpnCore.create(appContext = applicationContext) { vpn ->
 *     Dependencies(...)
 * }
 * // Access connection manager
 * val connectionManager = core.connectionManager
 * connectionManager.connect(initialConfig)
 * ...
 * ```
 */
interface ProtonVpnCore {
    val connectionManager: ProtonVpnConnectionManager

    /**
     * Clears persistent data cached for recent VPN session.
     * @param userId User ID to clear cache for.
     */
    suspend fun clearCache(userId: String)

    /**
     * Clears certificate from persistent cache for a given userId.
     */
    suspend fun clearCertificate(userId: String)

    companion object {

        /**
         * Create and initialize the ProtonVPN Core.
         * NOTE: this method needs to be called in Application's onCreate - otherwise VpnService
         *  launched automatically by the system will be missing required dependencies.
         *  Dependencies should be lightweight (e.g. via lazy) to avoid slowing-down app startup.
         *
         * @param context Application context
         * @param logger Logger implementation
         * @param persistentCacheCipher Optional cipher for storing auth secrets. If not provided,
         *    plaintext storage will be used.
         * @param includeNativeLogs Whether to include logs from the rust layer. Set it to false if
         *    you already handle rust `log::set_logger` in the app.
         * @param nativeLogLevel Minimum log level for native logs
         * @param initDependencies Function to provide dependencies (see [Dependencies])
         *    that need to be implemented by consumers. Makes [ProtonVpnCore] instance available for
         *    dependencies that need it.
         *
         * @return Initialized ProtonVpnCore instance
         */
        fun create(
            context: Context,
            logger: Logger,
            persistentCacheCipher: PersistentCacheCipher?,
            includeNativeLogs: Boolean = true,
            nativeLogLevel: LogLevel = LogLevel.INFO,
            initDependencies: (ProtonVpnCore) -> Dependencies,
        ): ProtonVpnCore {
            val appContext = context.applicationContext
            val mainScope = MainScope()

            val vpn = ProtonVpnCoreImpl(
                ProtonVpnConnectionManagerImpl(mainScope, appContext, logger)
            )

            val dependencies = initDependencies(vpn)

            // Initialize the dependency container for system-instantiated components
            DependencyContainer.initialize(
                context = appContext,
                logger = logger,
                notificationFactory = dependencies.notificationFactory,
                systemEventHandler = dependencies.systemEventHandler,
                nativeLogLevel = nativeLogLevel.takeIf { includeNativeLogs },
                cache = PersistentCacheStorage(persistentCacheCipher, logger, appContext),
            )

            return vpn
        }
    }
}

internal class ProtonVpnCoreImpl(
    override val connectionManager: ProtonVpnConnectionManager,
) : ProtonVpnCore {

    override suspend fun clearCache(userId: String) {
        DependencyContainer.cache.clearAll(userId)
    }

    override suspend fun clearCertificate(userId: String) {
        DependencyContainer.cache.remove(CacheKey.CERTIFICATE, userId)
    }
}

/**
 * Dependencies required by the library to operate within the host application.
 *
 * @param notificationFactory Factory for creating VPN notifications
 * @param systemEventHandler Handler for system events (e.g. connectivity changes)
 */
class Dependencies(
    val notificationFactory: ForegroundServiceNotificationFactory,
    val systemEventHandler: SystemEventHandler
)

/**
 * Interface for encrypting/decrypting cached auth secrets. Will be used on a background thread
 * where blocking IO is allowed.
 */
interface PersistentCacheCipher {
    fun encrypt(data: ByteArray): Result<ByteArray>
    fun decrypt(data: ByteArray): Result<ByteArray>
}