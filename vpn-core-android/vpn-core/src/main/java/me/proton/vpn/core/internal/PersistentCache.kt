/*
 * Copyright (c) 2026 Proton AG
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

package me.proton.vpn.core.internal

import android.content.Context
import android.util.Base64
import androidx.core.content.edit
import me.proton.vpn.core.api.Logger
import me.proton.vpn.core.api.PersistentCacheCipher
import uniffi.protun.CacheKey
import uniffi.protun.LogLevel
import uniffi.protun.PersistentCache

// This class will be used from background threads, and blocking IO is allowed.
internal class PersistentCacheImpl(
    private val userId: String,
    private val storage: PersistentCacheStorage,
) : PersistentCache {

    override fun put(key: CacheKey, bytes: ByteArray) {
        storage.put(key, userId, bytes)
    }

    override fun get(key: CacheKey): ByteArray? =
        storage.get(key, userId)

    override fun remove(key: CacheKey) {
        storage.remove(key, userId)
    }

    override fun clearAll() {
        storage.clearAll(userId)
    }
}

internal class PersistentCacheStorage(
    private val cipher: PersistentCacheCipher?,
    private val logger: Logger,
    context: Context,
) {

    private val prefs = context.getSharedPreferences("vpn-core-prefs", Context.MODE_PRIVATE)

    private fun getKey(key: CacheKey, userId: String) = "${key.name}:$userId"

    fun cacheFor(userId: String) = PersistentCacheImpl(userId, this)

    fun put(key: CacheKey, userId: String, bytes: ByteArray) {
        val data = cipher?.encrypt(bytes)?.getOrElse { e ->
            logger.log(LogLevel.ERROR, "PersistentCache: encryption failed for $key: $e")
            return
        } ?: bytes
        prefs.edit {
            putString(getKey(key, userId), Base64.encodeToString(data, Base64.NO_WRAP))
        }
    }

    fun get(key: CacheKey, userId: String): ByteArray? {
        val stored = prefs.getString(getKey(key, userId), null)?.let {
            Base64.decode(it, Base64.NO_WRAP)
        } ?: return null

        return if (cipher != null) {
            cipher.decrypt(stored).getOrElse { e ->
                logger.log(LogLevel.ERROR, "PersistentCache: decryption failed for $key: $e")
                null
            }
        } else {
            stored
        }
    }

    fun clearAll(userId: String) {
        prefs.edit {
            CacheKey.entries.forEach { remove(getKey(it, userId)) }
        }
    }

    fun remove(key: CacheKey, userId: String) {
        prefs.edit {
            remove(getKey(key, userId))
        }
    }
}
