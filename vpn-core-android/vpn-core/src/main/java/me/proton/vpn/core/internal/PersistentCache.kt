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

    // Memory cache storing unencrypted data for devices with broken key store. When cipher fails
    // to encrypt, data won't be persisted and memory cache will keep the data available for as long
    // as the process is alive.
    // Guarded by [lock], which also keeps the memory cache and prefs in sync when concurrent
    // writers touch the same key. Cipher operations (potentially slow) are done outside the lock.
    private val memoryCache = mutableMapOf<Pair<String, CacheKey>, ByteArray>()

    private val lock = Any()

    private val prefs = context.getSharedPreferences("vpn-core-cache", Context.MODE_PRIVATE)

    private fun getKey(key: CacheKey, userId: String) = "${key.name}:$userId"

    fun cacheFor(userId: String) = PersistentCacheImpl(userId, this)

    fun put(key: CacheKey, userId: String, data: ByteArray) {
        val storeData = if (cipher != null) {
            cipher.encrypt(data).getOrElse { e ->
                logger.log(LogLevel.ERROR, "PersistentCache: encryption failed for $key: $e")
                null
            }
        } else {
            data
        }
        synchronized(lock) {
            memoryCache[userId to key] = data
            prefs.edit {
                if (storeData != null)
                    putString(getKey(key, userId), Base64.encodeToString(storeData, Base64.NO_WRAP))
                else
                    remove(getKey(key, userId)) // encryption failed, remove old data, rely on mem cache
            }
        }
    }

    fun get(key: CacheKey, userId: String): ByteArray? {
        val prefsKey = getKey(key, userId)
        val stored64 = synchronized(lock) {
            memoryCache[userId to key]?.let { return it }
            prefs.getString(prefsKey, null)
        } ?: return null

        val stored = Base64.decode(stored64, Base64.NO_WRAP)
        val value = if (cipher != null) {
            cipher.decrypt(stored).getOrElse { e ->
                logger.log(LogLevel.ERROR, "PersistentCache: decryption failed for $key: $e")
                return null
            }
        } else {
            stored
        }

        synchronized(lock) {
            val cached = memoryCache[userId to key]
            // A concurrent put/remove might have happened while decrypting, prefer its result.
            if (cached != null)
                return cached
            else if (prefs.getString(prefsKey, null) == stored64)
                memoryCache[userId to key] = value
        }
        return value
    }

    fun clearAll(userId: String) {
        synchronized(lock) {
            memoryCache.keys.removeAll { it.first == userId }
            prefs.edit {
                CacheKey.entries.forEach { remove(getKey(it, userId)) }
            }
        }
    }

    fun remove(key: CacheKey, userId: String) {
        synchronized(lock) {
            memoryCache.remove(userId to key)
            prefs.edit {
                remove(getKey(key, userId))
            }
        }
    }
}
