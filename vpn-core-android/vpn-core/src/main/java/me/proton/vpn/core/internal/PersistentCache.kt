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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import me.proton.vpn.core.api.Logger
import me.proton.vpn.core.api.PersistentCacheCipher
import uniffi.protun.CacheKey
import uniffi.protun.LogLevel
import uniffi.protun.PersistentCache

// This class will be used from background threads, and blocking IO is allowed.
class PersistentCacheImpl(
    private val cipher: PersistentCacheCipher?,
    private val logger: Logger,
    context: Context,
) : PersistentCache {

    private val prefs = context.getSharedPreferences("vpn-core-prefs", Context.MODE_PRIVATE)

    override fun put(key: CacheKey, bytes: ByteArray) {
        val data = cipher?.encrypt(bytes)?.getOrElse { e ->
            logger.log(LogLevel.ERROR, "PersistentCache: encryption failed for $key: $e")
            return
        } ?: bytes
        prefs.edit {
            putString(key.name, Base64.encodeToString(data, Base64.NO_WRAP))
        }
    }

    override fun get(key: CacheKey): ByteArray? {
        val stored = prefs.getString(key.name, null)?.let {
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

    override fun clear() {
        prefs.edit { clear() }
    }
}
