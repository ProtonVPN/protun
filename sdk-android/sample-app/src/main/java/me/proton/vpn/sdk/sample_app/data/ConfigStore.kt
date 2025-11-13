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

package me.proton.vpn.sdk.sample_app.data

import android.content.Context
import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import androidx.datastore.dataStoreFile
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import java.io.InputStream
import java.io.OutputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ConfigStore @Inject constructor(
    @ApplicationContext context: Context
) : DataStore<VpnConfig?> by DataStoreFactory.create(
    serializer = JsonDataStoreSerializer(
        defaultValue = null,
        serializer = VpnConfig.serializer()
    ),
    produceFile = { context.dataStoreFile("config.json") }
)

class JsonDataStoreSerializer<T>(
    override val defaultValue: T?,
    private val serializer: KSerializer<T>
) : Serializer<T?> {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    override suspend fun readFrom(input: InputStream): T? =
        try {
            if (input.available() == 0)
                null
            else
                json.decodeFromString(serializer, input.readBytes().decodeToString())
        } catch (serialization: SerializationException) {
            throw CorruptionException("Unable to read", serialization)
        }

    override suspend fun writeTo(t: T?, output: OutputStream) {
        if (t != null)
            output.write(json.encodeToString(serializer, t).encodeToByteArray())
    }
}