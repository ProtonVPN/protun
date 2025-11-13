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

package me.proton.vpn.sdk.sample_app.ui

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContract

enum class VpnPermissionError {
    PermissionDenied,
    VpnNotSupported
}

fun ComponentActivity.runWithVpnPermission(
    onError: (VpnPermissionError) -> Unit,
    onPermissionGranted: () -> Unit
) {
    val intent = VpnService.prepare(this)
    if (intent == null) {
        onPermissionGranted()
    } else {
        val permissionCall = activityResultRegistry.register(
            "VPNPermission",
            PermissionContract(intent)
        ) { permissionGranted ->
            if (permissionGranted) {
                onPermissionGranted()
            } else {
                onError(VpnPermissionError.PermissionDenied)
            }
        }
        try {
            permissionCall.launch(PermissionContract.VPN_PERMISSION_ACTIVITY)
        } catch (_: ActivityNotFoundException) {
            onError(VpnPermissionError.VpnNotSupported)
        }
    }
}

class PermissionContract(val intent: Intent) : ActivityResultContract<Int, Boolean>() {

    override fun parseResult(resultCode: Int, intent: Intent?): Boolean = resultCode == Activity.RESULT_OK
    override fun createIntent(context: Context, input: Int): Intent = intent

    companion object {
        const val VPN_PERMISSION_ACTIVITY = 1
    }
}
