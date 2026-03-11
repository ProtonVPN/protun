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

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import java.time.Duration

/**
 * Events related to VPN connection. (available via [ProtonVpnConnectionManager.events])
 */
@Parcelize
sealed interface VpnConnectionEvent : Parcelable {
    data class PacketCaptureStarted(val info: PacketCaptureInfo) : VpnConnectionEvent
    data class PacketCaptureStopped(val reason: PacketCaptureStopReason) : VpnConnectionEvent
}

@Parcelize
sealed interface PacketCaptureStopReason : Parcelable {

    /**
     * Capture was stopped by a request from the client app.
     */
    data class Request(val file: PacketCaptureFile) : PacketCaptureStopReason

    /**
     * Capture ended because max file size was reached (see [PacketCaptureInfo.maxBytes]).
     */
    data class MaxSizeReached(val file: PacketCaptureFile) : PacketCaptureStopReason

    /**
     * Capture ended when connection was closed.
     */
    data class Disconnected(val file: PacketCaptureFile) : PacketCaptureStopReason

    /**
     * Packet capture stop was requested when capture was not active.
     */
    data object AlreadyStopped : PacketCaptureStopReason
}
