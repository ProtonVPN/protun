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

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * Events related to VPN connection. (available via [ProtonVpnConnectionManager.events])
 */
@Parcelize
sealed interface VpnConnectionEvent : Parcelable {
    data class PacketCaptureStarted(val info: PacketCaptureInfo) : VpnConnectionEvent
    data class PacketCaptureStopped(val reason: PacketCaptureStopReason) : VpnConnectionEvent
    data class Error(val error: VpnErrorEvent) : VpnConnectionEvent
}

@Parcelize
sealed interface VpnErrorEvent : Parcelable {
    data object ApiSessionExpired : VpnErrorEvent
    data object CertificateRefreshFatalError : VpnErrorEvent
    data class LocalAgentSettingPolicyRefused(val setting: LocalAgentSettingType) : VpnErrorEvent
}

enum class LocalAgentSettingType {
    NetshieldLevel,
    Bouncing,
    PortForwarding,
    SplitTcp,
    SafeMode,
    RandomNat,
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
