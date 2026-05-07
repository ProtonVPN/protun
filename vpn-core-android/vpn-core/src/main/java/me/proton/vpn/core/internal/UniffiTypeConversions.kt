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

import me.proton.vpn.core.api.AgentConnectionInfo
import me.proton.vpn.core.api.AgentConnectionWaitReason
import me.proton.vpn.core.api.ConnectionMode
import me.proton.vpn.core.api.ConnectionStats
import me.proton.vpn.core.api.LocalAgentSettingType
import me.proton.vpn.core.api.LocalAgentStats
import me.proton.vpn.core.api.NetShieldLevel
import me.proton.vpn.core.api.PacketCaptureStopReason
import me.proton.vpn.core.api.PacketCaptureFile
import me.proton.vpn.core.api.PacketCaptureInfo
import me.proton.vpn.core.api.Peer
import me.proton.vpn.core.api.PeerConnection
import me.proton.vpn.core.api.LocalAgentSettings
import me.proton.vpn.core.api.LocationCoordinates
import me.proton.vpn.core.api.Restriction
import me.proton.vpn.core.api.VpnConnectionEvent
import me.proton.vpn.core.api.VpnDisconnectError
import me.proton.vpn.core.api.VpnDisconnectError.*
import me.proton.vpn.core.api.VpnErrorEvent
import me.proton.vpn.core.api.VpnProtocol
import me.proton.vpn.core.api.WaitJailReason
import uniffi.protun.CaptureStopReason
import uniffi.protun.DisconnectReason
import uniffi.protun.ErrorEvent
import uniffi.protun.Event
import uniffi.protun.FileWriteMode
import uniffi.protun.PcapFile
import uniffi.protun.PcapFileInfo
import uniffi.protun.PeerConnectionInfo
import uniffi.protun.PeerInfo
import uniffi.protun.Protocol
import java.io.File
import java.net.InetSocketAddress
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

fun List<Peer>.toUniFFI(): List<PeerInfo> = map { peer ->
    PeerInfo(
        peerId = peer.id,
        serverIp = requireNotNull(peer.address.hostAddress),
        serverPublicKey = peer.publicKeyX25519Base64.decodeBase64(),
        tcpPorts = peer.ports[VpnProtocol.WireGuardTcp]?.map { it.toUShort() } ?: emptyList(),
        udpPorts = peer.ports[VpnProtocol.WireGuardUdp]?.map { it.toUShort() } ?: emptyList(),
        tlsPorts = peer.ports[VpnProtocol.Stealth]?.map { it.toUShort() } ?: emptyList(),
        priority = peer.priority,
        exitLabel = peer.exitLabel,
    )
}

fun PacketCaptureInfo.toUniFFI(): PcapFileInfo = PcapFileInfo(
    when (file) {
        is PacketCaptureFile.Fd -> PcapFile.Fd(file.fd)
        is PacketCaptureFile.Path -> PcapFile.Path(
            file.path.absolutePath,
            if (file.append) FileWriteMode.APPEND else FileWriteMode.OVERWRITE
        )
    },
    maxBytes
)

fun LocalAgentSettings.toUniFFI() = uniffi.protun.LocalAgentSettings(
    splitTcp = splitTcp,
    netshieldLevel = netshieldLevel?.toUniFFI(),
    softJail = softJail,
    portForwarding = portForwarding,
    randomNat = randomNat,
    circumventionRouting = circumventionRouting,
)

fun NetShieldLevel.toUniFFI(): uniffi.protun.NetshieldLevel = when (this) {
    NetShieldLevel.None -> uniffi.protun.NetshieldLevel.NONE
    NetShieldLevel.MalwareFilter -> uniffi.protun.NetshieldLevel.MALWARE_FILTER
    NetShieldLevel.AdsAndMalwareFilter -> uniffi.protun.NetshieldLevel.ADS_AND_MALWARE_FILTER
}

fun PeerConnectionInfo.toCoreApi(): PeerConnection =
    PeerConnection(
        protocol = protocol.toCoreApi(),
        id = peerId,
        entryAddr = InetSocketAddress(entryIp, port.toInt())
    )

fun DisconnectReason.toCoreApi(): VpnDisconnectError = when (this) {
    is DisconnectReason.TunEstablishError -> TunInterfaceError(message)
}

fun Protocol.toCoreApi(): VpnProtocol = when (this) {
    Protocol.WIREGUARD_UDP -> VpnProtocol.WireGuardUdp
    Protocol.WIREGUARD_TCP -> VpnProtocol.WireGuardTcp
    Protocol.STEALTH -> VpnProtocol.Stealth
}

fun CaptureStopReason.toCoreApi(): PacketCaptureStopReason = when (this) {
    CaptureStopReason.AlreadyStopped -> PacketCaptureStopReason.AlreadyStopped
    is CaptureStopReason.Disconnected -> PacketCaptureStopReason.Disconnected(file.toCoreApi().file)
    is CaptureStopReason.MaxSizeReached -> PacketCaptureStopReason.MaxSizeReached(file.toCoreApi().file)
    is CaptureStopReason.Request -> PacketCaptureStopReason.Request(file.toCoreApi().file)
}

fun PcapFileInfo.toCoreApi() = PacketCaptureInfo(
    when (val f = file) {
        is PcapFile.Fd -> PacketCaptureFile.Fd(f.v1)
        is PcapFile.Path -> PacketCaptureFile.Path(
            path = File(f.path),
            append = f.mode == FileWriteMode.APPEND
        )
    },
    maxBytes = maxBytes
)

fun uniffi.protun.WaitJailReason.toCoreApi(): WaitJailReason = when (this) {
    is uniffi.protun.WaitJailReason.BadUserBehavior -> WaitJailReason.BadUserBehavior(message)
    is uniffi.protun.WaitJailReason.DisabledUser -> WaitJailReason.DisabledUser(message)
    is uniffi.protun.WaitJailReason.LowPlan -> WaitJailReason.LowPlan(message)
    is uniffi.protun.WaitJailReason.PendingInvoice -> WaitJailReason.PendingInvoice(message)
    is uniffi.protun.WaitJailReason.SessionOverLimit -> WaitJailReason.SessionOverLimit(message)
    is uniffi.protun.WaitJailReason.WaitingClientChallengeReply -> WaitJailReason.WaitingClientChallengeReply(message)
    is uniffi.protun.WaitJailReason.Need2Fa -> WaitJailReason.Need2FA(message)
    is uniffi.protun.WaitJailReason.Internal -> WaitJailReason.Internal(message)
    is uniffi.protun.WaitJailReason.Other -> WaitJailReason.Other(code, message)
}

fun uniffi.protun.AgentConnectionInfo.toCoreApi() = AgentConnectionInfo(
    serverExitV4 = serverExitV4,
    serverExitV6 = serverExitV6,
    userIspIP = userIspIp,
    userIspCountryCode = userIspCountryCode,
    userIspName = userIspName,
    userIspCoordinates = userIspCoordinates?.let {
        LocationCoordinates(latitude = it.latitude, longitude = it.longitude)
    },
    settings = settings.toCoreApi(),
    restrictions = restrictions.map { restriction ->
        when (restriction) {
            is uniffi.protun.Restriction.Streaming -> Restriction.Streaming(restriction.reason)
            is uniffi.protun.Restriction.Torrent -> Restriction.Torrent(restriction.reason)
            is uniffi.protun.Restriction.Other -> Restriction.Other(restriction.reason)
        }
    },
)

fun uniffi.protun.LocalAgentSettings.toCoreApi() = LocalAgentSettings(
    splitTcp = splitTcp,
    netshieldLevel = netshieldLevel?.toCoreApi(),
    softJail = softJail,
    portForwarding = portForwarding,
    randomNat = randomNat,
    circumventionRouting = circumventionRouting,
)

fun Event.ConnectionStats.toCoreApi() = ConnectionStats(
    receivedBytes = receivedBytes,
    sentBytes = sentBytes,
    timeSinceLastHandshake = timeSinceLastHandshake,
    estimatedLoss = estimatedLoss,
    estimatedRoundTripTime = estimatedRoundTripTime,
)

fun ConnectionMode.toUniFFI(): uniffi.protun.ConnectionMode = when (this) {
    is ConnectionMode.NoLocalAgent ->
        uniffi.protun.ConnectionMode.NoLocalAgent(clientX25519PrivateKeyBase64.decodeBase64())
    is ConnectionMode.LocalAgent ->
        uniffi.protun.ConnectionMode.LocalAgent(userAgent, appVersion, settings.toUniFFI())
}

fun Event.LocalAgentStats.toCoreApi() = LocalAgentStats(
    bytesReceived = bytesReceived,
    bytesSent = bytesSent,
    maliciousBlocked = maliciousBlocked,
    adsBlocked = adsBlocked,
    trackersBlocked = trackersBlocked,
    adultContentBlocked = adultContentBlocked,
    dataSaved = dataSaved,
)

fun uniffi.protun.NetshieldLevel.toCoreApi(): NetShieldLevel = when (this) {
    uniffi.protun.NetshieldLevel.NONE -> NetShieldLevel.None
    uniffi.protun.NetshieldLevel.MALWARE_FILTER -> NetShieldLevel.MalwareFilter
    uniffi.protun.NetshieldLevel.ADS_AND_MALWARE_FILTER -> NetShieldLevel.AdsAndMalwareFilter
}

fun uniffi.protun.LocalAgentSettingType.toCoreApi(): LocalAgentSettingType = when (this) {
    uniffi.protun.LocalAgentSettingType.NETSHIELD_LEVEL -> LocalAgentSettingType.NetshieldLevel
    uniffi.protun.LocalAgentSettingType.BOUNCING -> LocalAgentSettingType.Bouncing
    uniffi.protun.LocalAgentSettingType.PORT_FORWARDING -> LocalAgentSettingType.PortForwarding
    uniffi.protun.LocalAgentSettingType.SPLIT_TCP -> LocalAgentSettingType.SplitTcp
    uniffi.protun.LocalAgentSettingType.SAFE_MODE -> LocalAgentSettingType.SafeMode
    uniffi.protun.LocalAgentSettingType.RANDOM_NAT -> LocalAgentSettingType.RandomNat
}

fun Event.toCoreApi(): VpnConnectionEvent? = when (this) {
    is Event.ConnectionStats -> null // ConnectionStats are exposed in a dedicated flow, not as events
    is Event.LocalAgentStats -> null // LocalAgentStats are exposed in localAgentStats flow, not as events
    is Event.PacketCaptureStarted -> VpnConnectionEvent.PacketCaptureStarted(info.toCoreApi())
    is Event.PacketCaptureStopped -> VpnConnectionEvent.PacketCaptureStopped(reason.toCoreApi())
    is Event.Error -> VpnConnectionEvent.Error(error.toCoreApi())
}

private fun ErrorEvent.toCoreApi(): VpnErrorEvent = when (this) {
    ErrorEvent.ApiSessionExpired -> VpnErrorEvent.ApiSessionExpired
    is ErrorEvent.LocalAgentSettingPolicyRefused -> VpnErrorEvent.LocalAgentSettingPolicyRefused(setting.toCoreApi())
    ErrorEvent.CertificateRefreshFatalError -> VpnErrorEvent.CertificateRefreshFatalError
}

fun uniffi.protun.AgentConnectionWaitReason.toCoreApi(): AgentConnectionWaitReason =
    when (this) {
        is uniffi.protun.AgentConnectionWaitReason.HardJailed ->
            AgentConnectionWaitReason.HardJailed(jails.map { it.toCoreApi() })

        uniffi.protun.AgentConnectionWaitReason.SoftJailed ->
            AgentConnectionWaitReason.SoftJailed
    }

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeBase64(): ByteArray = Base64.decode(this)