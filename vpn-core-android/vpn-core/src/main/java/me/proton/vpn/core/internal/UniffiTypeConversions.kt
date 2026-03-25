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

import me.proton.vpn.core.api.ConnectionStats
import me.proton.vpn.core.api.PacketCaptureStopReason
import me.proton.vpn.core.api.PacketCaptureFile
import me.proton.vpn.core.api.PacketCaptureInfo
import me.proton.vpn.core.api.Peer
import me.proton.vpn.core.api.PeerConnection
import me.proton.vpn.core.api.VpnDisconnectError
import me.proton.vpn.core.api.VpnProtocol
import uniffi.protun.CaptureStopReason
import uniffi.protun.DisconnectReason
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

fun PeerConnectionInfo.toCoreApi(): PeerConnection =
    PeerConnection(
        protocol = protocol.toCoreApi(),
        id = peerId,
        entryAddr = InetSocketAddress(entryIp, port.toInt())
    )

fun DisconnectReason.toCoreApi(): VpnDisconnectError = when (this) {
    is DisconnectReason.TunEstablishError -> VpnDisconnectError.TunInterfaceError(message)
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

fun Event.ConnectionStats.toCoreApi() = ConnectionStats(
    receivedBytes = receivedBytes,
    sentBytes = sentBytes,
    timeSinceLastHandshake = timeSinceLastHandshake,
    estimatedLoss = estimatedLoss,
    estimatedRoundTripTime = estimatedRoundTripTime,
)

@OptIn(ExperimentalEncodingApi::class)
fun String.decodeBase64(): ByteArray = Base64.decode(this)