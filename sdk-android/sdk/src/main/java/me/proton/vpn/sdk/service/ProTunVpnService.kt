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

package me.proton.vpn.sdk.service

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.Parcel
import android.os.Parcelable
import android.util.Log
import me.proton.vpn.sdk.api.InitialConfig
import me.proton.vpn.sdk.api.InterfaceConfig
import me.proton.vpn.sdk.api.Logger
import me.proton.vpn.sdk.api.ForegroundServiceNotificationFactory
import me.proton.vpn.sdk.api.Peer
import me.proton.vpn.sdk.api.SystemEventHandler
import me.proton.vpn.sdk.api.VpnConnectionState
import me.proton.vpn.sdk.internal.DependencyContainer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.parcelize.Parcelize
import me.proton.vpn.sdk.api.PcapFile
import uniffi.protun.LogLevel
import uniffi.protun.OnSocketFdAvailableCallback
import java.lang.ref.WeakReference

internal interface ProTunVpnServiceCallback {
    fun onStateChanged(state: VpnConnectionState)
}

internal class ProTunVpnService : VpnService() {

    // Coroutine scope that will be cancelled when the service is destroyed
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var binder: ProTunVpnServiceBinder? = null
    lateinit var socketProtectCallback: ProTunSocketProtectCallback

    // Dependencies provided via DependencyContainer (initialized via ProtonVpnSdk.create())
    private val manager: ConnectionManager by lazy { DependencyContainer.connectionManager }
    private val logger: Logger get() = DependencyContainer.logger
    private val notifications: ForegroundServiceNotificationFactory by lazy { DependencyContainer.notificationFactory }
    private val systemEventHandler: SystemEventHandler by lazy { DependencyContainer.eventHandler }

    override fun onCreate() {
        super.onCreate()

        if (!DependencyContainer.isInitialized) {
            Log.e("ProtonVpnService", "SDK dependencies are not initialized. " +
                    "Make sure ProtonVpnSdk.create() is called in Application.onCreate()")
            stopSelf()
            return
        }

        logger.log(LogLevel.INFO, "ProTunVpnService onCreate")
        socketProtectCallback = ProTunSocketProtectCallback(logger, WeakReference(this))
        binder = ProTunVpnServiceBinder(logger, WeakReference(this))
        manager.init(serviceScope)
        manager.state.onEach {
            binder?.notifyStateChanged(it)
        }.launchIn(serviceScope)
    }

    override fun onBind(intent: Intent) = binder

    override fun onDestroy() {
        if (DependencyContainer.isInitialized) {
            logger.log(LogLevel.INFO, "ProTunVpnService onDestroy")
            manager.clearConnection()
            stopForeground(STOP_FOREGROUND_REMOVE)
            binder?.weakService?.clear()
            binder = null
            serviceScope.cancel()
        }
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!DependencyContainer.isInitialized)
            return START_NOT_STICKY

        logger.log(LogLevel.INFO, "ProTunVpnService onStartCommand, intent: $intent, flags: $flags, startId: $startId")
        val startSticky = when {
            intent == null -> {
                handleProcessRestore()
                false
            }
            intent.action == SERVICE_INTERFACE -> {
                handleAlwaysOn()
                false
            }
            intent.action == VPN_ACTION -> {
                // As action is always delivered via startForegroundService we always need to
                // meet the promise of startForeground, even if we're stopping it right away.
                startForeground(notifications.notificationId, notifications.buildNotification(this, manager.state.value))

                val vpnAction = requireNotNull(intent.getParcelableExtra<VpnAction>(VPN_ACTION_EXTRA))
                when (vpnAction) {
                    is VpnAction.Connect -> {
                        manager.connect(vpnAction.config, Builder(), socketProtectCallback)
                        true
                    }
                    VpnAction.Disconnect -> {
                        manager.clearConnection()
                        // stopSelf without stopForeground will not destroy the service.
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                        false
                    }
                    is VpnAction.Update -> {
                        if (manager.activeConnection != null) {
                            when (vpnAction) {
                                is VpnAction.Update.Interface ->
                                    manager.updateInterfaceConfig(vpnAction.interfaceConfig, Builder())

                                is VpnAction.Update.Peers ->
                                    manager.updatePeers(vpnAction.peers)

                                is VpnAction.Update.ClientPrivateKey ->
                                    manager.updateClientPrivateKey(vpnAction.clientED25519PrivateKeyPem)

                                is VpnAction.Update.PacketCapture ->
                                    manager.setPacketCaptureEnabled(vpnAction.pcapFile)
                            }
                            true
                        } else {
                            logger.log(LogLevel.WARN, "ProTunVpnService received update action without " +
                                    "active connection ${vpnAction.javaClass.simpleName}")
                            stopForeground(STOP_FOREGROUND_REMOVE)
                            stopSelf()
                            false
                        }
                    }
                }
            }
            else -> {
                logger.log(LogLevel.WARN, "ProTunVpnService received unknown intent action: ${intent.action}")
                false
            }
        }
        return if (startSticky) START_STICKY else START_NOT_STICKY
    }

    private fun handleProcessRestore() =
        systemEventHandler.onProcessRestored().also {
            logger.log(LogLevel.INFO, "ProTunVpnService.handleProcessRestore shouldRestart=$it")
        }

    private fun handleAlwaysOn() =
        systemEventHandler.onAlwaysOnEnabled().also {
            logger.log(LogLevel.INFO, "ProTunVpnService.handleAlwaysOn shouldRestart=$it")
        }

    //TODO(VPNAND-2287): not called for some reason when another VPN takes over
    override fun onRevoke() {
        if (!DependencyContainer.isInitialized)
            return

        logger.log(LogLevel.INFO, "ProTunVpnService onRevoke")
        manager.clearConnection()
        // stopSelf without stopForeground will not destroy the service.
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        super.onRevoke()
    }

    val state get(): VpnConnectionState = manager.state.value

    sealed interface VpnAction : Parcelable {
        @Parcelize data class Connect(val config: InitialConfig) : VpnAction
        @Parcelize data object Disconnect : VpnAction

        sealed interface Update : VpnAction {
            @Parcelize data class Interface(val interfaceConfig: InterfaceConfig) : Update
            @Parcelize data class Peers(val peers: List<Peer>) : Update
            @Parcelize data class ClientPrivateKey(val clientED25519PrivateKeyPem: String) : Update
            @Parcelize data class PacketCapture(val pcapFile: PcapFile?) : Update
        }
    }

    companion object {
        fun actionIntent(context: Context, vpnAction: VpnAction) =
            Intent(context, ProTunVpnService::class.java).apply {
                action = VPN_ACTION
                putExtra(VPN_ACTION_EXTRA, vpnAction)
            }

        const val VPN_ACTION = "VPN_ACTION"
        const val VPN_ACTION_EXTRA = "VPN_ACTION_EXTRA"
    }
}

internal class ProTunVpnServiceBinder(
    val logger: Logger,
    val weakService: WeakReference<ProTunVpnService>
) : Binder() {

    private val callbacks = mutableSetOf<ProTunVpnServiceCallback>()

    fun getState(): VpnConnectionState = weakService.get()?.state ?: VpnConnectionState.Disconnected()

    fun registerCallback(callback: ProTunVpnServiceCallback) {
        callbacks.add(callback)
    }

    fun unregisterCallback(callback: ProTunVpnServiceCallback) {
        callbacks.remove(callback)
    }

    fun notifyStateChanged(state: VpnConnectionState) {
        callbacks.forEach { it.onStateChanged(state) }
    }

    //TODO(VPNAND-2287): workaround for onRevoke not being called when another VPN takes over, but
    //   might not work on all devices/versions
    override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
        // We'll get this code when VPN connection is replaced by another VPN app
        // or revoked via system settings.
        if (code == LAST_CALL_TRANSACTION) {
            logger.log(LogLevel.INFO, "ProTunVpnService: binder LAST_CALL_TRANSACTION received, revoking VPN")
            weakService.get()?.onRevoke()
            return true
        }
        return super.onTransact(code, data, reply, flags)
    }
}

internal class ProTunSocketProtectCallback(
    val logger: Logger,
    val weakService: WeakReference<ProTunVpnService>
): OnSocketFdAvailableCallback {

    override fun onSocketFdAvailable(socketFd: Int) {
        val success = weakService.get()?.protect(socketFd) == true
        logger.log(LogLevel.INFO, "ProTunVpnService protect socket($socketFd) success: $success")
    }
}