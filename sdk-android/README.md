# Proton VPN Android SDK

## Quick Start

### 1. Initialization

SDK instance need to be created with the DI framework of your choice in `Application.onCreate`
(early initialization is needed to handle VpnService being instantiated by the system):

```kotlin
class MyApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        ...
        vpnSdk = ProtonVpnSdk.create(context) { sdk ->
            SdkDependencies(
                notificationFactory = MyNotificationFactory(),
                logger = MyLogger(),
                systemEventHandler = MyEventHandler(sdk)
            )
        }
    }
}
```

### 2. Connect to VPN

```kotlin
val connectionManager = vpnSdk.connectionManager

// Observe connection state
connectionManager.state.forEach { state ->
    when (state) {
        is VpnConnectionState.Connected -> {
            // state.connection will have connection details (IP, port, protocol)
            ...
        }
        is VpnConnectionState.Connecting -> ...
    
        // Connection attempt requires app, user or system action to proceed.
        is VpnConnectionState.WaitingForAction -> when (state.reason) {
            ...
        }
    
        // If Disconnected::error != null connection failed due to error that might require app
        // action to fix and restart connection.
        is VpnConnectionState.Disconnected -> {
            if (state.error != null) {
                when (state.error) {
                    ...
                }
            }
        }
    }
}.launchIn(scope)

// Before connection app needs to make sure VPN system permission is granted.
val intent = VpnService.prepare(context)
if (intent != null) {
    // see https://developer.android.com/reference/android/net/VpnService#prepare(android.content.Context)
    // or sample app for more details.
    activity.startActivityForResult(intent , REQUEST_VPN_PERMISSION)
} else {
    // Permission already granted
}

// Start connection
val config = InitialConfig(
    interfaceConfig = InterfaceConfig(supportInTunnelIPv6 = true),
    clientED25519PrivateKeyBase64 = "<base64-private-key>",
    peers = listOf(
        Peer(
            address = serverAddress, // IPv4 or IPv6 server IP
            ports = mapOf(
                VpnProtocol.WireGuardUdp to listOf(udpPort1, udpPort2),
                VpnProtocol.WireGuardTcp to listOf(tcpPort)
            ),
            publicKeyX25519Base64 = "<base64-public-key>",
            priority = 0,
            id = "peer-1" // custom-ID attached to the peer
        )
    )
)

connectionManager.connect(config)
```

### 3. Update Configuration

Connection can be updated on-the-fly without full disconnection.

```kotlin
// Switch to different servers
connectionManager.updatePeers(newPeers)

// Update split tunneling or routing
connectionManager.updateInterfaceConfig(newInterfaceConfig)

// Disconnect
connectionManager.disconnect()
```

## Sample App

See the [sample-app](sample-app/) for a basic VPN app demonstrating:
- SDK initialization (with Hilt)
- VPN permission handling
- Preparing connection and handling connection states

## License

This project is licensed under the GNU General Public License v3.0 - see the source files for details.
