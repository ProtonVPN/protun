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

import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.hilt.lifecycle.viewmodel.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.flow.first
import me.proton.vpn.sdk.sample_app.data.VpnConfig

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: MainViewModel = hiltViewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    var ip by rememberSaveable { mutableStateOf("") }
    var udpPorts by rememberSaveable { mutableStateOf("") }
    var tcpPorts by rememberSaveable { mutableStateOf("") }
    var tlsPorts by rememberSaveable { mutableStateOf("") }
    var peerPublicKey by rememberSaveable { mutableStateOf("") }
    var clientPrivateKey by rememberSaveable { mutableStateOf("") }

    LaunchedEffect(Unit) {
        val initialConfig = viewModel.lastConfig.first()
        initialConfig?.let { cfg ->
            ip = cfg.ip
            udpPorts = cfg.udpPorts.joinToString(",")
            tcpPorts = cfg.tcpPorts.joinToString(",")
            tlsPorts = cfg.tlsPorts.joinToString(",")
            peerPublicKey = cfg.peerPublicKey
            clientPrivateKey = cfg.clientPrivateKey
        }
    }

    val context = LocalContext.current
    LaunchedEffect(context) {
        viewModel.events.collect { event ->
            when (event) {
                is Event.ConnectionError -> {
                    Toast.makeText(context, event.message, Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .statusBarsPadding()
            .fillMaxSize()
    ) {
        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = ip,
                onValueChange = { ip = it },
                label = { Text("Peer IP") },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = udpPorts,
                onValueChange = { udpPorts = it },
                label = { Text("UDP Ports (comma separated)") },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = tcpPorts,
                onValueChange = { tcpPorts = it },
                label = { Text("TCP Ports (comma separated)") },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = tlsPorts,
                onValueChange = { tlsPorts = it },
                label = { Text("TLS Ports (comma separated)") },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = peerPublicKey,
                onValueChange = { peerPublicKey = it },
                label = { Text("Peer public key (Base64)") },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = clientPrivateKey,
                onValueChange = { clientPrivateKey = it },
                label = { Text("Client private key (Base64)") },
                modifier = Modifier.fillMaxWidth()
            )
        }

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(color = MaterialTheme.colorScheme.surfaceVariant)
                .padding(16.dp)
                .navigationBarsPadding()
        ) {
            Column(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = uiState.stateLabel,
                    minLines = 2,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp)
                )

                val activity = LocalActivity.current as ComponentActivity
                when (uiState.buttonType) {
                    ButtonType.Loading -> {
                        Button(
                            onClick = {},
                            enabled = false,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                CircularProgressIndicator(
                                    color = ButtonDefaults.buttonColors().disabledContentColor,
                                    strokeWidth = 2.dp,
                                    modifier = Modifier.padding(end = 8.dp).size(12.dp)
                                )
                                Text("Loading...")
                            }
                        }
                    }
                    ButtonType.Connect -> {
                        Button(
                            onClick = {
                                val cfg = VpnConfig(
                                    ip = ip,
                                    udpPorts = parsePorts(udpPorts),
                                    tcpPorts = parsePorts(tcpPorts),
                                    tlsPorts = parsePorts(tlsPorts),
                                    peerPublicKey = peerPublicKey,
                                    clientPrivateKey = clientPrivateKey
                                )
                                activity.runWithVpnPermission(onError = viewModel::onPermissionError) {
                                    viewModel.connect(cfg)
                                }
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Connect")
                        }
                    }
                    ButtonType.Disconnect -> {
                        Button(
                            onClick = viewModel::disconnect,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text("Disconnect")
                        }
                    }
                }
            }
        }
    }
}

fun parsePorts(s: String): List<Int> = s
    .split(',')
    .mapNotNull { it.trim().toIntOrNull() }
