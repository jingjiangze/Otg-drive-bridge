package com.jingjiangze.otgdrivebridge

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.provider.DocumentsContract
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.jingjiangze.otgdrivebridge.network.InternetExposure
import com.jingjiangze.otgdrivebridge.network.NetBirdExposure
import com.jingjiangze.otgdrivebridge.network.SystemProcessRunner
import com.jingjiangze.otgdrivebridge.network.TransportProbeUseCase
import com.jingjiangze.otgdrivebridge.security.CredentialGenerator
import com.jingjiangze.otgdrivebridge.service.WebDavService
import com.jingjiangze.otgdrivebridge.storage.StorageRoot
import com.jingjiangze.otgdrivebridge.storage.StorageRootKind
import com.jingjiangze.otgdrivebridge.storage.StorageRootRepository
import com.jingjiangze.otgdrivebridge.storage.TreeGrant
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The single screen: pick the OTG folder, start the service, then show the
 * ordered transport cards (LAN first, virtual LAN, tunnel) the user can copy or
 * scan.
 *
 * The layout is intentionally plain — this is a control panel, not a gallery.
 * Every card states the address, whether it is encrypted, and what to do if
 * Windows refuses it (RaiDrive fallback), which is the audit's top open risk.
 */
class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    BridgeScreen()
                }
            }
        }
    }

    @Composable
    private fun BridgeScreen() {
        val context = this
        val clipboard = LocalClipboardManager.current
        var root by remember { mutableStateOf(StorageRootRepository.load()) }
        var credentials by remember {
            mutableStateOf(StorageRootRepository.credentials() ?: generateAndStoreCredentials())
        }
        var internetEnabled by remember { mutableStateOf(false) }
        var transports by remember { mutableStateOf(emptyList<com.jingjiangze.otgdrivebridge.network.Transport>()) }
        var status by remember { mutableStateOf("未启动") }
        val isRunning by WebDavService.isRunning.collectAsState()

        val picker = androidx.activity.compose.rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocumentTree()
        ) { uri: Uri? ->
            val treeGrant = TreeGrant(context, noopLauncher())
            uri?.let {
                val picked = treeGrant.onTreePicked(it)
                if (picked != null) {
                    StorageRootRepository.save(picked)
                    root = picked
                    status = "已选择：${picked.treeUri ?: picked.managedPath}"
                } else {
                    status = "系统拒绝了持久化授权，请重试"
                }
            }
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("OTG Drive Bridge", style = MaterialTheme.typography.headlineSmall)
            Text(
                "把 OTG U 盘共享为 WebDAV，Windows 映射为网络驱动器后直接编辑原文件。",
                style = MaterialTheme.typography.bodyMedium
            )

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("1. 选择 U 盘目录", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        root?.let { "已选择：${it.treeUri ?: it.managedPath}" }
                            ?: "尚未选择。Android 11+ 可能不允许选可移动卷根目录，可选择一个子目录。",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            val seed = treeGrantRemovableSeed()
                            picker.launch(seed)
                        }) { Text("选择 U 盘目录（SAF）") }
                        OutlinedButton(onClick = {
                            val intent = Intent(
                                Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION,
                                Uri.parse("package:$packageName")
                            )
                            startActivity(intent)
                            status = "请在系统设置中授予「所有文件访问权限」，然后用路径模式选择 /storage/…"
                        }) { Text("全部文件访问（备用）") }
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("2. 访问凭据（Digest，不传明文密码）", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    Text("用户名：${credentials.first}", fontFamily = FontFamily.Monospace)
                    Text("密码：${credentials.second}", fontFamily = FontFamily.Monospace)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Windows 映射时输入这对凭据。Digest 认证不会在网络上传输明文密码，也不受 Windows 默认阻止 HTTP Basic Auth 的影响。",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = {
                        credentials = generateAndStoreCredentials()
                        status = "已轮换凭据，请重新连接"
                    }) { Text("轮换密码") }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text("启用互联网通道", style = MaterialTheme.typography.titleMedium)
                        Switch(checked = internetEnabled, onCheckedChange = { internetEnabled = it })
                    }
                    Text(
                        "默认关闭。开启后才会尝试 NetBird / Cloudflare；二者都不可用时不会出现对应卡片。",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("3. 连接方式（按优先级排列）", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(8.dp))
                    if (transports.isEmpty()) {
                        Text("启动服务后这里会显示可用的连接地址。", style = MaterialTheme.typography.bodySmall)
                    }
                    transports.forEach { transport ->
                        TransportCard(
                            transport = transport,
                            onCopy = {
                                clipboard.setText(androidx.compose.ui.text.AnnotatedString(transport.url))
                                status = "已复制：${transport.url}"
                            }
                        )
                        Spacer(Modifier.height(8.dp))
                    }
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        val current = root
                        if (current == null) {
                            status = "请先选择 U 盘目录"
                        } else if (!TreeGrant(context, noopLauncher()).isGrantValid(current)) {
                            status = "授权已失效，请重新选择目录"
                        } else {
                            WebDavService.start(context)
                            status = "服务启动中…"
                            probeTransports(
                                internetEnabled = internetEnabled,
                                onResult = { transports = it },
                                onStatus = { status = it }
                            )
                        }
                    },
                    enabled = !isRunning
                ) { Text("启动共享") }

                OutlinedButton(
                    onClick = { WebDavService.stop(context) },
                    enabled = isRunning
                ) { Text("停止共享") }
            }

            Text("状态：$status", style = MaterialTheme.typography.bodySmall)
            Text(
                "Windows 侧：文件资源管理器 → 映射网络驱动器 → 粘贴上面的地址。若原生映射失败（例如提示网络错误或 0x80070043），" +
                    "请改用 RaiDrive（个人免费）或 rclone + WinFSP，它们自带 WebDAV 客户端并支持非 80 端口。",
                style = MaterialTheme.typography.bodySmall
            )
        }
    }

    private fun probeTransports(
        internetEnabled: Boolean,
        onResult: (List<com.jingjiangze.otgdrivebridge.network.Transport>) -> Unit,
        onStatus: (String) -> Unit
    ) {
        CoroutineScope(Dispatchers.Main).launch {
            val exposures: List<InternetExposure> = listOf(
                NetBirdExposure(SystemProcessRunner())
            )
            val useCase = TransportProbeUseCase(
                lanAddressResolver = com.jingjiangze.otgdrivebridge.network.LanAddressResolver(this@MainActivity),
                exposures = exposures,
                localPort = com.jingjiangze.otgdrivebridge.server.WebDavEngine.DEFAULT_PORT,
                internetEnabled = internetEnabled
            )
            val probe = withContext(Dispatchers.IO) { useCase.probe() }
            onResult(probe.transports)
            onStatus("已探测 ${probe.transports.size} 条通道")
        }
    }

    private fun generateAndStoreCredentials(): Pair<String, String> {
        val username = CredentialGenerator.username()
        val password = CredentialGenerator.password()
        StorageRootRepository.saveCredentials(username, password)
        return username to password
    }

    /** Seeds the SAF picker with the first removable volume, if visible. */
    private fun treeGrantRemovableSeed(): Uri? {
        val volumes = getExternalFilesDirs(null).mapNotNull { dir ->
            dir ?: return@mapNotNull null
            val marker = "/Android/"
            val idx = dir.absolutePath.indexOf(marker)
            if (idx < 0) null else dir.absolutePath.substring(0, idx)
        }.distinct()
        val removable = volumes.firstOrNull { it.startsWith("/storage/") && !it.contains("emulated") }
            ?: return null
        return runCatching {
            DocumentsContract.buildDocumentUri(
                "com.android.externalstorage.documents",
                "$removable:"
            )
        }.getOrNull()
    }

    private fun noopLauncher() = object : androidx.activity.result.ActivityResultLauncher<android.net.Uri?> {
        override fun launch(input: android.net.Uri?, transition: androidx.core.app.ActivityOptionsCompat?) = Unit
        override val contract: androidx.activity.result.contract.ActivityResultContract<android.net.Uri?, *>
            get() = throw UnsupportedOperationException("only used for grant checks")
        override fun unregister() = Unit
    }

    @Composable
    private fun TransportCard(
        transport: com.jingjiangze.otgdrivebridge.network.Transport,
        onCopy: () -> Unit
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(12.dp)) {
                Text(transport.label, style = MaterialTheme.typography.titleSmall)
                Text(transport.url, fontFamily = FontFamily.Monospace)
                Text(transport.detail, style = MaterialTheme.typography.bodySmall)
                transport.warning?.let {
                    Text("⚠ $it", style = MaterialTheme.typography.bodySmall)
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = onCopy) { Text("复制地址") }
            }
        }
    }
}
