package com.jingjiangze.otgdrivebridge

import android.content.Intent
import android.net.Uri
import android.os.Build
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
import androidx.compose.material3.OutlinedTextField
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
        // LAN passkey + temporary keys, refreshed from the registry so a restart
        // of the screen does not lose them (they live in prefs, not in memory).
        var lanKey by remember {
            mutableStateOf(StorageRootRepository.registry().lanPasskey)
        }
        var tempKeys by remember {
            mutableStateOf(StorageRootRepository.registry().aliveTemporaries(System.currentTimeMillis()))
        }
        // openp2p: the token is typed by the user (persisted privately), the node
        // name is what the server assigned after login — the only value a peer
        // may use as -peernode.
        var p2pTokenInput by remember { mutableStateOf(StorageRootRepository.p2pToken() ?: "") }
        var p2pNodeName by remember { mutableStateOf<String?>(null) }
        var transports by remember { mutableStateOf(emptyList<com.jingjiangze.otgdrivebridge.network.Transport>()) }
        var status by remember { mutableStateOf("未启动") }
        val isRunning by WebDavService.isRunning.collectAsState()

        val picker = androidx.activity.compose.rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocumentTree()
        ) { uri: Uri? ->
            val treeGrant = TreeGrant(context)
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
                            // MANAGE_EXTERNAL_STORAGE and its settings screen only
                            // exist from API 30; below that SAF is the only route.
                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                                val intent = Intent(
                                    Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION,
                                    Uri.parse("package:$packageName")
                                )
                                startActivity(intent)
                                status = "请在系统设置中授予「所有文件访问权限」，然后用路径模式选择 /storage/…"
                            } else {
                                status = "Android 11 以下没有「所有文件访问权限」，请使用左侧的 SAF 目录授权"
                            }
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
                        status = "已轮换凭据，运行中的服务立即生效（每请求重读）"
                    }) { Text("轮换密码") }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("局域网仅密钥（免账户）", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "同一局域网内的设备不验证账户，只用这把口令即可映射。口令由本机生成、可轮换；" +
                            "公网/异地来源永远不认这把口令（按来源 IP 判定，不做任何 DNS 反查）。",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            val key = StorageRootRepository.rotateLanPasskey()
                            lanKey = key
                            status = "已生成局域网密钥：${key.password}"
                        }) { Text("生成/轮换局域网密钥") }
                        OutlinedButton(onClick = {
                            StorageRootRepository.saveLanPasskey(null)
                            lanKey = null
                            status = "局域网密钥已吊销"
                        }) { Text("吊销") }
                    }
                    lanKey?.let {
                        Spacer(Modifier.height(8.dp))
                        Text("用户名：${it.username}", fontFamily = FontFamily.Monospace)
                        Text("密钥：${it.password}", fontFamily = FontFamily.Monospace)
                        Text(
                            "Windows 侧直接映射 http://<本机IP>:8080/ 时输入这对即可，无需主账户。",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("临时密钥（远程/借用，到期自动失效）", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "给远程设备（P2P 借用方）的一次性限时凭据。到点自动作废，不碰主账户。" +
                            "任何来源都可使用（与局域网密钥相反），所以时限是它的护栏。",
                        style = MaterialTheme.typography.bodySmall
                    )
                    Spacer(Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = {
                            val issued = StorageRootRepository.registry()
                            val entry = com.jingjiangze.otgdrivebridge.security.CredentialRegistry.newTemporary(
                                ttlMillis = 2L * 60 * 60 * 1000
                            )
                            StorageRootRepository.saveTemporaryKeys(issued.aliveTemporaries(System.currentTimeMillis()) + entry)
                            tempKeys = StorageRootRepository.registry().aliveTemporaries(System.currentTimeMillis())
                            status = "已签发 ${entry.username}（2 小时有效）：${entry.password}"
                        }) { Text("签发 2 小时密钥") }
                    }
                    if (tempKeys.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        tempKeys.forEach { key ->
                            Text(
                                "${key.username} / ${key.password} — 剩余 " +
                                    "${((key.expiresAtMillis ?: 0L) - System.currentTimeMillis()) / 60000} 分钟",
                                fontFamily = FontFamily.Monospace,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("异地接入（openp2p，可选）", style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(4.dp))
                    val engine = remember { com.jingjiangze.otgdrivebridge.p2p.P2pEngineFactory.create() }
                    if (engine == null) {
                        Text(
                            "这个构建没有内嵌 openp2p 引擎（构建时 app/libs/openp2p.aar 不存在）。" +
                                "带引擎的包由 Actions 的 openp2p AAR 工作流产出 AAR 后自动注入。",
                            style = MaterialTheme.typography.bodySmall
                        )
                    } else {
                        Text(
                            "手机作为被访问方只需登录 openp2p 网络；异地电脑用 openp2p 拨到本机节点名，" +
                                "再把 WebDAV 指向 127.0.0.1:<映射端口>。仅私有 P2P（不中继他人流量）。",
                            style = MaterialTheme.typography.bodySmall
                        )
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = p2pTokenInput,
                            onValueChange = { p2pTokenInput = it.trim() },
                            label = { Text("openp2p 网络 token（数字）") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        Spacer(Modifier.height(8.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = {
                                val token = p2pTokenInput
                                if (token.isEmpty() || token.any { c -> !c.isDigit() }) {
                                    status = "token 必须是纯数字（非数字会被解析成 0，登录静默失败）"
                                } else {
                                    StorageRootRepository.saveP2pToken(token)
                                    status = "openp2p 登录中…"
                                    CoroutineScope(Dispatchers.Main).launch {
                                        val baseDir = getExternalFilesDir(null)?.absolutePath
                                            ?: filesDir.absolutePath
                                        val ok = kotlinx.coroutines.withContext(Dispatchers.IO) {
                                            engine.start(baseDir, token, 0)
                                        }
                                        if (ok) {
                                            val node = engine.nodeName()
                                            p2pNodeName = node
                                            status = if (node != null) {
                                                "openp2p 已登录，节点名：$node"
                                            } else {
                                                "openp2p 已登录，但读不到节点名"
                                            }
                                        } else {
                                            status = "openp2p 登录失败（检查 token 与网络）"
                                        }
                                    }
                                }
                            }) { Text("登录 openp2p") }
                        }
                        p2pNodeName?.let { node ->
                            Spacer(Modifier.height(8.dp))
                            Text("节点名：$node", fontFamily = FontFamily.Monospace)
                            Text(
                                "异地电脑执行：openp2p -node <本机名> -token <同上> -peernode $node " +
                                    "-srcport <本地口> -dstip 127.0.0.1 -dstport 8080 -protocol tcp -sharebandwidth 0",
                                style = MaterialTheme.typography.bodySmall
                            )
                            OutlinedButton(onClick = {
                                clipboard.setText(androidx.compose.ui.text.AnnotatedString(node))
                                status = "已复制节点名"
                            }) { Text("复制节点名") }
                        }
                    }
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
                        } else if (!TreeGrant(context).isGrantValid(current)) {
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
