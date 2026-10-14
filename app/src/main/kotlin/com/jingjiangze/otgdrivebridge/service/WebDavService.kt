package com.jingjiangze.otgdrivebridge.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import com.jingjiangze.otgdrivebridge.MainActivity
import com.jingjiangze.otgdrivebridge.R
import com.jingjiangze.otgdrivebridge.security.DigestAuthenticator
import com.jingjiangze.otgdrivebridge.server.WebDavEngine
import com.jingjiangze.otgdrivebridge.storage.SafDavStorage
import com.jingjiangze.otgdrivebridge.storage.StorageRoot
import com.jingjiangze.otgdrivebridge.storage.StorageRootKind
import com.jingjiangze.otgdrivebridge.storage.StorageRootRepository
import com.jingjiangze.otgdrivebridge.storage.TreeGrant
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Foreground service that hosts the WebDAV core.
 *
 * Why a foreground service: Android's Doze mode suspends network access and
 * ignores wake locks for background apps, which would drop the mapped drive
 * whenever the screen turns off. A `dataSync` foreground service with a visible
 * notification is the documented way to keep the listener alive, and the
 * notification doubles as the user's always-visible stop button.
 *
 * The service never starts itself and never exposes the port to the Internet on
 * its own — see `docs/dual-transport-plan.md` §4.5 for the exposure policy.
 */
class WebDavService : android.app.Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var wakeLock: PowerManager.WakeLock? = null
    private var engine: WebDavEngine? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                setRunning(false)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> startServer()
        }
        return START_STICKY
    }

    private fun startServer() {
        startForeground(NOTIFICATION_ID, buildNotification("正在共享…"))
        acquireWakeLock()

        val root = StorageRootRepository.load()
        if (root == null || !TreeGrant(this).isGrantValid(root)) {
            setRunning(false)
            publish("共享根目录不可用，请在 App 中重新选择")
            stopSelf()
            return
        }

        val storageProvider = {
            when (root.kind) {
                StorageRootKind.TREE_URI -> SafDavStorage(this, root)
                StorageRootKind.MANAGED_PATH -> SafDavStorage(this, root)
            }
        }

        val credentials = StorageRootRepository.credentials()
        val engine = WebDavEngine(
            storageProvider = storageProvider,
            credentialProvider = {
                credentials?.let { (user, pass) -> DigestAuthenticator.Credentials(user, pass) }
            }
        )
        this.engine = engine

        scope.launch {
            val lanAddress = com.jingjiangze.otgdrivebridge.network.LanAddressResolver(this@WebDavService)
                .currentAddress()
            val result = engine.start(lanAddress = lanAddress)
            if (result.isSuccess) {
                setRunning(true)
                publish("运行中：${engine.state.value.displayAddress}")
            } else {
                setRunning(false)
                publish("启动失败：${result.exceptionOrNull()?.message}")
                stopSelf()
            }
        }
    }

    /** Re-checks the storage root and the network address after a network change. */
    fun onNetworkChanged() {
        scope.launch {
            val root = StorageRootRepository.load() ?: return@launch
            val treeGrant = TreeGrant(this@WebDavService)
            if (!treeGrant.isGrantValid(root)) {
                publish("U 盘授权已失效，服务已停止")
                stopSelf()
                return@launch
            }
            val address = com.jingjiangze.otgdrivebridge.network.LanAddressResolver(this@WebDavService)
                .currentAddress()
            engine?.refreshAddress(address)
        }
    }

    override fun onDestroy() {
        engine?.stop()
        engine = null
        releaseWakeLock()
        setRunning(false)
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun acquireWakeLock() {
        if (wakeLock != null) return
        val power = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "otg-bridge:webdav").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        wakeLock?.takeIf { it.isHeld }?.release()
        wakeLock = null
    }

    private fun publish(message: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(message))
    }

    private fun buildNotification(message: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 1, Intent(this, WebDavService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("OTG Drive Bridge")
            .setContentText(message)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(0, "停止共享", stopIntent)
            .build()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "WebDAV 共享状态",
                NotificationManager.IMPORTANCE_LOW
            ).apply { description = "显示共享地址与停止按钮" }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    companion object {
        const val CHANNEL_ID = "otg-bridge-status"
        const val NOTIFICATION_ID = 1001
        const val ACTION_STOP = "com.jingjiangze.otgdrivebridge.STOP"

        /** The single source of truth for the running state, read by the UI. */
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning.asStateFlow()

        fun setRunning(running: Boolean) {
            _isRunning.value = running
        }

        fun start(context: Context) {
            val intent = Intent(context, WebDavService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, WebDavService::class.java))
        }
    }
}
