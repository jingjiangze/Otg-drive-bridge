package com.jingjiangze.otgdrivebridge.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Cloudflare Tunnel (named tunnel, user's own domain).
 *
 * Chosen over a plain `cloudflared --url` quick tunnel because a **named**
 * tunnel gets a stable hostname on the user's domain with Universal SSL, so the
 * Windows mapping never changes and no interstitial page is inserted.
 *
 * Known limits of the free tier that this class surfaces to the user rather
 * than hiding (from Cloudflare's own docs):
 *  - **100 MB maximum upload per request**
 *  - 100 s read / 30 s write HTTP timeouts
 *  - WebDAV must run with `--no-chunked-encoding`, otherwise PUT is rejected
 *
 * For files beyond those limits the app points the user at frp + Caddy.
 */
class CloudflareTunnelExposure(
    private val processRunner: ProcessRunner,
    private val hostname: String,
    private val cloudflaredPath: String = "cloudflared"
) : InternetExposure {

    override val id: String = "cloudflare-tunnel"

    private val mutex = Mutex()
    private var endpoint: PublicEndpoint? = null

    override val isActive: Boolean get() = endpoint != null

    override suspend fun isAvailable(): Boolean = withContext(Dispatchers.IO) {
        val result = processRunner.run(listOf(cloudflaredPath, "--version"))
        result.ok && result.stdout.contains("cloudflared", ignoreCase = true)
    }

    override suspend fun start(localPort: Int): Result<PublicEndpoint> = mutex.withLock {
        withContext(Dispatchers.IO) {
            val config = writeTunnelConfig(localPort)
            val result = processRunner.run(
                listOf(
                    cloudflaredPath,
                    "tunnel",
                    "--config", config,
                    "--no-chunked-encoding",
                    "run",
                    TUNNEL_NAME
                )
            )
            if (!result.ok && endpoint == null) {
                return@withContext Result.failure(
                    ExposureUnavailableException(
                        result.stderr.ifBlank { "cloudflared failed (exit ${result.exitCode})" }
                    )
                )
            }
            val public = PublicEndpoint(
                url = "https://$hostname/",
                https = true,
                port = 443,
                requiresExtraAuth = false,
                notes = "Free tier: 100 MB per upload, ${TUNNEL_READ_TIMEOUT_S}s read timeout. " +
                    "Large files need frp + Caddy."
            )
            endpoint = public
            Result.success(public)
        }
    }

    override suspend fun stop() = mutex.withLock {
        withContext(Dispatchers.IO) {
            if (endpoint == null) return@withContext
            runCatching { processRunner.run(listOf(cloudflaredPath, "tunnel", "cleanup", TUNNEL_NAME)) }
            endpoint = null
        }
    }

    /** Writes a minimal ingress config mapping the hostname to the local port. */
    private fun writeTunnelConfig(localPort: Int): String {
        val path = "${System.getProperty("java.io.tmpdir")}/otg-bridge-cloudflared.yml"
        val body = """
            tunnel: $TUNNEL_NAME
            credentials-file: ${System.getProperty("user.home")}/.cloudflared/${TUNNEL_NAME}.json
            ingress:
              - hostname: $hostname
                service: http://localhost:$localPort
              - service: http_status:404
        """.trimIndent()
        java.io.File(path).writeText(body)
        return path
    }

    companion object {
        const val TUNNEL_NAME = "otg-drive-bridge"
        const val TUNNEL_READ_TIMEOUT_S = 100
        const val MAX_UPLOAD_MB = 100
    }
}
