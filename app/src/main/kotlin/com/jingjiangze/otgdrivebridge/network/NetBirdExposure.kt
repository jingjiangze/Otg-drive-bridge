package com.jingjiangze.otgdrivebridge.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * NetBird `expose` — the audit's first choice for the Internet path.
 *
 * Why this over a tunnel or a plain tailnet IP (see `docs/dual-transport-plan.md`):
 *  - One command yields `https://<name>.proxy.<domain>`: **port 443, a publicly
 *    trusted certificate, and optional authentication**.
 *  - Windows' native WebDAV mapping therefore works without registry changes:
 *    no port problem, no untrusted-certificate problem, no Basic-auth block.
 *  - The official Tailscale Android app cannot do this (`serve`/`funnel` are
 *    compiled out on Android), so a plain `100.x` address is not enough.
 *
 * The CLI is invoked as an external process — NetBird ships an Android client
 * and a CLI; this class only orchestrates it and parses the URL it prints.
 * When NetBird is not installed, [isAvailable] is false and the UI hides the
 * card instead of failing.
 */
class NetBirdExposure(
    private val processRunner: ProcessRunner,
    private val netbirdPath: String = "netbird"
) : InternetExposure {

    override val id: String = "netbird-expose"

    private val mutex = Mutex()
    private var endpoint: PublicEndpoint? = null

    override val isActive: Boolean get() = endpoint != null

    override suspend fun isAvailable(): Boolean = withContext(Dispatchers.IO) {
        val result = processRunner.run(listOf(netbirdPath, "version"))
        result.ok && result.stdout.contains("netbird", ignoreCase = true)
    }

    override suspend fun start(localPort: Int): Result<PublicEndpoint> = mutex.withLock {
        withContext(Dispatchers.IO) {
            // `netbird expose --port <local>` prints the public HTTPS URL on stdout.
            val result = processRunner.run(
                listOf(netbirdPath, "expose", "--port", localPort.toString())
            )
            if (!result.ok) {
                return@withContext Result.failure(
                    ExposureUnavailableException(
                        result.stderr.ifBlank { "netbird expose failed (exit ${result.exitCode})" }
                    )
                )
            }
            val url = parsePublicUrl(result.stdout)
                ?: return@withContext Result.failure(
                    ExposureUnavailableException(
                        "netbird expose did not report a public URL: ${result.stdout.take(200)}"
                    )
                )
            val public = PublicEndpoint(
                url = url,
                https = url.startsWith("https://"),
                requiresExtraAuth = false,
                notes = "Publicly reachable — NetBird reverse proxy domain"
            )
            endpoint = public
            Result.success(public)
        }
    }

    override suspend fun stop() = mutex.withLock {
        withContext(Dispatchers.IO) {
            if (endpoint == null) return@withContext
            runCatching { processRunner.run(listOf(netbirdPath, "expose", "--stop")) }
            endpoint = null
        }
    }

    /**
     * Extracts the first `https://…` URL from NetBird's output. The CLI prints
     * a banner plus the URL, so a plain scan for the scheme is the robust
     * approach; the alternative is to parse `URL:` lines.
     */
    internal fun parsePublicUrl(stdout: String): String? {
        val schemeMatch = Regex("https://[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+").find(stdout)
        return schemeMatch?.value?.trimEnd('.', ',', ')')
    }
}
