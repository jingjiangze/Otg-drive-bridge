package com.jingjiangze.otgdrivebridge.network

/**
 * Internet exposure, as an *ordered, replaceable* transport.
 *
 * The audit's conclusion was that the Internet path must land on **443 with a
 * valid certificate** — not merely "be reachable" — because Windows' native
 * WebDAV redirector rejects plain HTTP Basic auth and non-standard ports.
 *
 * This interface is the seam between the app and the mature infrastructure the
 * user asked us to reuse. Two implementations ship:
 *
 *  - [NetBirdExposure]  — `netbird expose`, which yields an `https://` URL on a
 *                         `proxy.<domain>` host (443 + valid certificate +
 *                         optional auth) in one command.
 *  - [CloudflareTunnelExposure] — a named tunnel on the user's own domain.
 *
 * Neither is bundled as a native library: the app invokes the installed CLI
 * through a process bridge and parses its output, which keeps the APK small and
 * lets each component be updated independently.
 */
interface InternetExposure {

    /** Identifies the transport in the UI. */
    val id: String

    /** True when the underlying CLI/tooling is installed and usable. */
    suspend fun isAvailable(): Boolean

    /**
     * Starts exposure of the local WebDAV port.
     *
     * @return the public URL (always https, always port 443) or a failure with a
     *         human-readable reason for the UI.
     */
    suspend fun start(localPort: Int): Result<PublicEndpoint>

    /** Stops exposure. Safe to call when not started. */
    suspend fun stop()

    /** True while exposure is active. */
    val isActive: Boolean
}

/** A public HTTPS endpoint the WebDAV core is reachable on. */
data class PublicEndpoint(
    val url: String,
    val https: Boolean = true,
    val port: Int = 443,
    val requiresExtraAuth: Boolean = false,
    val notes: String = ""
) {
    /** The exact string a user should map in Windows. */
    val mountUrl: String get() = url.trimEnd('/') + "/"
}

/** Raised when a transport cannot be used, with a reason fit for display. */
class ExposureUnavailableException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
