package com.jingjiangze.otgdrivebridge.network

/**
 * A transport the WebDAV core can be reached through.
 *
 * Three transports share one WebDAV core (see `docs/dual-transport-plan.md`):
 *  - [LAN]      — the phone's own address, zero cost, default
 *  - [VIRTUAL_LAN] — a tailnet address or a NetBird `expose` URL (443 + cert)
 *  - [TUNNEL]   — an Internet tunnel landing on 443 with a valid certificate
 *
 * The UI shows one card per transport, ordered by [priority]; the user copies
 * the URL or scans the QR. The engine itself never changes.
 */
data class Transport(
    val kind: TransportKind,
    val label: String,
    val url: String,
    val https: Boolean,
    val priority: Int,
    val detail: String = "",
    val warning: String? = null
) {
    val isSecure: Boolean get() = https
}

enum class TransportKind {
    /** Same Wi-Fi / phone hotspot: `http://<ip>:8080/`. */
    LAN,

    /** Tailnet / NetBird expose: `https://...` on 443 with a valid certificate. */
    VIRTUAL_LAN,

    /** Cloudflare named tunnel or frp + Caddy: `https://<your-domain>/`. */
    TUNNEL
}

/** Result of probing which transports are currently usable. */
data class TransportProbe(
    val transports: List<Transport>,
    val lanAddress: String?,
    val checkedAtMillis: Long
) {
    val preferred: Transport? get() = transports.minByOrNull { it.priority }
}
