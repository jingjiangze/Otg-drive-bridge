package com.jingjiangze.otgdrivebridge.security

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap

/**
 * HTTP Digest Access Authentication (RFC 2617 §3.2.2, MD5 qop=auth).
 *
 * Why Digest instead of Basic for the Windows network-drive scenario:
 *  - Basic over plain HTTP sends the password recoverably, and Windows' WebClient
 *    blocks it by default (`BasicAuthLevel` defaults to 2 = HTTPS only), while
 *    Microsoft 365 blocks Basic Auth entirely.
 *  - Digest never transmits the password; only HA1/HA2/response hashes.
 *  - RFC 2617 defines a fixed realm format, which the redirector accepts.
 *
 * Nonce freshness: a nonce issued here is stamped with the wall-clock second at
 * issue time. A nonce older than [NONCE_LIFETIME_SECONDS] triggers a
 * "stale=true" challenge so the client retries transparently.
 *
 * Thread safety: [NonceTracker] and [attempts] are concurrent; [MessageDigest]
 * instances are created per call.
 */
class DigestAuthenticator(private val realm: String = DEFAULT_REALM) {

    /** Credentials the server validates incoming `Authorization` headers against. */
    data class Credentials(val username: String, val password: String)

    /** Parsed `Authorization: Digest ...` fields. */
    data class DigestHeader(
        val username: String,
        val realm: String,
        val nonce: String,
        val uri: String,
        val response: String,
        val qop: String?,
        val nc: String?,
        val cnonce: String?,
        val opaque: String?
    )

    /** Per-nonce replay/opaque bookkeeping. */
    private class NonceTracker {
        @Volatile var lastSeenMillis: Long = 0L
        @Volatile var opaque: String = ""
        /** Highest nonce-count accepted so far (guards against replay). */
        val maxNcSeen = java.util.concurrent.atomic.AtomicLong(0L)
    }

    private val trackers = ConcurrentHashMap<String, NonceTracker>()
    private val random = SecureRandom()

    /** Max requests replayed with one nonce before it is rotated. */
    private val maxNonceCount = 200

    /** How many distinct nonces we keep alive (bounded to avoid unbounded growth). */
    private val maxTrackedNonces = 512

    fun challenge(stale: Boolean = false): String {
        val nonce = newNonce()
        val opaque = newOpaque()
        trackers[nonce] = NonceTracker().also {
            it.lastSeenMillis = System.currentTimeMillis()
            it.opaque = opaque
        }
        pruneIfNeeded()
        return buildString {
            append("Digest realm=\"").append(realm).append("\", ")
            append("qop=\"auth\", ")
            append("nonce=\"").append(nonce).append("\", ")
            append("opaque=\"").append(opaque).append("\"")
            if (stale) append(", stale=true")
        }
    }

    /**
     * Verifies an incoming `Authorization: Digest` header against [expected].
     *
     * @return true when the response hash matches and the request is fresh.
     */
    fun verify(header: DigestHeader, expected: Credentials, method: String): Boolean {
        if (!header.realm.equals(realm, ignoreCase = true)) return false
        if (header.username != expected.username) return false
        if (header.response.isBlank()) return false

        val tracker = trackers[header.nonce] ?: return false
        if (System.currentTimeMillis() - tracker.lastSeenMillis > NONCE_LIFETIME_MILLIS) return false

        // RFC 2616: qop must be echoed; the nonce-count must not be replayed.
        val qop = header.qop?.lowercase()
        if (qop != null && qop != "auth") return false
        if (qop == "auth") {
            if (header.nc.isNullOrBlank() || header.cnonce.isNullOrBlank()) return false
            if (!isNcIncreasing(tracker, header.nc)) return false
        }
        if (!header.opaque.isNullOrBlank() && header.opaque != tracker.opaque) return false

        val expectedResponse = computeResponse(
            username = expected.username,
            password = expected.password,
            method = method,
            uri = header.uri,
            nonce = header.nonce,
            nc = header.nc ?: "00000001",
            cnonce = header.cnonce ?: "",
            qop = qop
        )
        if (!constantTimeEquals(expectedResponse, header.response)) return false

        tracker.lastSeenMillis = System.currentTimeMillis()
        return true
    }

    /** Rejects replayed nonce-counts for a given nonce. */
    private fun isNcIncreasing(tracker: NonceTracker, nc: String): Boolean {
        val value = nc.trim().toLongOrNull(16) ?: return false
        val previous = tracker.maxNcSeen.getAndSet(maxOf(tracker.maxNcSeen.get(), value))
        return value > previous || (previous == 0L && value == 1L)
    }

    /**
     * Computes RFC 2616 §3.2.2.1 `response`:
     * `KD(HA1:nonce:nc:cnonce:qop, HA2)` where HA1 = MD5(user:realm:pass),
     * HA2 = MD5(method:uri).
     */
    fun computeResponse(
        username: String,
        password: String,
        method: String,
        uri: String,
        nonce: String,
        nc: String = "00000001",
        cnonce: String = "",
        qop: String? = "auth"
    ): String {
        val ha1 = md5("$username:$realm:$password")
        val ha2 = md5("${method.uppercase()}:$uri")
        return if (qop.isNullOrEmpty()) {
            md5("$ha1:$nonce:$ha2")
        } else {
            md5("$ha1:$nonce:$nc:$cnonce:$qop:$ha2")
        }
    }

    private fun md5(input: String): String {
        val digest = MessageDigest.getInstance("MD5")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return buildString(bytes.size * 2) {
            for (b in bytes) append(HEX[(b.toInt() shr 4) and 0xF]).append(HEX[b.toInt() and 0xF])
        }
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var diff = 0
        for (i in a.indices) diff = diff or (a[i].code xor b[i].code)
        return diff == 0
    }

    private fun newNonce(): String {
        val bytes = ByteArray(16).also { random.nextBytes(it) }
        return Base64.getEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun newOpaque(): String {
        val bytes = ByteArray(8).also { random.nextBytes(it) }
        return Base64.getEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun pruneIfNeeded() {
        if (trackers.size <= maxTrackedNonces) return
        // Drop the least-recently-seen trackers first.
        trackers.entries
            .sortedBy { it.value.lastSeenMillis }
            .take(trackers.size - maxTrackedNonces / 2)
            .forEach { trackers.remove(it.key) }
    }

    companion object {
        const val DEFAULT_REALM = "OTG Drive Bridge"

        /** RFC 2617 nonce lifetime — after this the server replies `stale=true`. */
        const val NONCE_LIFETIME_SECONDS = 300L
        private val NONCE_LIFETIME_MILLIS = NONCE_LIFETIME_SECONDS * 1000L

        private val HEX = "0123456789abcdef".toCharArray()

        /**
         * Parses an `Authorization: Digest ...` header value into [DigestHeader].
         * Returns null when the value is not a well-formed Digest challenge response.
         */
        fun parseHeader(value: String?): DigestHeader? {
            if (value.isNullOrBlank()) return null
            val commaParts = value.split(',')
            if (commaParts.firstOrNull()?.trim()?.startsWith("Digest", ignoreCase = true) != true) return null
            val fields = LinkedHashMap<String, String>()
            for (part in commaParts) {
                val eq = part.indexOf('=')
                if (eq <= 0) continue
                val key = part.substring(0, eq).trim().removePrefix("Digest").trim()
                val raw = part.substring(eq + 1).trim()
                if (key.isEmpty()) continue
                fields[key.lowercase()] = if (raw.startsWith("\"") && raw.endsWith("\"") && raw.length >= 2) {
                    raw.substring(1, raw.length - 1).replace("\\\"", "\"").replace("\\\\", "\\")
                } else {
                    raw
                }
            }
            val username = fields["username"] ?: return null
            val realm = fields["realm"] ?: return null
            val nonce = fields["nonce"] ?: return null
            val uri = fields["uri"] ?: return null
            val response = fields["response"] ?: return null
            return DigestHeader(
                username = username,
                realm = realm,
                nonce = nonce,
                uri = uri,
                response = response,
                qop = fields["qop"],
                nc = fields["nc"],
                cnonce = fields["cnonce"],
                opaque = fields["opaque"]
            )
        }
    }
}
