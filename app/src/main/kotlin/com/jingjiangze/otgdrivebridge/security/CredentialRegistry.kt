package com.jingjiangze.otgdrivebridge.security

/**
 * The two short-lived credential classes the scheme asks for:
 *
 *  - **LAN passkey** — same-Wi-Fi peers authenticate with this key alone. There
 *    is no account behind it: whoever holds the key and arrives from a
 *    site-local address is trusted. It is deliberately *not* accepted from a
 *    remote origin, so guessing one does not open the Internet path.
 *  - **Temporary key** — a time-boxed credential for a remote session
 *    (the P2P path). It works from any origin but dies at [expiresAtMillis],
 *    which is what makes it safe to hand to a device you do not own.
 *
 * Both are ordinary `Digest` credentials on the wire — the username is the key
 * name and the generated password *is* the key — so Windows' redirector, the
 * Go client and the interop harness keep working with zero protocol changes.
 * What this class adds is *which* credentials a given request may use,
 * decided from the request's origin and the wall clock.
 *
 * The registry is a pure value: serialization is a flat string, parsing is
 * total (any garbage line drops that entry, never the whole set), and the
 * caller supplies `now` so the expiry logic is testable without waiting.
 */
class CredentialRegistry private constructor(
    val lanPasskey: TimedCredential?,
    val temporaries: List<TimedCredential>
) {

    /** One credential with an optional expiry, as it is stored. */
    data class TimedCredential(
        val username: String,
        val password: String,
        val expiresAtMillis: Long?
    ) {
        fun isAlive(nowMillis: Long): Boolean = expiresAtMillis == null || nowMillis < expiresAtMillis

        fun toWire(): DigestAuthenticator.Credentials =
            DigestAuthenticator.Credentials(username, password)
    }

    /**
     * Credentials this [remoteHost] may present right now.
     *
     * The LAN passkey is gated by origin — a request from a public address
     * never sees it as an option, even if the hash would match. Temporary keys
     * are origin-free but time-boxed, which is the other half of the trade.
     * Expired entries are filtered rather than merely ignored, so callers can
     * use the same list for storage compaction.
     */
    fun acceptableCredentials(remoteHost: String, nowMillis: Long): List<DigestAuthenticator.Credentials> {
        val out = ArrayList<DigestAuthenticator.Credentials>(1 + temporaries.size)
        lanPasskey?.takeIf { it.isAlive(nowMillis) && IpTrust.isLocalOrigin(remoteHost) }?.let {
            out += it.toWire()
        }
        for (t in temporaries) {
            if (t.isAlive(nowMillis)) out += t.toWire()
        }
        return out
    }

    /** True when any temporary key is still alive — the UI uses it for "有 N 个有效". */
    fun aliveTemporaries(nowMillis: Long): List<TimedCredential> =
        temporaries.filter { it.isAlive(nowMillis) }

    companion object {
        /** Username the LAN passkey is published under (UI + prefs + server agree). */
        const val LAN_USERNAME = "lan"

        /** Prefix for generated temporary keys, kept distinct from the primary account. */
        const val TEMP_PREFIX = "tmp"

        val EMPTY = CredentialRegistry(null, emptyList())

        /**
         * Issues a LAN passkey: high-entropy, no account behind it, and by
         * default it does not expire — it lives until the user rotates it.
         * Pass [ttlMillis] to make it time-boxed like a temporary key.
         */
        fun newLanPasskey(ttlMillis: Long? = null, nowMillis: Long = System.currentTimeMillis()): TimedCredential =
            TimedCredential(
                username = LAN_USERNAME,
                password = CredentialGenerator.password(),
                expiresAtMillis = ttlMillis?.let { nowMillis + it }
            )

        /**
         * Issues a temporary remote key with a hard expiry. The username is
         * `tmp-<4 chars>` so the log shows *which* short key authenticated a
         * request without revealing the key itself. The suffix comes from its
         * own generator — [CredentialGenerator.password] enforces a 16-char
         * minimum, which would throw for a 4-char label.
         */
        fun newTemporary(ttlMillis: Long, nowMillis: Long = System.currentTimeMillis()): TimedCredential {
            val random = java.security.SecureRandom()
            val suffix = buildString(4) {
                repeat(4) { append(CredentialGenerator.ALPHABET[random.nextInt(CredentialGenerator.ALPHABET.length)]) }
            }
            return TimedCredential(
                username = "$TEMP_PREFIX-$suffix",
                password = CredentialGenerator.password(),
                expiresAtMillis = nowMillis + ttlMillis
            )
        }

        /**
         * One entry per line: `username|password|expiresAt` where the expiry is
         * `0` for "never". `|` cannot appear in a generated username or in
         * [CredentialGenerator.ALPHABET], so the split is unambiguous.
         */
        fun serialize(entry: TimedCredential): String =
            "${entry.username}|${entry.password}|${entry.expiresAtMillis ?: 0L}"

        fun serializeAll(entries: List<TimedCredential>): String =
            entries.joinToString("\n") { serialize(it) }

        /**
         * Parses [text] tolerantly: a line without all three fields, or with a
         * non-numeric expiry, is dropped instead of poisoning the whole set —
         * a half-written prefs value must not disable every key.
         */
        fun parseEntries(text: String?): List<TimedCredential> {
            if (text.isNullOrBlank()) return emptyList()
            return text.lineSequence()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .mapNotNull { line ->
                    val parts = line.split('|')
                    if (parts.size != 3) return@mapNotNull null
                    val username = parts[0]
                    val password = parts[1]
                    if (username.isEmpty() || password.isEmpty()) return@mapNotNull null
                    val expiry = parts[2].toLongOrNull() ?: return@mapNotNull null
                    TimedCredential(username, password, expiry.takeIf { it != 0L })
                }
                .toList()
        }

        /** Rebuilds a registry from the two persisted strings (LAN key line, temp list). */
        fun fromStored(lanPasskeyLine: String?, temporaryLines: String?): CredentialRegistry {
            val lan = parseEntries(lanPasskeyLine).firstOrNull { it.username == LAN_USERNAME }
            val temps = parseEntries(temporaryLines).filter { it.username.startsWith("$TEMP_PREFIX-") }
            return CredentialRegistry(lan, temps)
        }
    }
}

/**
 * Origin classification for the trust decision, deliberately literal-only.
 *
 * [IpTrust.isLocalOrigin] answers "is this a peer on the same network?"
 * **without any DNS**: a hostname, an IPv6 with a zone id, or a non-literal
 * spelling is never local. Reverse-resolving the peer would let an attacker
 * with a PTR record claim to be local, which is the whole security model, so
 * the check refuses to do name resolution at all.
 *
 * Accepted: the three RFC-1918 IPv4 blocks and the IPv6 unique-local
 * `fc00::/7` range. Deliberately **not** accepted:
 *
 *  - **Loopback.** A genuine peer on the network can never present a loopback
 *    source address; the only things that do are *local proxies* — cloudflared
 *    and netbird-expose run on the phone and forward to `127.0.0.1:8080`, so
 *    trusting loopback would hand the LAN passkey to the whole Internet the
 *    moment an exposure is active, and a future transport (e.g. an openp2p
 *    listener) could reintroduce the same hole. Same-device clients use the
 *    primary account instead; nothing real is lost.
 *  - **Link-local** (`169.254/16`, `fe80::/10`): every interface can talk to
 *    its own link-local space, the wrong place to hang trust on a phone with
 *    Wi-Fi, hotspot and cellular up at once.
 *  - **CGNAT** (`100.64/10`, the range NetBird/tailnets use): "reachable but
 *    private" is not "same Wi-Fi", which is the only thing the passkey means.
 */
object IpTrust {

    fun isLocalOrigin(host: String): Boolean {
        val h = host.trim().removePrefix("/").substringBefore('%').lowercase()
        if (h.isEmpty()) return false
        if (h.startsWith("fc") || h.startsWith("fd")) return isIpv6Literal(h)
        val octets = h.split('.')
        if (octets.size != 4) return false
        // An explicit loop, not forEach: inside a lambda `return false` only
        // escapes the lambda, so the validation below would run with `v`
        // defaulted and non-numeric octets sneaking past the range check.
        for (part in octets) {
            val v = part.toIntOrNull() ?: return false
            // Reject leading zeros ("010"): stacks disagree on how they parse,
            // and the server must never be more permissive than its clients.
            if (part.length > 1 && part[0] == '0') return false
            if (v !in 0..255) return false
        }
        val a = octets[0].toInt()
        val b = octets[1].toInt()
        // 10/8 · 192.168/16 · 172.16-31/12 — and nothing else.
        return a == 10 || (a == 192 && b == 168) || (a == 172 && b in 16..31)
    }

    /**
     * Shape-validates an IPv6 literal: groups of 1–4 hex digits separated by
     * colons, at most one `::` compression. This deliberately does not accept
     * every string made of hex digits and colons — "fcaef123" has no colon at
     * all and "fc00::abcd::" compresses twice; neither may be trusted.
     */
    private fun isIpv6Literal(host: String): Boolean {
        if (':' !in host) return false
        if (host.contains(":::")) return false
        val parts = host.split("::")
        if (parts.size > 2) return false
        val groups = if (parts.size == 2) {
            (parts[0].split(':') + parts[1].split(':')).filter { it.isNotEmpty() }
        } else {
            host.split(':').filter { it.isNotEmpty() }
        }
        // "fc00::" (compression at the end) legitimately yields no groups.
        return groups.all { it.length in 1..4 && it.all { c -> c in '0'..'9' || c in 'a'..'f' } }
    }
}
