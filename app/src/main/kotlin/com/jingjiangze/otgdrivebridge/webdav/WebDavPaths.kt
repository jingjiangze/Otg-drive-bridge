package com.jingjiangze.otgdrivebridge.webdav

/**
 * Pure-JVM WebDAV path handling.
 *
 * Every incoming request path is normalised through [normalize] before it is
 * mapped onto a storage handle. The rules mirror the reference implementation
 * but are stated here as testable invariants:
 *
 *  1. The path is split on "/" into segments; empty segments are dropped.
 *  2. Every segment is percent-decoded.
 *  3. A path is **rejected** (returns null) when any decoded segment is empty,
 *     ".", "..", or contains a path separator or a NUL byte.
 *
 * Rule 3 is the traversal defence: a client cannot escape the shared root with
 * "..", an encoded "..", a doubled slash, a backslash, or a NUL truncation.
 * All checks happen on the *decoded* value so "%2e%2e" cannot slip through.
 */
object WebDavPaths {

    /** Rejects the path; returns null. Kept as a value so callers can map it. */
    fun normalize(path: String?): List<String>? {
        if (path == null) return null
        val trimmed = path.trim()
        if (trimmed.isEmpty()) return emptyList()
        val raw = trimmed.split('/')
        val segments = ArrayList<String>(raw.size)
        for (piece in raw) {
            if (piece.isEmpty()) continue
            val decoded = percentDecode(piece)
            if (!isSafeSegment(decoded)) return null
            segments += decoded
        }
        return segments
    }

    /** True when [path] normalises to exactly the shared root. */
    fun isRoot(path: String?): Boolean = normalize(path)?.isEmpty() == true

    /** Rejects traversal-unsafe segments. Public for direct unit testing. */
    fun isSafeSegment(segment: String): Boolean {
        if (segment.isEmpty()) return false
        if (segment == "." || segment == "..") return false
        if (segment.indexOf('/') >= 0) return false
        if (segment.indexOf('\\') >= 0) return false
        if (segment.indexOf('\u0000') >= 0) return false
        // Windows device names would break client-side path building.
        if (WINDOWS_RESERVED.any { segment.equals(it, ignoreCase = true) }) return false
        return true
    }

    /**
     * Percent-decodes a single path segment. `+` is *not* decoded to a space,
     * because path segments are not query strings.
     *
     * Escapes encode *bytes*, not characters: `%E4%B8%AD` is one three-byte
     * UTF-8 sequence. A run of decoded bytes is therefore accumulated and
     * decoded as UTF-8 as a whole — converting each byte to a `Char` on its own
     * would turn every non-ASCII name into mojibake.
     */
    fun percentDecode(segment: String): String {
        if (segment.indexOf('%') < 0) return segment
        val out = StringBuilder(segment.length)
        val pendingBytes = java.io.ByteArrayOutputStream(4)
        fun flushBytes() {
            if (pendingBytes.size() > 0) {
                out.append(String(pendingBytes.toByteArray(), Charsets.UTF_8))
                pendingBytes.reset()
            }
        }
        var i = 0
        while (i < segment.length) {
            val c = segment[i]
            if (c == '%' && i + 2 < segment.length) {
                val hex = segment.substring(i + 1, i + 3)
                val decoded = hex.toIntOrNull(16)
                if (decoded != null) {
                    pendingBytes.write(decoded)
                    i += 3
                    continue
                }
            }
            flushBytes()
            out.append(c)
            i++
        }
        flushBytes()
        return out.toString()
    }

    /**
     * Builds the request URI a client should send back, percent-encoding each
     * segment while preserving "/" separators. Used for `href` in PROPFIND.
     */
    fun encodeHref(segments: List<String>): String =
        segments.joinToString("/", prefix = "/") { percentEncode(it) }

    /** Encodes a single segment, leaving unreserved characters intact. */
    fun percentEncode(segment: String): String {
        val out = StringBuilder(segment.length * 2)
        for (ch in segment) {
            when {
                ch in UNRESERVED -> out.append(ch)
                ch == ' ' -> out.append("%20")
                else -> {
                    val bytes = ch.toString().toByteArray(Charsets.UTF_8)
                    for (b in bytes) {
                        out.append('%')
                        out.append(HEX[(b.toInt() shr 4) and 0xF])
                        out.append(HEX[b.toInt() and 0xF])
                    }
                }
            }
        }
        return out.toString()
    }

    /** Lower-cases an extension without the dot, for MIME lookup. */
    fun extensionOf(name: String): String =
        name.substringAfterLast('.', "").lowercase()

    private val HEX = "0123456789ABCDEF".toCharArray()
    private const val UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

    /** Names that Windows cannot address on a mapped drive. */
    private val WINDOWS_RESERVED = setOf(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    )
}
