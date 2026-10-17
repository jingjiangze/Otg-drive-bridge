package com.jingjiangze.otgdrivebridge.webdav

/**
 * What a `Range` request header (RFC 9110 §14.1) asked for, after parsing.
 *
 * Three outcomes because the RFC distinguishes three — conflating them is how
 * a server ends up answering a malformed header with 416, which makes a
 * client discard its cache for no reason:
 *
 *  - [Ignore]: the header cannot be honoured as written (wrong unit, more
 *    than one range, syntax error). §14.2: "A server that does not understand
 *    or cannot satisfy the Range header field MUST ignore it" — the response
 *    is the whole resource with 200. Multi-range is deliberately in this
 *    bucket: this server answers one range per request, and a client that
 *    wants several issues several requests (which is what every real client
 *    of this bridge does — see the note on [parse]).
 *  - [Unsatisfiable]: the header is well-formed but no part of it falls
 *    within the resource (§14.4.1.3: first-position at/after the end). That
 *    is a 416 whose Content-Range is `bytes * / length`, and it is the answer
 *    that tells a resuming client "the file shrank underneath you — re-download".
 *    (The literal header value has no spaces — `bytes` `*` `/` `length` — and is
 *    spelled with a space here only because `*` followed by `/` would close this
 *    very comment block.)
 *  - [Spec]: exactly one inclusive byte interval to serve as 206.
 */
sealed class RangeOutcome {
    object Ignore : RangeOutcome()
    object Unsatisfiable : RangeOutcome()

    /** Inclusive interval `from..to`, guaranteed `0 <= from <= to < total`. */
    data class Spec(val from: Long, val to: Long) : RangeOutcome()
}

/**
 * Parses a single-range `bytes=` header against a resource of known length.
 *
 * Why this lives next to [WebDavPaths] instead of inside the handler: it is
 * arithmetic over strings with no Android or Ktor dependency, so CI tests it
 * on a plain JVM — and the handler then only has to translate outcomes into
 * status codes. The three-way distinction above is exactly the part that a
 * hand-rolled `split('-')` inside the handler gets wrong.
 *
 * Single-range only, on purpose: rclone's parallel download, MRxDAV's seek
 * reads and CfApi/WinFSP hydration all send one range per request; the only
 * clients that send multi-range want a `multipart/byteranges` body, which no
 * consumer of this bridge can parse — answering one would be inventing a
 * format the callers cannot use. So multi-range falls to [Ignore] (full 200),
 * which every caller can use.
 */
object ByteRange {

    fun parse(header: String?, totalLength: Long): RangeOutcome {
        val value = header?.trim() ?: return RangeOutcome.Ignore
        if (!value.startsWith("bytes=", ignoreCase = true)) return RangeOutcome.Ignore
        val spec = value.substring("bytes=".length).trim()
        if (spec.isEmpty()) return RangeOutcome.Ignore
        if (spec.contains(',')) return RangeOutcome.Ignore
        return parseSpec(spec, totalLength)
    }

    private fun parseSpec(spec: String, total: Long): RangeOutcome {
        val dash = spec.indexOf('-')
        if (dash < 0) return RangeOutcome.Ignore
        val first = spec.substring(0, dash).trim()
        val last = spec.substring(dash + 1).trim()
        // `bytes=-` names nothing at all; §14.1 requires at least one side.
        if (first.isEmpty() && last.isEmpty()) return RangeOutcome.Ignore
        // The ABNF is `1DIGIT` on both sides: a leading `+`, a hex form or a
        // thousands separator is not a range position. `toLongOrNull` alone
        // would accept `+5` and silently serve a wrong slice, so the shape is
        // checked before the value.
        if (first.isNotEmpty() && !first.isDigits()) return RangeOutcome.Ignore
        if (last.isNotEmpty() && !last.isDigits()) return RangeOutcome.Ignore

        if (first.isEmpty()) {
            // suffix form: the last N bytes. N=0 is unsatisfiable, not a
            // zero-length range — §14.1.1: "no bytes can be selected".
            val suffix = last.toLongOrNull() ?: return RangeOutcome.Ignore
            if (suffix <= 0 || total <= 0) return RangeOutcome.Unsatisfiable
            return RangeOutcome.Spec(maxOf(0L, total - suffix), total - 1)
        }

        val from = first.toLongOrNull() ?: return RangeOutcome.Ignore
        if (from >= total) return RangeOutcome.Unsatisfiable

        val to = if (last.isEmpty()) total - 1 else (last.toLongOrNull() ?: return RangeOutcome.Ignore)
        // `bytes=10-5`: reversed pair is unsatisfiable (§14.1.1 requires
        // first-pos <= last-pos), not a malformed header.
        if (to < from) return RangeOutcome.Unsatisfiable
        // `bytes=10-99999` on a 40-byte file is clamped, not rejected: the
        // end may exceed the length, only the start may not (RFC 9110 §14.1.2).
        return RangeOutcome.Spec(from, minOf(to, total - 1))
    }

    private fun String.isDigits(): Boolean = all { it in '0'..'9' }
}
