package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/**
 * The `Range` header parser (RFC 9110 §14.1–§14.4).
 *
 * The three-way outcome split is what earns these tests: a malformed header
 * must NOT become a 416 (clients throw their cache away on 416), a range
 * past the end MUST be a 416 (that is how a resuming client learns the file
 * shrank), and a clampable range must clamp rather than fail. A parser that
 * only has `Some(start, end) | None` gets one of those three wrong, which is
 * why the type carries all three.
 */
class ByteRangeTest {

    @Test
    fun `no header is Ignore`() {
        assertEquals(RangeOutcome.Ignore, ByteRange.parse(null, 100))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("", 100))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("   ", 100))
    }

    @Test
    fun `a well formed single range yields the inclusive interval`() {
        assertEquals(RangeOutcome.Spec(0, 9), ByteRange.parse("bytes=0-9", 40))
        assertEquals(RangeOutcome.Spec(5, 5), ByteRange.parse("bytes=5-5", 40))
    }

    @Test
    fun `an open ended range runs to the last byte`() {
        assertEquals(RangeOutcome.Spec(10, 39), ByteRange.parse("bytes=10-", 40))
    }

    @Test
    fun `a suffix range counts back from the end`() {
        assertEquals(RangeOutcome.Spec(35, 39), ByteRange.parse("bytes=-5", 40))
        // The suffix is clamped to the resource, not rejected: more bytes than
        // exist simply means "the whole file".
        assertEquals(RangeOutcome.Spec(0, 2), ByteRange.parse("bytes=-5", 3))
        assertEquals(RangeOutcome.Spec(0, 0), ByteRange.parse("bytes=-1", 1))
    }

    @Test
    fun `an end past the resource clamps instead of failing`() {
        // RFC 9110 §14.1.2: the last-position may exceed the length; only the
        // first-position may not.
        assertEquals(RangeOutcome.Spec(0, 39), ByteRange.parse("bytes=0-100", 40))
        assertEquals(RangeOutcome.Spec(38, 39), ByteRange.parse("bytes=38-99", 40))
    }

    @Test
    fun `a first position at or past the end is Unsatisfiable`() {
        // The resuming client's signal to re-download — this must be 416, not
        // a silent 200.
        assertEquals(RangeOutcome.Unsatisfiable, ByteRange.parse("bytes=40-", 40))
        assertEquals(RangeOutcome.Unsatisfiable, ByteRange.parse("bytes=99-100", 40))
        assertEquals(RangeOutcome.Unsatisfiable, ByteRange.parse("bytes=-0", 40))
        assertEquals(RangeOutcome.Unsatisfiable, ByteRange.parse("bytes=0-", 0))
    }

    @Test
    fun `a reversed pair is Unsatisfiable`() {
        // `bytes=10-5` is well-formed syntax (§14.1.1 requires first <= last),
        // so it is an unsatisfiable range, not a malformed header.
        assertEquals(RangeOutcome.Unsatisfiable, ByteRange.parse("bytes=10-5", 40))
    }

    @Test
    fun `anything this server cannot honour is Ignore, never 416`() {
        // §14.2: an unparseable or unsupported Range MUST be ignored — the
        // response is the whole 200. A client typo must not cost its cache.
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes=abc", 40))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes=1-2-3", 40))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes=", 40))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes=-", 40))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes -5", 40))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("items=0-9", 40))
        // `+5` is not a number the ABNF admits, and "-5-" is two dashes.
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes=+5", 40))
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes=-5-", 40))
    }

    @Test
    fun `multiple ranges are Ignore rather than multipart`() {
        // This server answers one range per request and every real caller of
        // this bridge sends one range per request; a multipart/byteranges body
        // would need a boundary the callers here cannot parse. Ignoring sends
        // a full 200, which every client can use — see the ByteRange KDoc.
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("bytes=0-9,20-29", 40))
    }

    @Test
    fun `unit names other than bytes are Ignore`() {
        // A server that does not understand the unit MUST ignore (§14.2), and
        // `416` for an unknown unit would fail every request that names a
        // unit this server happens not to implement.
        assertEquals(RangeOutcome.Ignore, ByteRange.parse("seconds=10-20", 40))
    }

    @Test
    fun `case and spacing are tolerated`() {
        assertEquals(RangeOutcome.Spec(0, 9), ByteRange.parse("BYTES=0-9", 40))
        assertEquals(RangeOutcome.Spec(0, 9), ByteRange.parse("bytes= 0-9 ", 40))
        assertEquals(RangeOutcome.Spec(0, 9), ByteRange.parse("bytes=0 - 9", 40))
    }
}
