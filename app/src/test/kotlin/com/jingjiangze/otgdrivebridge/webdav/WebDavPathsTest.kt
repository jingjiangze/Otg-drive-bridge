package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Traversal defence is the single most important server-side invariant: a client
 * must never be able to address anything outside the shared root, no matter how
 * the path is encoded.
 */
class WebDavPathsTest {

    @Test
    fun `root and empty paths normalise to no segments`() {
        assertEquals(emptyList<String>(), WebDavPaths.normalize("/"))
        assertEquals(emptyList<String>(), WebDavPaths.normalize(""))
        assertTrue(WebDavPaths.isRoot("/"))
    }

    @Test
    fun `a null path is rejected rather than read as the root`() {
        // Fail closed: the shared root must not be served just because the path
        // is missing, so null stays null and isRoot stays false.
        assertNull(WebDavPaths.normalize(null))
        assertFalse(WebDavPaths.isRoot(null))
    }

    @Test
    fun `plain segments decode as expected`() {
        assertEquals(listOf("docs", "file.txt"), WebDavPaths.normalize("/docs/file.txt"))
        assertEquals(listOf("docs"), WebDavPaths.normalize("docs"))
        assertEquals(listOf("a", "b", "c"), WebDavPaths.normalize("//a///b//c/"))
    }

    @Test
    fun `percent encoded traversal is rejected`() {
        assertNull(WebDavPaths.normalize("/%2e%2e/etc/passwd"))
        assertNull(WebDavPaths.normalize("/..%2f..%2fetc"))
        assertNull(WebDavPaths.normalize("/docs/%2E%2E/%2E%2E"))
    }

    @Test
    fun `literal traversal is rejected`() {
        assertNull(WebDavPaths.normalize("/../etc/passwd"))
        assertNull(WebDavPaths.normalize("/docs/../../secret"))
        assertNull(WebDavPaths.normalize("/.."))
    }

    @Test
    fun `dot and backslash and nul are rejected`() {
        assertNull(WebDavPaths.normalize("/docs/./file"))
        assertNull(WebDavPaths.normalize("/docs\\file"))
        assertNull(WebDavPaths.normalize("/docs/\u0000file"))
    }

    @Test
    fun `legitimate percent encoded names survive`() {
        assertEquals(listOf("my file (1).txt"), WebDavPaths.normalize("/my%20file%20(1).txt"))
        assertEquals(listOf("中文目录", "文件.txt"), WebDavPaths.normalize("/%E4%B8%AD%E6%96%87%E7%9B%AE%E5%BD%95/%E6%96%87%E4%BB%B6.txt"))
        assertEquals(listOf("a+b"), WebDavPaths.normalize("/a+b"))
    }

    @Test
    fun `windows reserved names are rejected`() {
        assertFalse(WebDavPaths.isSafeSegment("CON"))
        assertFalse(WebDavPaths.isSafeSegment("com1"))
        assertFalse(WebDavPaths.isSafeSegment("LPT9"))
        assertTrue(WebDavPaths.isSafeSegment("CONSOLE"))
    }

    @Test
    fun `href encoding round trips through normalize`() {
        val segments = listOf("my file", "sub dir", "a&b.txt")
        val href = WebDavPaths.encodeHref(segments)
        assertEquals("/my%20file/sub%20dir/a%26b.txt", href)
        assertEquals(segments, WebDavPaths.normalize(href))
    }

    @Test
    fun `extensionOf lowercases`() {
        assertEquals("txt", WebDavPaths.extensionOf("A.TXT"))
        assertEquals("", WebDavPaths.extensionOf("noext"))
    }

    @Test
    fun `trailing dots and spaces are rejected`() {
        // Windows strips trailing dots/spaces from a path component when it
        // resolves a name, so a server that accepts them creates a file the
        // client cannot address: `PUT /dot.` landed on disk as `con..bin` via the
        // SAF mime-extension mangling, and the next GET for `/dot.` found nothing.
        // Rejecting turns a silent round-trip failure into a 400 the client can
        // report. Measured on-device (emulator-5554): PUT /dot. answered 201.
        assertFalse(WebDavPaths.isSafeSegment("dot."))
        assertFalse(WebDavPaths.isSafeSegment("dot. "))
        assertFalse(WebDavPaths.isSafeSegment("dot "))
        assertFalse(WebDavPaths.isSafeSegment("."))
        assertNull(WebDavPaths.normalize("/dot."))
        assertNull(WebDavPaths.normalize("/docs/trailing "))
    }

    @Test
    fun `leading spaces are rejected`() {
        // Explorer will not display such a name and neither will a shell glob.
        assertFalse(WebDavPaths.isSafeSegment(" leading"))
        assertNull(WebDavPaths.normalize("/%20leading"))
    }

    @Test
    fun `ordinary dots and spaces inside a name survive`() {
        // The rejection is about the *edges* only — a file called
        // "my report (final).txt" is perfectly ordinary.
        assertTrue(WebDavPaths.isSafeSegment("my report (final).txt"))
        assertTrue(WebDavPaths.isSafeSegment("a.b.c.txt"))
        assertEquals(listOf("my report (final).txt"), WebDavPaths.normalize("/my%20report%20(final).txt"))
    }
}
