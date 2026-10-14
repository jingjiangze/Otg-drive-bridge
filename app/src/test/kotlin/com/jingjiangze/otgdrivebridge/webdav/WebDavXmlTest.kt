package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The PROPFIND body is where Windows compatibility is won or lost: the redirector
 * needs the explicit `D:` namespace prefix, correct `resourcetype`, and an
 * `href` that ends with "/" for collections.
 */
class WebDavXmlTest {

    @Test
    fun `multistatus declares the D namespace`() {
        val body = WebDavXml.multistatus(emptyList())
        assertTrue(body.startsWith("<?xml version=\"1.0\" encoding=\"utf-8\"?>"))
        assertTrue(body.contains("<D:multistatus xmlns:D=\"DAV:\">"))
        assertTrue(body.endsWith("</D:multistatus>"))
    }

    @Test
    fun `a file response carries length and mime`() {
        val node = fakeNode("report.txt", isDirectory = false, length = 1234, lastModified = 1_700_000_000_000)
        val xml = WebDavXml.response("/docs/report.txt", node, "text/plain")
        assertTrue(xml.contains("<D:displayname>report.txt</D:displayname>"))
        assertTrue(xml.contains("<D:iscollection>0</D:iscollection>"))
        assertTrue(xml.contains("<D:getcontentlength>1234</D:getcontentlength>"))
        assertTrue(xml.contains("<D:getcontenttype>text/plain</D:getcontenttype>"))
        assertTrue(xml.contains("<D:resourcetype></D:resourcetype>"))
        assertTrue(xml.contains("<D:getlastmodified>"))
    }

    @Test
    fun `a directory response is a collection with no content length`() {
        val node = fakeNode("docs", isDirectory = true, length = 0, lastModified = 1_700_000_000_000)
        val xml = WebDavXml.response("/docs/", node, "text/plain")
        assertTrue(xml.contains("<D:iscollection>1</D:iscollection>"))
        assertTrue(xml.contains("<D:resourcetype><D:collection/></D:resourcetype>"))
        assertFalse(xml.contains("<D:getcontentlength>"))
    }

    @Test
    fun `collection listing includes the collection then children with trailing slashes`() {
        val collection = fakeNode("docs", isDirectory = true, length = 0, lastModified = 1_700_000_000_000)
        val children = listOf(
            fakeNode("b.txt", isDirectory = false, length = 10, lastModified = 1_700_000_001_000),
            fakeNode("a", isDirectory = true, length = 0, lastModified = 1_700_000_002_000)
        )
        val xml = WebDavXml.collectionListing("/docs/", collection, children) { "application/octet-stream" }
        assertTrue(xml.contains("<D:href>/docs/</D:href>"))
        assertTrue(xml.contains("<D:href>/docs/b.txt</D:href>"))
        assertTrue(xml.contains("<D:href>/docs/a/</D:href>"), "collections must end with /")
        assertEquals(3, Regex("<D:response>").findAll(xml).count())
    }

    @Test
    fun `special characters are escaped in hrefs and displaynames`() {
        val node = fakeNode("a&b<c>.txt", isDirectory = false, length = 1, lastModified = 0)
        val xml = WebDavXml.response("/a%26b.txt", node, "text/plain")
        assertTrue(xml.contains("&amp;b&lt;c&gt;.txt"))
        assertFalse(xml.contains("<D:displayname>a&b"))
    }

    @Test
    fun `lock discovery emits the token and timeout`() {
        val lock = LockManager.Lock(
            path = "/a.txt",
            token = "opaquelocktoken:1234",
            owner = "Office/16.0",
            expiresAtMillis = System.currentTimeMillis() + 60_000,
            scope = "exclusive",
            depth = "0"
        )
        val xml = WebDavXml.lockDiscovery(lock)
        assertTrue(xml.contains("<D:lockscope><D:exclusive/></D:lockscope>"))
        assertTrue(xml.contains("<D:depth>0</D:depth>"))
        assertTrue(xml.contains("<D:href>opaquelocktoken:1234</D:href>"))
        assertTrue(xml.contains("Second-"))
    }

    @Test
    fun `allow header lists every implemented method`() {
        listOf(
            "OPTIONS", "GET", "HEAD", "PUT", "DELETE", "PROPFIND",
            "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"
        ).forEach { method ->
            assertTrue(WebDavXml.ALLOWED_METHODS.contains(method), "missing $method")
        }
    }

    private fun fakeNode(
        name: String,
        isDirectory: Boolean,
        length: Long,
        lastModified: Long
    ) = object : DavNode {
        override val name: String = name
        override val isDirectory: Boolean = isDirectory
        override val length: Long = length
        override val lastModified: Long = lastModified
        override fun listChildren(): List<DavNode> = emptyList()
        override fun exists(): Boolean = true
    }
}
