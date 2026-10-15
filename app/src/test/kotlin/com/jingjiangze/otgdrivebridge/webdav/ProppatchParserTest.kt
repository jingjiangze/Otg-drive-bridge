package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * PROPPATCH body parsing (RFC 4918 §9.2).
 *
 * The parser is the gate in front of the dead-property store: anything it
 * accepts wrongly becomes a corrupt or unauthorisable write, and anything it
 * rejects wrongly becomes a 400 the client cannot explain. Both directions are
 * covered here.
 */
class ProppatchParserTest {

    private val body = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:author>Ada</Z:author></D:prop></D:set>
  <D:set><D:prop><Z:reviewed>true</Z:reviewed></D:prop></D:set>
</D:propertyupdate>"""

    @Test
    fun `a set instruction carries the value`() {
        val instructions = requireNotNull(ProppatchParser.parse(body))
        assertEquals(2, instructions.size)
        val author = instructions.single { it.name.local == "author" }
        assertTrue(author.isSet)
        assertEquals("Ada", author.value)
        assertEquals("Z", author.name.prefix)
        assertEquals("urn:example:test", author.name.namespaceUri)
    }

    @Test
    fun `a remove instruction has no value`() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:remove><D:prop><Z:reviewed/></D:prop></D:remove>
</D:propertyupdate>"""
        val instructions = requireNotNull(ProppatchParser.parse(xml))
        assertEquals(1, instructions.size)
        assertFalse(instructions[0].isSet)
        assertNull(instructions[0].value)
    }

    @Test
    fun `set and remove in one body are both parsed`() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:author>Ada</Z:author></D:prop></D:set>
  <D:remove><D:prop><Z:stale/></D:prop></D:remove>
</D:propertyupdate>"""
        val instructions = requireNotNull(ProppatchParser.parse(xml))
        assertEquals(2, instructions.size)
        assertTrue(instructions.any { it.isSet && it.name.local == "author" })
        assertTrue(instructions.any { !it.isSet && it.name.local == "stale" })
    }

    @Test
    fun `a blank body is refused rather than read as an empty instruction list`() {
        // An empty list is not expressible: `propertyupdate` with no `set` and no
        // `remove` is malformed per the RFC's content model, and treating it as
        // "nothing to do" would answer 207 for a broken request.
        assertNull(ProppatchParser.parse(""))
        assertNull(ProppatchParser.parse("   \n  "))
    }

    @Test
    fun `a non-propertyupdate root is refused`() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:"><D:response/></D:multistatus>"""
        assertNull(ProppatchParser.parse(xml))
    }

    @Test
    fun `not well formed xml is refused`() {
        assertNull(ProppatchParser.parse("<D:propertyupdate xmlns:D=\"DAV:\"><D:set>"))
    }

    @Test
    fun `a set whose child has children is refused`() {
        // A structured property value has no plain-string form. Storing its
        // `toString()` would corrupt it silently, so this is a 400.
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:address><Z:street>High</Z:street></Z:address></D:prop></D:set>
</D:propertyupdate>"""
        assertNull(ProppatchParser.parse(xml))
    }

    @Test
    fun `an unprefixed property is refused`() {
        // With no prefix there is nothing to key the property by, and a default
        // namespace is not allowed for `D:` elements.
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:">
  <D:set><D:prop><author>Ada</author></D:prop></D:set>
</D:propertyupdate>"""
        assertNull(ProppatchParser.parse(xml))
    }

    @Test
    fun `an empty prop is refused`() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop></D:prop></D:set>
</D:propertyupdate>"""
        assertNull(ProppatchParser.parse(xml))
    }

    @Test
    fun `a doctype declaration is refused`() {
        // XXE: a WebDAV body is untrusted input reachable from the LAN. Without
        // `disallow-doctype-decl` the parser would honour an external entity,
        // which is a local-file-disclosure primitive.
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE D:propertyupdate [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:author>&xxe;</Z:author></D:prop></D:set>
</D:propertyupdate>"""
        assertNull(ProppatchParser.parse(xml))
    }

    @Test
    fun `isProtected compares namespace uris not prefixes`() {
        val dav = WebDavXml.QualifiedName("D", "getcontentlength").apply {
            namespaceUri = "DAV:"
        }
        val samePrefixWrongNamespace = WebDavXml.QualifiedName("D", "author").apply {
            namespaceUri = "urn:example:test"
        }
        assertTrue(ProppatchParser.isProtected(dav))
        assertFalse(
            ProppatchParser.isProtected(samePrefixWrongNamespace),
            "a D: prefix bound to another namespace is an ordinary custom property"
        )
    }

    @Test
    fun `a property with no namespace at all is not protected`() {
        val plain = WebDavXml.QualifiedName("Z", "author")
        assertFalse(ProppatchParser.isProtected(plain))
    }

    @Test
    fun `xml special characters survive the value round trip`() {
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:note>a &amp; b &lt; c</Z:note></D:prop></D:set>
</D:propertyupdate>"""
        val instructions = requireNotNull(ProppatchParser.parse(xml))
        assertEquals("a & b < c", instructions[0].value)
    }
}
