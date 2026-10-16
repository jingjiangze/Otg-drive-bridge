package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

/**
 * [SecureXml], the one XML entry point every request-body parser shares.
 *
 * One thing this file cannot do, and the reason it says so: the failure it was
 * written for is invisible to a JVM unit test. All three hardening features
 * exist on the JVM that runs these tests, so the old per-parser `setFeature`
 * calls passed green here — while Android's XML stack does not implement them
 * and throws, which made PROPFIND answer 400 for every well-formed body on the
 * device. That divergence is verified on-device, not here.
 *
 * What *is* assertable, and is asserted below, is the contract the three
 * parsers depend on: a well-formed body parses, a blank one is null rather
 * than an empty document, and a malformed one is null rather than a throw. The
 * last two are what turn into a 400, so they are drawn as exactly the boundary
 * the handler has to be able to rely on.
 */
class SecureXmlTest {

    @Test
    fun `a well formed body parses with its namespaces intact`() {
        val document = SecureXml.parse(
            """<?xml version="1.0" encoding="utf-8"?>
            <D:propfind xmlns:D="DAV:"><D:prop><D:getetag/></D:prop></D:propfind>"""
        )
        assertNotNull(document, "a body every conforming client sends must parse")
        assertEquals("propfind", document!!.documentElement.localName)
        // Namespace awareness is the one setting that is load-bearing: without
        // it `Z:author` from two namespaces silently merges into one property.
        assertEquals("DAV:", document.documentElement.namespaceURI)
    }

    @Test
    fun `a body whose prefix is bound to a foreign namespace keeps that namespace`() {
        val document = SecureXml.parse("<x:propfind xmlns:x=\"DAV:\"><x:allprop/></x:propfind>")
        assertNotNull(document)
        assertEquals("propfind", document!!.documentElement.localName)
        assertEquals("DAV:", document.documentElement.namespaceURI)
    }

    @Test
    fun `a blank body is null rather than an empty document`() {
        assertNull(SecureXml.parse(""), "blank is not a document")
        assertNull(SecureXml.parse("   \n\t "), "whitespace-only is not a document")
    }

    @Test
    fun `a malformed body is null and does not throw`() {
        assertNull(SecureXml.parse("<D:propfind><D:prop>"), "unterminated markup must not throw")
        assertNull(SecureXml.parse("not xml at all"), "plain text must not throw")
    }

    /**
     * A DOCTYPE is refused rather than expanded: this is the actual XXE guard,
     * and on a listener reachable from the LAN a honoured external entity is a
     * local-file-disclosure primitive. Whatever the platform does with the
     * feature switch, the body must not reach a resolver.
     */
    @Test
    fun `a doctype with an external entity is not expanded`() {
        val body = """<?xml version="1.0"?>
            <!DOCTYPE propfind [<!ENTITY xx SYSTEM "file:///nonexistent">]>
            <D:propfind xmlns:D="DAV:"><D:prop><D:getetag/></D:prop></D:propfind>"""
        val document = SecureXml.parse(body)
        // Either refused outright or parsed without expanding — never expanded.
        if (document != null) {
            val text = document.documentElement.textContent
            assertNull(
                Regex("nonexistent|root:|/bin/").find(text),
                "an external entity must never be expanded into the tree"
            )
        }
    }
}
