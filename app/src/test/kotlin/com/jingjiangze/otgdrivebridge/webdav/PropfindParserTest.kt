package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The PROPFIND (RFC 4918 §9.1) and sync-collection (RFC 6578 §6.1) request
 * parsers.
 *
 * The cases that earn their place here are the ones a lenient parser gets
 * wrong in production: the empty body that §9.1 *requires* reading as allprop,
 * the `include` element that must ride along with allprop, the namespace-bound
 * `D:` prefix versus a `D:` bound to some other namespace, and the sync body
 * whose required elements are missing (a default there would invent a request
 * the client never made).
 */
class PropfindParserTest {

    private fun name(prefix: String, local: String, uri: String) =
        WebDavXml.QualifiedName(prefix, local).also { it.namespaceUri = uri }

    @Test
    fun `an empty body is allprop`() {
        // RFC 4918 §9.1: "An empty PROPFIND request body MUST be treated as if
        // it were an 'allprop' request."
        assertEquals(PropfindRequest.AllProp, PropfindParser.parse(""))
        assertEquals(PropfindRequest.AllProp, PropfindParser.parse("   \n  "))
    }

    @Test
    fun `allprop and propname are recognised`() {
        assertTrue(PropfindParser.parse("""<D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>""") is PropfindRequest.AllProp)
        assertTrue(PropfindParser.parse("""<D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>""") is PropfindRequest.PropName)
    }

    @Test
    fun `allprop with include is still allprop`() {
        // `include` names extra live properties to fold into allprop. This
        // server's allprop already carries everything it can compute, so the
        // right answer is to accept the body, not reject it.
        val request = PropfindParser.parse(
            """<D:propfind xmlns:D="DAV:"><D:allprop/><D:include><D:getetag/></D:include></D:propfind>"""
        )
        assertTrue(request is PropfindRequest.AllProp)
    }

    @Test
    fun `prop collects names with their namespace uris`() {
        val request = PropfindParser.parse(
            """<D:propfind xmlns:D="DAV:" xmlns:Z="urn:example"><D:prop><D:getetag/><Z:custom/></D:prop></D:propfind>"""
        ) as PropfindRequest.Named
        assertEquals(2, request.names.size)
        assertEquals("getetag", request.names[0].local)
        assertEquals("DAV:", request.names[0].namespaceUri)
        assertEquals("custom", request.names[1].local)
        assertEquals("urn:example", request.names[1].namespaceUri)
    }

    @Test
    fun `a D prefix bound to another namespace is read by uri not prefix`() {
        val request = PropfindParser.parse(
            """<D:propfind xmlns:D="urn:not-dav"><D:prop><D:getetag/></D:prop></D:propfind>"""
        ) as PropfindRequest.Named
        assertEquals("urn:not-dav", request.names[0].namespaceUri)
    }

    @Test
    fun `an unknown root or a non-dav body is refused`() {
        assertNull(PropfindParser.parse("""<D:propfind xmlns:D="DAV:"><D:nonsense/></D:propfind>"""))
        assertNull(PropfindParser.parse("<other/>"))
        assertNull(PropfindParser.parse("<D:propfind xmlns:D='DAV:'><!DOCTYPE x><D:allprop/></D:propfind>"))
    }

    // ------------------------------------------------------------------ sync

    @Test
    fun `a sync-collection body parses its three required parts`() {
        val request = SyncCollectionParser.parse(
            """<D:sync-collection xmlns:D="DAV:">
                 <D:sync-token>https://example/ns#sync/3</D:sync-token>
                 <D:sync-level>1</D:sync-level>
                 <D:prop><D:getetag/><D:getlastmodified/></D:prop>
               </D:sync-collection>"""
        )!!
        assertEquals("https://example/ns#sync/3", request.syncToken)
        assertEquals("1", request.syncLevel)
        assertEquals(listOf("getetag", "getlastmodified"), request.propNames.map { it.local })
    }

    @Test
    fun `an empty sync-token means initial sync and is distinct from a missing one`() {
        // RFC 6578 §3.4: an empty token element asks for a full listing. A
        // *missing* element is a malformed body — collapsing the two would turn
        // a client bug into a full re-transfer.
        val initial = SyncCollectionParser.parse(
            """<D:sync-collection xmlns:D="DAV:"><D:sync-token/>
               <D:sync-level>infinite</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"""
        )!!
        assertNull(initial.syncToken)
        assertEquals("infinite", initial.syncLevel)

        assertNull(
            SyncCollectionParser.parse(
                """<D:sync-collection xmlns:D="DAV:"><D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"""
            )
        )
    }

    @Test
    fun `a sync body missing level or prop is malformed`() {
        assertNull(
            SyncCollectionParser.parse(
                """<D:sync-collection xmlns:D="DAV:"><D:sync-token/><D:prop><D:getetag/></D:prop></D:sync-collection>"""
            )
        )
        assertNull(
            SyncCollectionParser.parse(
                """<D:sync-collection xmlns:D="DAV:"><D:sync-token/><D:sync-level>1</D:sync-level></D:sync-collection>"""
            )
        )
    }

    @Test
    fun `a limit element is accepted and ignored`() {
        val request = SyncCollectionParser.parse(
            """<D:sync-collection xmlns:D="DAV:"><D:sync-token/><D:sync-level>1</D:sync-level>
               <D:limit><D:nresults>10</D:nresults></D:limit>
               <D:prop><D:getetag/></D:prop></D:sync-collection>"""
        )
        assertTrue(request != null)
    }

    @Test
    fun `xml special characters survive a token round trip`() {
        val request = SyncCollectionParser.parse(
            """<D:sync-collection xmlns:D="DAV:"><D:sync-token>https://x/ns#sync/a&amp;b</D:sync-token>
               <D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"""
        )!!
        assertEquals("https://x/ns#sync/a&b", request.syncToken)
    }

    @Test
    fun `names returned by the parser round trip through the store key`() {
        // The whole reason the parser attaches URIs: the dead-property store is
        // keyed on `{uri}local`, so a name parsed without its URI would store
        // and read back under a different key than it was written with.
        val request = PropfindParser.parse(
            """<D:propfind xmlns:D="DAV:" xmlns:Z="urn:example"><D:prop><Z:author/></D:prop></D:propfind>"""
        ) as PropfindRequest.Named
        val key = DavPropertyStore.keyOf(request.names[0])
        assertEquals("{urn:example}author", key)
        assertEquals("urn:example", DavPropertyStore.namespaceOf(key))
        assertEquals("author", DavPropertyStore.localOf(key))
        assertFalse(key.startsWith("urn"), "the URI must be inside the braces")
    }
}
