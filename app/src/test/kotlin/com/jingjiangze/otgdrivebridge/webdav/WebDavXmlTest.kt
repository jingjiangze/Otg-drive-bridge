package com.jingjiangze.otgdrivebridge.webdav

import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.w3c.dom.Element

/**
 * The PROPFIND body is where Windows compatibility is won or lost: the redirector
 * needs the explicit `D:` namespace prefix, correct `resourcetype`, and an
 * `href` that ends with "/" for collections.
 */
class WebDavXmlTest {

    /**
     * A `DAV:`-namespace fixture name.
     *
     * `namespaceUri` is what decides whether the emitter keeps the prefix — it is
     * the identity of the property (RFC 4918 §4.4), and the prefix is only the
     * document's spelling of it. Constructing `QualifiedName("D", …)` and leaving
     * the URI at its default `""` builds a name that reads as *no namespace*, and
     * the emitter then correctly drops the prefix and emits a bare element: a
     * `D:` prefix with nothing bound is not a name any client can read. Four tests
     * asserted `<D:getcontentlength/>` on exactly that fixture and failed on the
     * emitter doing the right thing, so the helper exists to stop the next one.
     */
    private fun davName(local: String) =
        WebDavXml.QualifiedName("D", local).also { it.namespaceUri = "DAV:" }

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
        // `mimeTypeOf` is named because a trailing lambda binds to the *last*
        // parameter, `extraForCollection`, which is a List — not a function.
        val xml = WebDavXml.collectionListing(
            baseHref = "/docs/",
            collection = collection,
            children = children,
            mimeTypeOf = { "application/octet-stream" }
        )
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

    @Test
    fun `a dead property propstat carries the value not just the name`() {
        // The value is the whole point of storing a property: a PROPFIND that
        // answers `<Z:author/>` has not given the client its data back.
        val properties = listOf(
            WebDavXml.QualifiedName("Z", "author").also { it.namespaceUri = "urn:example:test" } to "Ada & Co",
            WebDavXml.QualifiedName("Z", "reviewed").also { it.namespaceUri = "urn:example:test" } to "true"
        )
        val xml = WebDavXml.deadPropertiesPropstat(properties)
        assertTrue(xml.contains("<Z:author>Ada &amp; Co</Z:author>"), xml)
        assertTrue(xml.contains("<Z:reviewed>true</Z:reviewed>"), xml)
        assertTrue(xml.contains("<D:status>HTTP/1.1 200 OK</D:status>"), xml)
        // One propstat, not one per property. The element carries an xmlns
        // declaration when the client's prefix needs binding, so the match has
        // to accept an attribute list — a bare `<D:propstat>` would never match
        // the correctly-emitted `<D:propstat xmlns:Z="urn:example:test">`.
        assertEquals(1, Regex("<D:propstat[ >]").findAll(xml).count())
        // The prefix must be *bound*: an unbound `<Z:author>` is not
        // namespace-well-formed and every namespace-aware parser rejects the
        // whole multistatus, which would reintroduce the empty-listing bug.
        assertTrue(
            xml.contains("xmlns:Z=\"urn:example:test\""),
            "the client's prefix must carry its xmlns declaration: $xml"
        )
    }

    @Test
    fun `a dead property propstat declares each prefix once and never rebinds D`() {
        val properties = listOf(
            WebDavXml.QualifiedName("Z", "author").also { it.namespaceUri = "urn:example:a" } to "Ada",
            WebDavXml.QualifiedName("Y", "title").also { it.namespaceUri = "urn:example:b" } to "Book",
            WebDavXml.QualifiedName("Z", "other").also { it.namespaceUri = "urn:example:a" } to "x"
        )
        val xml = WebDavXml.deadPropertiesPropstat(properties)
        assertEquals(1, Regex("xmlns:Z=").findAll(xml).count(), "one declaration per prefix: $xml")
        assertEquals(1, Regex("xmlns:Y=").findAll(xml).count(), xml)
        // `D` is bound on the multistatus root already; redeclaring it here
        // would be legal but is noise, and a wrong one would break every DAV
        // element in the document.
        assertFalse(xml.contains("xmlns:D="), xml)
        assertTrue(xml.contains("xmlns:Z=\"urn:example:a\""), xml)
        assertTrue(xml.contains("xmlns:Y=\"urn:example:b\""), xml)
    }

    @Test
    fun `a proppatch propstat declares the prefix it echoes`() {
        val xml = WebDavXml.proppatchPropstat(
            listOf(WebDavXml.QualifiedName("Z", "author").also { it.namespaceUri = "urn:example:a" }),
            WebDavXml.HttpStatus.OK
        )
        assertTrue(xml.contains("<Z:author/>"), xml)
        assertTrue(xml.contains("xmlns:Z=\"urn:example:a\""), "unbound prefix: $xml")
    }

    @Test
    fun `a name with no namespace is emitted unprefixed`() {
        // A property with no namespace has no prefix to bind, and binding one
        // anyway is not an option: `xmlns:Z=""` is illegal — a prefixed namespace
        // binding may not be empty, which a namespace-aware parser enforces
        // ("带前缀的名称空间绑定不能为空", verified against Xerces). The only legal
        // way to say "no namespace" is an unprefixed element, so the emitter must
        // drop the `prefix:local` form for these rather than emit a document no
        // client can parse.
        val noNamespace = WebDavXml.QualifiedName("", "plain")
        assertEquals("", noNamespace.namespaceUri)
        assertEquals(
            "",
            WebDavXml.namespaceDeclarationsFor(listOf(noNamespace)),
            "nothing to bind when there is no prefix: $noNamespace"
        )

        // And it must survive into a real propstat, not just the fragment.
        val xml = WebDavXml.deadPropertiesPropstat(listOf(noNamespace to "v"))
        assertTrue(xml.contains("<plain>v</plain>"), "unprefixed element: $xml")
        assertFalse(xml.contains("xmlns:") && xml.contains("xmlns:="), "no empty prefixed binding: $xml")
    }

    @Test
    fun `a synthesized prefix for a no-namespace property is dropped`() {
        // The case the test above cannot reach, and the one that actually
        // shipped broken: `WebDavRequestHandler.deadPropertiesPropstats`
        // generates a `p0`, `p1`… prefix per distinct *namespace URI* so it can
        // echo a URI back — a URI contains `:` and `/` and is not itself a legal
        // prefix. For a property in no namespace that generation produces prefix
        // `p0` with URI `""`, i.e. the illegal `xmlns:p0=""` binding, and the
        // guard has to be keyed on the URI to catch it. Keyed on the prefix it
        // looked correct and still emitted `<D:propstat xmlns:p0=""><p0:plain>`.
        val synthesized = WebDavXml.QualifiedName("p0", "plain")
        assertEquals("", synthesized.namespaceUri)
        assertEquals("", WebDavXml.namespaceDeclarationsFor(listOf(synthesized)))
        val xml = WebDavXml.deadPropertiesPropstat(listOf(synthesized to "v"))
        assertTrue(xml.contains("<plain>v</plain>"), "unprefixed element: $xml")
        assertFalse(Regex("xmlns:\\w+=\"\"").containsMatchIn(xml), "no empty binding: $xml")
    }

    @Test
    fun `a synthesized prefix for a real namespace is still declared`() {
        // The other half: a synthetic prefix bound to a real URI must keep its
        // declaration, or the element is an unbound prefix and the whole
        // multistatus is rejected — the empty-listing bug again.
        val synthesized = WebDavXml.QualifiedName("p0", "marker").also { it.namespaceUri = "urn:example:t" }
        assertEquals(" xmlns:p0=\"urn:example:t\"", WebDavXml.namespaceDeclarationsFor(listOf(synthesized)))
        val xml = WebDavXml.deadPropertiesPropstat(listOf(synthesized to "v"))
        assertTrue(xml.contains("<p0:marker>v</p0:marker>"), "prefixed element: $xml")
        assertTrue(xml.contains("xmlns:p0=\"urn:example:t\""), "the binding must be present: $xml")
    }

    @Test
    fun `namespace declarations are empty when there is nothing to declare`() {
        // `D` is never declared here — the multistatus root owns that binding.
        val dav = davName("getcontentlength")
        assertEquals("", WebDavXml.namespaceDeclarationsFor(listOf(dav)))
        assertEquals("", WebDavXml.namespaceDeclarationsFor(emptyList()))
    }

    @Test
    fun `a proppatch propstat lists names only and names the condition`() {
        // A PROPPATCH *response* carries no values — RFC 4918 §9.2 says the
        // request is echoed back, the client already knows what it sent.
        val xml = WebDavXml.proppatchPropstat(
            listOf(davName("getcontentlength")),
            WebDavXml.HttpStatus.FORBIDDEN,
            WebDavXml.Conditions.CANNOT_MODIFY_PROTECTED_PROPERTY
        )
        assertTrue(xml.contains("<D:getcontentlength/>"), xml)
        assertTrue(xml.contains("<D:cannot-modify-protected-property/>"), xml)
        assertTrue(xml.contains("<D:status>HTTP/1.1 403 Forbidden</D:status>"), xml)
    }

    @Test
    fun `an error body always carries at least one element`() {
        // RFC 4918 §14.5: `<!ELEMENT error ANY>` — at least one XML element,
        // never bare text. A client that parses the body (x/net/webdav,
        // Windows MiniRedir, litmus) would otherwise find nothing it knows.
        val empty = WebDavXml.error()
        assertTrue(empty.startsWith("<?xml version=\"1.0\" encoding=\"utf-8\"?>"), empty)
        assertTrue(empty.contains("<D:error xmlns:D=\"DAV:\""), empty)
        assertTrue(empty.endsWith("</D:error>"), empty)
        assertTrue(empty.contains("<Z:condition-not-mapped/>"), empty)
        assertTrue(
            Regex("<[A-Za-z]:[^>]*/>").containsMatchIn(empty),
            "error with no condition must still contain an element: $empty"
        )
    }

    @Test
    fun `an error body emits each named dav condition`() {
        val xml = WebDavXml.error(
            WebDavXml.Conditions.LOCK_TOKEN_SUBMITTED,
            WebDavXml.Conditions.NO_CONFLICTING_LOCK
        )
        assertTrue(xml.contains("<D:lock-token-submitted/>"), xml)
        assertTrue(xml.contains("<D:no-conflicting-lock/>"), xml)
        assertFalse(xml.contains("Z:"), "a mapped condition must not fall back to Z:")
    }

    @Test
    fun `every rfc 4918 section 16 condition is defined`() {
        // The complete set from §16. Names that circulate in tutorials but come
        // from RFC 3744 or vendor extensions must NOT be here — a conforming
        // client rejects an error body naming a condition it does not know.
        //
        // Filtered by *what the field is*, not by name: on a Kotlin `object`
        // `declaredFields` also holds the `INSTANCE` the compiler generates and —
        // under the Compose compiler plugin, which AGP 8.5.2 applies here — a
        // `$stable` marker the stability inference emits. Measured on CI: the
        // `$stable` field is present and a name-based filter that only excluded
        // `INSTANCE` reported `[…, $stable]` and failed. Every §16 condition is a
        // `public static final String`, and neither of those two is, so asserting
        // the shape is what keeps the set closed without a filter that has to be
        // updated every time the toolchain adds a field.
        val conditionNames = WebDavXml.Conditions::class.java.declaredFields
            .filter { java.lang.reflect.Modifier.isStatic(it.modifiers) }
            .filter { java.lang.reflect.Modifier.isPublic(it.modifiers) }
            .filter { java.lang.reflect.Modifier.isFinal(it.modifiers) }
            .filter { it.type == String::class.java }
            .filter { it.name != "INSTANCE" }
            .map { it.name }
            .toSet()
        assertEquals(
            setOf(
                "LOCK_TOKEN_MATCHES_REQUEST_URI",
                "LOCK_TOKEN_SUBMITTED",
                "NO_CONFLICTING_LOCK",
                "NO_EXTERNAL_ENTITIES",
                "PRESERVED_LIVE_PROPERTIES",
                "PROPFIND_FINITE_DEPTH",
                "CANNOT_MODIFY_PROTECTED_PROPERTY"
            ),
            conditionNames,
            "the §16 set is closed — every name here, and nothing else"
        )
        listOf(
            WebDavXml.Conditions.LOCK_TOKEN_MATCHES_REQUEST_URI,
            WebDavXml.Conditions.LOCK_TOKEN_SUBMITTED,
            WebDavXml.Conditions.NO_CONFLICTING_LOCK,
            WebDavXml.Conditions.NO_EXTERNAL_ENTITIES,
            WebDavXml.Conditions.PRESERVED_LIVE_PROPERTIES,
            WebDavXml.Conditions.PROPFIND_FINITE_DEPTH,
            WebDavXml.Conditions.CANNOT_MODIFY_PROTECTED_PROPERTY
        ).forEach { condition ->
            assertTrue(condition.isNotEmpty() && condition == condition.lowercase(), "bad condition: $condition")
        }
    }

    @Test
    fun `a proppatch response wraps each propstat in one response`() {
        val stored = WebDavXml.proppatchPropstat(
            listOf(WebDavXml.QualifiedName("Z", "author").also { it.namespaceUri = "urn:example:a" }),
            WebDavXml.HttpStatus.OK
        )
        val refused = WebDavXml.proppatchPropstat(
            listOf(davName("getcontentlength")),
            WebDavXml.HttpStatus.FORBIDDEN,
            WebDavXml.Conditions.CANNOT_MODIFY_PROTECTED_PROPERTY
        )
        val xml = WebDavXml.proppatchResponse("/a.txt", listOf(stored, refused))
        assertTrue(xml.startsWith("<D:response><D:href>/a.txt</D:href>"), xml)
        assertTrue(xml.endsWith("</D:response>"), xml)
        // Both outcomes in one response — never a blanket status for the whole
        // request, which is what made the old PROPPATCH a lie.
        assertTrue(xml.contains("200 OK"), xml)
        assertTrue(xml.contains("403 Forbidden"), xml)
    }

    @Test
    fun `an extra propstat lands inside the response that owns it`() {
        // The multistatus DTD is `(response+, error?)`. A propstat sitting after
        // `</D:response>` — which is what concatenating to the return value of
        // `response()` produces — is a child of nothing, so every parser rejects
        // the whole document and the client sees an empty listing.
        val node = fakeNode("doc.txt", isDirectory = false, length = 4, lastModified = 1_700_000_000_000)
        val extra = listOf(
            WebDavXml.deadPropertiesPropstat(
                listOf(WebDavXml.QualifiedName("Z", "marker").also { it.namespaceUri = "urn:example:t" } to "hello")
            )
        )
        val xml = WebDavXml.response("/doc.txt", node, "text/plain", extraPropstats = extra)
        assertTrue(xml.contains("<Z:marker>hello</Z:marker>"), xml)
        assertTrue(xml.contains("xmlns:Z=\"urn:example:t\""), "unbound prefix: $xml")

        val responseEnd = xml.indexOf("</D:response>")
        assertTrue(responseEnd > 0, "no </D:response> in $xml")
        assertTrue(
            xml.indexOf("<Z:marker>") < responseEnd,
            "the dead-property propstat must precede </D:response>: $xml"
        )
        // Exactly one response, and the propstat count is what was asked for.
        // The extra propstat declares `xmlns:Z`, so match the open tag with an
        // attribute list rather than the bare element.
        assertEquals(1, Regex("<D:response>").findAll(xml).count())
        assertEquals(2, Regex("<D:propstat[ >]").findAll(xml).count())
    }

    @Test
    fun `a collection listing keeps the extra propstat inside the collection response`() {
        val collection = fakeNode("docs", isDirectory = true, length = 0, lastModified = 1_700_000_000_000)
        val children = listOf(fakeNode("b.txt", isDirectory = false, length = 10, lastModified = 1_700_000_001_000))
        // Same named-argument form as every other `collectionListing` call site:
        // the trailing lambda would land on `extraForCollection`.
        val xml = WebDavXml.collectionListing(
            baseHref = "/docs/",
            collection = collection,
            children = children,
            mimeTypeOf = { "application/octet-stream" }
        )
        assertTrue(xml.contains("</D:multistatus>"))

        // No argument means no extra propstat at all — the default must not
        // inject an empty element. Two resources (collection + one child) each
        // carry exactly their own live-property propstat: one per response, and
        // the count is the number of responses, not the number of properties.
        assertEquals(2, Regex("<D:propstat[ >]").findAll(xml).count())
        assertEquals(2, Regex("<D:response>").findAll(xml).count())
    }

    @Test
    fun `a collection listing places an extra propstat inside the collection response`() {
        val collection = fakeNode("docs", isDirectory = true, length = 0, lastModified = 1_700_000_000_000)
        val children = listOf(fakeNode("b.txt", isDirectory = false, length = 10, lastModified = 1_700_000_001_000))
        val extra = listOf(
            WebDavXml.deadPropertiesPropstat(
                listOf(WebDavXml.QualifiedName("Z", "label").also { it.namespaceUri = "urn:example:t" } to "Receipts")
            )
        )
        val xml = WebDavXml.collectionListing(
            "/docs/", collection, children, { "application/octet-stream" }, extra
        )
        // The label belongs to the collection's own response, and to nothing
        // else: the child must not carry it, and it must be inside the document.
        assertTrue(xml.contains("<Z:label>Receipts</Z:label>"), xml)
        assertTrue(xml.indexOf("<Z:label>") < xml.lastIndexOf("</D:multistatus>"), xml)
        assertTrue(
            xml.indexOf("<Z:label>") < xml.indexOf("<D:href>/docs/b.txt</D:href>"),
            "the child's response must not carry the collection's property: $xml"
        )
    }

    // ------------------------------------------------- namespace well-formedness
    //
    // These parse the documents with a *namespace-aware* parser, which is what
    // Go's x/net/webdav, Windows' MiniRedir and litmus all do. A substring
    // assertion cannot catch an unbound prefix — `<Z:marker>` looks fine as text
    // and is a fatal error to every one of those parsers, which then discard the
    // entire multistatus and show the user an empty listing.

    /** Parses [xml] namespace-aware; fails the test when it is not well-formed. */
    private fun parseNamespaceAware(xml: String): org.w3c.dom.Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        runCatching {
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        }
        return factory.newDocumentBuilder()
            .parse(ByteArrayInputStream(xml.toByteArray(Charsets.UTF_8)))
    }

    /**
     * Elements matching `prefix:local` **resolved through their namespace URI**.
     *
     * `getElementsByTagName` matches on the qualified name as written, so it
     * cannot tell an unbound `<Z:marker>` from a bound one — which is exactly
     * how the bug this guards against survived a first round of tests. Walking
     * the tree and reading `namespaceURI` does, because a document with an
     * unbound prefix does not parse at all and `localName`/`namespaceURI` are
     * only meaningful once it has.
     */
    private fun org.w3c.dom.Document.elements(qName: String): List<Element> {
        val prefix = qName.substringBefore(':', qName)
        val local = qName.substringAfter(':', qName)
        val out = ArrayList<Element>()
        fun walk(node: org.w3c.dom.Node) {
            if (node.nodeType == org.w3c.dom.Node.ELEMENT_NODE) {
                val element = node as Element
                if (element.localName == local && element.prefix == prefix) out += element
            }
            val children = node.childNodes
            for (i in 0 until children.length) walk(children.item(i))
        }
        walk(documentElement ?: return out)
        return out
    }

    @Test
    fun `a propfind body with dead properties parses namespace-aware`() {
        // The real end-to-end shape: a stored property read back inside a full
        // multistatus, exactly as the handler builds it.
        val node = fakeNode("doc.txt", isDirectory = false, length = 4, lastModified = 1_700_000_000_000)
        val extra = listOf(
            WebDavXml.deadPropertiesPropstat(
                listOf(
                    WebDavXml.QualifiedName("Z", "marker").also { it.namespaceUri = "urn:example:test" } to "hello"
                )
            )
        )
        val xml = WebDavXml.multistatus(
            listOf(WebDavXml.response("/doc.txt", node, "text/plain", extraPropstats = extra))
        )
        val document = parseNamespaceAware(xml)
        val marker = document.elements("Z:marker").single()
        // The prefix must resolve to the namespace the client actually used —
        // this is the assertion that an unbound prefix fails at parse time.
        assertEquals("urn:example:test", marker.namespaceURI)
        assertEquals("hello", marker.textContent)
        // The DAV elements must still resolve to DAV: alongside it.
        val responses = document.elements("D:response")
        assertEquals(1, responses.size)
        assertEquals("DAV:", responses.single().namespaceURI)
    }

    @Test
    fun `a proppatch response body parses namespace-aware`() {
        val stored = WebDavXml.proppatchPropstat(
            listOf(WebDavXml.QualifiedName("Z", "author").also { it.namespaceUri = "urn:example:a" }),
            WebDavXml.HttpStatus.OK
        )
        val refused = WebDavXml.proppatchPropstat(
            listOf(davName("getcontentlength")),
            WebDavXml.HttpStatus.FORBIDDEN,
            WebDavXml.Conditions.CANNOT_MODIFY_PROTECTED_PROPERTY
        )
        val xml = WebDavXml.multistatus(
            listOf(WebDavXml.proppatchResponse("/a.txt", listOf(stored, refused)))
        )
        val document = parseNamespaceAware(xml)
        val author = document.elements("Z:author").single()
        assertEquals("urn:example:a", author.namespaceURI)
        // The protected property is in the real DAV: namespace, and the refusal
        // names the RFC 4918 §16 condition in that same namespace.
        val protected = document.elements("D:getcontentlength").single()
        assertEquals("DAV:", protected.namespaceURI)
        val condition = document.elements("D:cannot-modify-protected-property").single()
        assertEquals("DAV:", condition.namespaceURI)
    }

    @Test
    fun `a collection listing with dead properties parses namespace-aware`() {
        val collection = fakeNode("docs", isDirectory = true, length = 0, lastModified = 1_700_000_000_000)
        val children = listOf(fakeNode("b.txt", isDirectory = false, length = 10, lastModified = 1_700_000_001_000))
        val extra = listOf(
            WebDavXml.deadPropertiesPropstat(
                listOf(
                    WebDavXml.QualifiedName("Z", "label").also { it.namespaceUri = "urn:example:t" } to "Receipts"
                )
            )
        )
        val xml = WebDavXml.collectionListing(
            "/docs/", collection, children, { "application/octet-stream" }, extra
        )
        val document = parseNamespaceAware(xml)
        assertEquals("urn:example:t", document.elements("Z:label").single().namespaceURI)
        assertEquals(2, document.elements("D:response").size)
        // Every href in a depth-1 listing must be a child of the root element,
        // not an orphan appended after the document closes.
        assertEquals(2, document.elements("D:href").size)
    }

    @Test
    fun `an error body parses namespace-aware`() {
        val xml = WebDavXml.error(WebDavXml.Conditions.LOCK_TOKEN_SUBMITTED)
        val document = parseNamespaceAware(xml)
        val condition = document.elements("D:lock-token-submitted").single()
        assertEquals("DAV:", condition.namespaceURI)
        // The no-condition fallback lives in this server's own namespace, which
        // §16 permits for conditions the RFC does not define.
        val fallback = parseNamespaceAware(WebDavXml.error()).elements("Z:condition-not-mapped").single()
        assertEquals("https://jingjiangze.otgdrivebridge/ns#", fallback.namespaceURI)
    }

    @Test
    fun `a file response carries the entity tag it was given`() {
        // RFC 4918 §15.6: "The getetag property MUST be defined on any
        // DAV-compliant resource that returns the Etag header." GET returns one,
        // so a listing that omits the property leaves a sync client unable to
        // ask a folder whether anything changed without downloading every file.
        val node = fakeNode("report.txt", isDirectory = false, length = 1234, lastModified = 1_700_000_000_000)
        val xml = WebDavXml.response("/docs/report.txt", node, "text/plain", etag = "\"1234-56\"")
        assertTrue(xml.contains("<D:getetag>&quot;1234-56&quot;</D:getetag>"), xml)
    }

    @Test
    fun `a file response without a tag emits no empty getetag`() {
        // An empty element would be worse than none: a client comparing tags
        // would read `""` and conclude the file never changes.
        val node = fakeNode("report.txt", isDirectory = false, length = 1, lastModified = 1)
        val xml = WebDavXml.response("/docs/report.txt", node, "text/plain")
        assertFalse(xml.contains("getetag"), xml)
    }

    @Test
    fun `a collection response carries no entity tag`() {
        // GET on a collection answers a directory index and sends no ETag, so
        // there is no header value for the property to mirror.
        val node = fakeNode("docs", isDirectory = true, length = 0, lastModified = 1_700_000_000_000)
        val xml = WebDavXml.response("/docs/", node, "text/plain", etag = "\"0-0\"")
        assertFalse(xml.contains("getetag"), xml)
    }

    @Test
    fun `a listing passes each child's tag through`() {
        val file = fakeNode("a.txt", isDirectory = false, length = 3, lastModified = 1_700_000_000_000)
        val xml = WebDavXml.collectionListing(
            "/",
            fakeNode("root", isDirectory = true, length = 0, lastModified = 1),
            listOf(file),
            { "text/plain" },
            emptyList(),
            etagOf = { "\"tag-${it.name}\"" }
        )
        assertTrue(xml.contains("<D:getetag>&quot;tag-a.txt&quot;</D:getetag>"), xml)
        // The collection itself gets none — `etagOf` is asked for it too, and
        // the emitter drops the property for a directory. One child, one tag.
        assertEquals(1, Regex("<D:getetag>").findAll(xml).count())
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
