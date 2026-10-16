package com.jingjiangze.otgdrivebridge.webdav

import java.io.ByteArrayInputStream
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.xml.sax.InputSource

/**
 * What a PROPFIND (RFC 4918 §9.1) or `DAV:sync-collection` report (RFC 6578
 * §3.2) body asks for, after parsing.
 */
sealed class PropfindRequest {

    /**
     * All properties, plus any dead ones. RFC 4918 §9.1: "A client may choose
     * not to submit a request body. An empty PROPFIND request body MUST be
     * treated as if it were an 'allprop' request."
     */
    object AllProp : PropfindRequest()

    /** Only the names of the properties defined on the resource (§14.21). */
    object PropName : PropfindRequest()

    /**
     * Exactly these properties. The server returns values for the ones it knows
     * and a separate 404 propstat for the ones it does not (§9.1: a missing
     * property "MUST be noted with a 'response' XML element that contains a 404
     * (Not Found) status value") — the split is made by the caller, which knows
     * which live properties it can compute.
     */
    data class Named(val names: List<WebDavXml.QualifiedName>) : PropfindRequest()
}

/**
 * Parses a PROPFIND request body (RFC 4918 §9.1 / §14.20):
 *
 *     <!ELEMENT propfind ( propname | (allprop, include?) | prop )>
 *
 * `include` is accepted and ignored: it names additional live properties to
 * return with `allprop`, and this server's allprop already includes every live
 * property it can compute, so honouring the subset is a no-op — refusing it
 * would reject bodies conforming clients legitimately send.
 *
 * An unrecognized root element is null, not an allprop guess: §9.1 defines
 * exactly three forms, and a body this parser cannot read is a client bug the
 * caller should surface as 400 rather than paper over with a full listing
 * (which for a large tree is a lot of bytes for a malformed request).
 */
object PropfindParser {

    fun parse(body: String): PropfindRequest? {
        // The empty-body rule of §9.1 — allprop, verbatim.
        if (body.isBlank()) return PropfindRequest.AllProp
        val document = runCatching {
            val factory = DocumentBuilderFactory.newInstance()
            factory.isNamespaceAware = true
            // XXE hardening, same as ProppatchParser: a request body is hostile
            // input, and a DTD would let `file:///` URLs reach the parser.
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            factory.newDocumentBuilder().parse(InputSource(ByteArrayInputStream(body.toByteArray(Charsets.UTF_8))))
        }.getOrNull() ?: return null
        val root = document.documentElement ?: return null
        if (root.namespaceURI != WebDavXml.DAV_NS) return null
        return when (root.localName) {
            "allprop" -> PropfindRequest.AllProp
            "propname" -> PropfindRequest.PropName
            "prop" -> {
                val names = ArrayList<WebDavXml.QualifiedName>()
                // childNodes is an org.w3c.dom.NodeList, which is neither a
                // Kotlin Iterable nor a Java Iterable: `for (node in …)` does
                // not resolve, and the extension that does resolve is
                // ambiguous. Indexed access is the portable form.
                val children = root.childNodes
                for (i in 0 until children.length) {
                    val node = children.item(i)
                    if (node is Element) {
                        names += WebDavXml.QualifiedName(node.prefix ?: "", node.localName ?: node.nodeName).apply {
                            namespaceUri = node.namespaceURI ?: ""
                        }
                    }
                }
                PropfindRequest.Named(names)
            }
            else -> null
        }
    }
}
