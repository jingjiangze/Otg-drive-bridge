package com.jingjiangze.otgdrivebridge.webdav

import org.w3c.dom.Element

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
        val document = SecureXml.parse(body) ?: return null
        val root = document.documentElement ?: return null
        // The three forms are *children* of `<D:propfind>`, not alternative
        // roots: §14.20's DTD is `<!ELEMENT propfind (propname | (allprop,
        // include?) | prop)>`. Switching on the root's own name — which is always
        // `propfind` — matched none of them and rejected every well-formed body
        // (measured on CI: 12 tests red, all of them this one line).
        //
        // The root's *namespace* is deliberately not checked, and neither is the
        // form element's: a client is free to bind the `D:` prefix to anything,
        // and reading `D:propfind` by its prefix rather than by what it is bound
        // to is the mistake this parser exists to avoid. What decides whether a
        // property is `DAV:getetag` is the URI on the property name, and that
        // comparison belongs to the handler, which has to make it anyway for the
        // names inside `<D:prop>`.
        if (root.localName != "propfind") return null
        val children = root.childNodes
        for (i in 0 until children.length) {
            val child = children.item(i)
            if (child !is Element) continue
            return when (child.localName) {
                // `include` rides along as a later sibling and is ignored — see
                // the class comment.
                "allprop" -> PropfindRequest.AllProp
                "propname" -> PropfindRequest.PropName
                "prop" -> PropfindRequest.Named(propNamesOf(child))
                else -> null
            }
        }
        return null
    }

    /**
     * The property names inside a `<D:prop>` element, in document order with
     * their namespace URIs.
     *
     * Unlike the form element above, these are *not* filtered to `DAV:`: a
     * `<D:prop>` legitimately names dead properties in a client's own namespace,
     * and dropping them would make the server answer 404 for properties it was
     * asked to look up.
     */
    private fun propNamesOf(prop: Element): List<WebDavXml.QualifiedName> {
        val names = ArrayList<WebDavXml.QualifiedName>()
        // childNodes is an org.w3c.dom.NodeList, which is neither a Kotlin
        // Iterable nor a Java Iterable: `for (node in …)` does not resolve, and
        // the extension that does resolve is ambiguous. Indexed access is the
        // portable form.
        val children = prop.childNodes
        for (i in 0 until children.length) {
            val node = children.item(i)
            if (node is Element) {
                names += WebDavXml.QualifiedName(node.prefix ?: "", node.localName ?: node.nodeName).apply {
                    namespaceUri = node.namespaceURI ?: ""
                }
            }
        }
        return names
    }
}
