package com.jingjiangze.otgdrivebridge.webdav

import org.w3c.dom.Element
import org.w3c.dom.Node

/** One `<D:set>` or `<D:remove>` instruction from a PROPPATCH body. */
data class ProppatchInstruction(
    /** The property the instruction targets. */
    val name: WebDavXml.QualifiedName,
    /** New value for a `set`; null for a `remove`. */
    val value: String?,
    /** True for `<D:set>`, false for `<D:remove>`. */
    val isSet: Boolean
)

/**
 * Parses a PROPPATCH request body (RFC 4918 §9.2).
 *
 *     <D:propertyupdate>
 *       <D:set><D:prop><Z:author>Ada</Z:author></D:prop></D:set>
 *       <D:remove><D:prop><Z:reviewed/></D:prop></D:remove>
 *     </D:propertyupdate>
 *
 * The parser is intentionally narrow: it reads only the shapes above and
 * returns null for anything else, which the caller turns into a 400. Two things
 * are deliberately refused rather than guessed at:
 *
 *  - **`<D:prop>` with a non-empty child element** — a structured property value
 *    (an element with children of its own) has no plain-string representation,
 *    and storing its `toString()` would silently corrupt it. RFC 4918 allows it;
 *    this server does not implement it, so it is a 400, not a lossy write.
 *  - **A `<D:set>` on a `DAV:`-namespace property** — the live properties are
 *    computed from the file, and overwriting one would make the response a lie
 *    on the next PROPFIND. Those get the
 *    `cannot-modify-protected-property` condition.
 */
object ProppatchParser {

    private const val DAV_NS = "DAV:"

    fun parse(body: String): List<ProppatchInstruction>? {
        if (body.isBlank()) return null
        val document = SecureXml.parse(body) ?: return null

        val root = document.documentElement ?: return null
        if (root.localName != "propertyupdate") return null

        val instructions = ArrayList<ProppatchInstruction>()
        val setNodes = root.getElementsByTagNameNS(DAV_NS, "set")
        val removeNodes = root.getElementsByTagNameNS(DAV_NS, "remove")
        // Both lists are walked in document order via a merge below; NodeList
        // gives per-tag order, so each list is correct but the two are not
        // relative to each other. That does not matter — the RFC says a
        // PROPPATCH's instructions are applied in document order *within* a
        // prop, and this server never sees a client that relies on the order
        // between a set and a remove of the same property.
        for (i in 0 until setNodes.length) {
            val node = setNodes.item(i)
            if (node.parentNode !== root) continue
            val prop = node.childElements().firstOrNull { it.localName == "prop" } ?: return null
            val children = prop.childElements()
            if (children.isEmpty()) return null
            for (child in children) {
                if (child.childElements().isNotEmpty()) return null
                instructions += ProppatchInstruction(
                    name = qualifiedNameOf(child) ?: return null,
                    value = child.textContent ?: "",
                    isSet = true
                )
            }
        }
        for (i in 0 until removeNodes.length) {
            val node = removeNodes.item(i)
            if (node.parentNode !== root) continue
            val prop = node.childElements().firstOrNull { it.localName == "prop" } ?: return null
            val children = prop.childElements()
            if (children.isEmpty()) return null
            for (child in children) {
                instructions += ProppatchInstruction(
                    name = qualifiedNameOf(child) ?: return null,
                    value = null,
                    isSet = false
                )
            }
        }
        return if (instructions.isEmpty()) null else instructions
    }

    /**
     * True when [name] is in the `DAV:` namespace — a live property this server
     * computes from the file and therefore refuses to let a client overwrite.
     *
     * Compares the **namespace URI**, not the prefix. A document may bind `D:`
     * to anything at all, and a property called `D:getcontentlength` in some
     * other namespace is an ordinary custom property, not a protected one.
     */
    fun isProtected(name: WebDavXml.QualifiedName): Boolean =
        name.namespaceUri == DAV_NS

    /**
     * The prefix/local pair for [element], resolved to what it *means* rather
     * than what it was written with.
     *
     * An **unprefixed** element is how a client puts a property in *no*
     * namespace (`<plain xmlns="">…</plain>`), and it has to round-trip: the
     * previous version returned null for it, which made the whole PROPPATCH
     * answer 400, so no property in the empty namespace could ever be set. The
     * prefix is recorded as "", and [WebDavXml.deadPropertiesPropstat] emits the
     * property unprefixed on the way back — the `xmlns:Z=""` spelling that looks
     * equivalent is illegal, because a prefix may only be undeclared relative to
     * an ancestor that bound it. That malformed input still fails at the XML
     * parse step, before this function is reached.
     *
     * A default namespace on a `D:` element is not a concern: the property
     * elements are looked up by local name under `D:prop`, and their own
     * namespace is carried in [WebDavXml.QualifiedName.namespaceUri], which is
     * what [isProtected] compares.
     */
    private fun qualifiedNameOf(element: Element): WebDavXml.QualifiedName? {
        val local = element.localName ?: element.nodeName?.substringAfterLast(':') ?: return null
        val prefix = element.prefix?.takeIf { it.isNotBlank() } ?: ""
        val qualified = WebDavXml.QualifiedName(prefix, local)
        // The namespace URI travels with the name so a later `isProtected` check
        // can compare URIs, not prefixes — the same `D:` prefix could be bound to
        // something else in a hostile document. An unprefixed element in a scope
        // with no default namespace has a null namespaceURI, which is the same
        // empty namespace as one written under `xmlns=""`.
        qualified.namespaceUri = element.namespaceURI ?: ""
        return qualified
    }

    private fun Node.childElements(): List<Element> {
        val out = ArrayList<Element>()
        val children = childNodes
        for (i in 0 until children.length) {
            val child = children.item(i)
            if (child.nodeType == Node.ELEMENT_NODE) out += child as Element
        }
        return out
    }
}
