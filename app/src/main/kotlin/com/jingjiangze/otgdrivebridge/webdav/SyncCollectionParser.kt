package com.jingjiangze.otgdrivebridge.webdav

import org.w3c.dom.Element

/**
 * One parsed `DAV:sync-collection` REPORT body (RFC 6578 §3.2 / §6.1):
 *
 *     <!ELEMENT sync-collection (sync-token, sync-level, limit?, prop)>
 */
data class SyncCollectionRequest(
    /**
     * The token the client last saw, or null for an initial sync (§3.4: an
     * empty `DAV:sync-token` element means "return all member URLs"). Kept as
     * the raw string: whether it is one *this server* issued is the caller's
     * precondition to check, because it alone knows its token namespace.
     */
    val syncToken: String?,
    /** `"1"` (immediate children) or `"infinite"` — §6.3. Recorded, not yet branched on. */
    val syncLevel: String,
    /** The properties to return for each changed member (§6.1's `prop`). */
    val propNames: List<WebDavXml.QualifiedName>
)

/**
 * Parses a `DAV:sync-collection` report request body.
 *
 * `limit` (RFC 5323 §5.17) is accepted and ignored: the spec's own recovery for
 * a result set the server could not truncate is the
 * `DAV:number-of-matches-within-limits` postcondition, and this server's
 * collections are small enough that truncation never engages. Rejecting the
 * element outright would refuse bodies conforming clients legitimately send.
 *
 * A missing `sync-token`/`sync-level`/`prop` is null rather than defaulted:
 * §6.1's element list has no optional member except `limit`, and a body missing
 * a required one is malformed, not lenient.
 */
object SyncCollectionParser {

    fun parse(body: String): SyncCollectionRequest? {
        if (body.isBlank()) return null
        val document = SecureXml.parse(body) ?: return null
        val root = document.documentElement ?: return null
        if (root.namespaceURI != WebDavXml.DAV_NS || root.localName != "sync-collection") return null

        var token: String? = null
        var tokenSeen = false
        var level: String? = null
        val propNames = ArrayList<WebDavXml.QualifiedName>()
        // NodeList is not Iterable in Kotlin, so this walks by index — see
        // PropfindParser for why.
        val children = root.childNodes
        for (i in 0 until children.length) {
            val child = children.item(i)
            if (child !is Element || child.namespaceURI != WebDavXml.DAV_NS) continue
            when (child.localName) {
                "sync-token" -> {
                    tokenSeen = true
                    token = child.textContent.trim().ifEmpty { null }
                }
                "sync-level" -> level = child.textContent.trim()
                "prop" -> {
                    val props = child.childNodes
                    for (k in 0 until props.length) {
                        val node = props.item(k)
                        if (node is Element) {
                            propNames += WebDavXml.QualifiedName(node.prefix ?: "", node.localName ?: node.nodeName)
                                .apply { namespaceUri = node.namespaceURI ?: "" }
                        }
                    }
                }
                // `limit` — ignored, see the class comment.
            }
        }
        if (!tokenSeen || level == null || propNames.isEmpty()) return null
        return SyncCollectionRequest(token, level, propNames)
    }
}
