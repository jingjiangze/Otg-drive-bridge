package com.jingjiangze.otgdrivebridge.webdav

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Builds the WebDAV XML responses.
 *
 * Windows' MRxDAV redirector is strict about namespaces: it expects the
 * standard `DAV:` prefix bound as `D:` in the multistatus, and a missing or
 * default-namespace-only response yields empty/incorrect directory listings.
 * The reference implementation learned this the hard way (issue reports of
 * "0 files" on Windows), so every element here is emitted with the explicit
 * `D:` prefix.
 */
object WebDavXml {

    private val HTTP_DATE: DateTimeFormatter =
        DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC)

    /** RFC 1123 date for `getlastmodified`. */
    fun httpDate(epochMillis: Long): String = HTTP_DATE.format(Instant.ofEpochMilli(epochMillis))

    /** ISO-8601 UTC for `getetag`-style properties and Last-Modified headers. */
    fun isoDate(epochMillis: Long): String =
        DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(epochMillis))

    fun escape(text: String): String = buildString(text.length) {
        for (ch in text) {
            when (ch) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\'' -> append("&apos;")
                else -> append(ch)
            }
        }
    }

    /**
     * Emits a `<D:response>` entry. [href] must already be percent-encoded and
     * root-relative (starting with "/").
     */
    fun response(
        href: String,
        node: DavNode?,
        mimeType: String,
        includeContentLength: Boolean = true
    ): String = buildString {
        append("<D:response><D:href>").append(escape(href)).append("</D:href>")
        append("<D:propstat><D:prop>")
        append("<D:displayname>").append(escape(node?.name ?: href.trimEnd('/').substringAfterLast('/'))).append("</D:displayname>")
        append("<D:iscollection>").append(if (node?.isDirectory == true) "1" else "0").append("</D:iscollection>")
        if (node != null) {
            append("<D:getlastmodified>").append(httpDate(node.lastModified)).append("</D:getlastmodified>")
            append("<D:creationdate>").append(isoDate(node.lastModified)).append("</D:creationdate>")
            if (includeContentLength && !node.isDirectory) {
                append("<D:getcontentlength>").append(node.length).append("</D:getcontentlength>")
            }
            if (!node.isDirectory) {
                append("<D:getcontenttype>").append(escape(mimeType)).append("</D:getcontenttype>")
            }
            append("<D:resourcetype>")
            if (node.isDirectory) append("<D:collection/>")
            append("</D:resourcetype>")
            append("<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope>")
            append("<D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>")
        }
        append("<D:lockdiscovery/>")
        append("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")
    }

    /** Wraps [entries] in a multistatus document. */
    fun multistatus(entries: List<String>): String = buildString {
        append("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
        append("<D:multistatus xmlns:D=\"DAV:\">")
        entries.forEach { append(it) }
        append("</D:multistatus>")
    }

    /**
     * Depth 1 collection listing: the collection itself plus its children.
     * [baseHref] is the collection's encoded href (with trailing slash).
     */
    fun collectionListing(
        baseHref: String,
        collection: DavNode,
        children: List<DavNode>,
        mimeTypeOf: (String) -> String
    ): String {
        val entries = ArrayList<String>(children.size + 1)
        entries += response(baseHref, collection, mimeTypeOf(collection.name))
        for (child in children) {
            val childHref = baseHref + WebDavPaths.percentEncode(child.name) +
                if (child.isDirectory) "/" else ""
            entries += response(childHref, child, mimeTypeOf(child.name))
        }
        return multistatus(entries)
    }

    /** LOCK response body. */
    fun lockDiscovery(lock: LockManager.Lock): String = buildString {
        append("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
        append("<D:prop xmlns:D=\"DAV:\"><D:lockdiscovery><D:activelock>")
        append("<D:locktype><D:write/></D:locktype>")
        append("<D:lockscope><D:").append(lock.scope).append("/></D:lockscope>")
        append("<D:depth>").append(lock.depth).append("</D:depth>")
        append("<D:owner>").append(escape(lock.owner)).append("</D:owner>")
        append("<D:timeout>Second-").append((lock.expiresAtMillis - System.currentTimeMillis()) / 1000)
        append("</D:timeout>")
        append("<D:locktoken><D:href>").append(escape(lock.token)).append("</D:href></D:locktoken>")
        append("</D:activelock></D:lockdiscovery></D:prop>")
    }

    /** OPTIONS/`Allow` header value: every method this server implements. */
    const val ALLOWED_METHODS =
        "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK"

    /** DAV compliance class advertised in OPTIONS. */
    const val DAV_HEADER = "1, 2"
}
