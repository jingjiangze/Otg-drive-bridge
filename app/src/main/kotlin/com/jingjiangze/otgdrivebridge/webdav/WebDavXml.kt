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
     *
     * [etag] is the resource's entity tag, emitted as `DAV:getetag` and omitted
     * when null. RFC 4918 §15.6: "The getetag property MUST be defined on any
     * DAV-compliant resource that returns the Etag header." This server returns
     * an `ETag` on `GET`, so leaving the property out of a listing left a sync
     * client no way to ask "has anything in this folder changed" without
     * fetching every file. It is omitted for a collection, because `GET` on one
     * answers a directory index and sends no `ETag` for it to mirror.
     *
     * [extraPropstats] are additional `<D:propstat>` blocks for this resource —
     * the dead-property block a PROPFIND adds, for instance. They must arrive as
     * *complete* `<D:propstat>...</D:propstat>` elements, because the multistatus
     * DTD is `(response+, error?)`: a propstat after `</D:response>` is not a
     * child of anything and makes the whole document invalid. Concatenating to
     * the return value of this function is exactly how that happens, which is
     * why the parameter exists instead.
     */
    fun response(
        href: String,
        node: DavNode?,
        mimeType: String,
        includeContentLength: Boolean = true,
        extraPropstats: List<String> = emptyList(),
        etag: String? = null
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
                if (etag != null) {
                    append("<D:getetag>").append(escape(etag)).append("</D:getetag>")
                }
            }
            append("<D:resourcetype>")
            if (node.isDirectory) append("<D:collection/>")
            append("</D:resourcetype>")
            append("<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope>")
            append("<D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>")
        }
        append("<D:lockdiscovery/>")
        append("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>")
        // Extra propstats go *before* `</D:response>`, so they are children of
        // this response and not orphans the parser will reject.
        extraPropstats.forEach { append(it) }
        append("</D:response>")
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
     *
     * [etagOf] supplies each child's entity tag for `DAV:getetag`; the default
     * omits the property, which is what a caller with no tag to give (a
     * directory index, say) wants.
     *
     * [extraForCollection] are extra `<D:propstat>` blocks for the collection's
     * own `<D:response>` — complete elements, passed in rather than concatenated
     * to the result, because the multistatus DTD is `(response+, error?)` and
     * anything after `</D:multistatus>` is not a child of anything.
     */
    fun collectionListing(
        baseHref: String,
        collection: DavNode,
        children: List<DavNode>,
        mimeTypeOf: (String) -> String,
        extraForCollection: List<String> = emptyList(),
        etagOf: (DavNode) -> String? = { null }
    ): String {
        val entries = ArrayList<String>(children.size + 1)
        entries += response(
            baseHref,
            collection,
            mimeTypeOf(collection.name),
            extraPropstats = extraForCollection,
            etag = etagOf(collection)
        )
        for (child in children) {
            val childHref = baseHref + WebDavPaths.percentEncode(child.name) +
                if (child.isDirectory) "/" else ""
            entries += response(childHref, child, mimeTypeOf(child.name), etag = etagOf(child))
        }
        return multistatus(entries)
    }

    /**
     * One `<D:propstat>` block for a PROPPATCH result: the properties that share
     * [status], listed by their qualified XML name in [propNames].
     *
     * A PROPPATCH response is a multistatus of these blocks, one per outcome —
     * RFC 4918 §9.2 requires the 200 block for what was stored and a 403 block
     * naming `cannot-modify-protected-property` for what was refused, never a
     * single blanket status for the whole request.
     *
     * The client's prefixes are echoed, so their `xmlns:` bindings are declared
     * here — see [namespaceDeclarationsFor].
     */
    fun proppatchPropstat(
        propNames: List<QualifiedName>,
        status: HttpStatus,
        condition: String? = null
    ): String = buildString {
        append("<D:propstat").append(namespaceDeclarationsFor(propNames)).append('>')
        append("<D:prop>")
        for (prop in propNames) {
            // No namespace means no prefix — see [deadPropertiesPropstat]. The
            // test is the URI, not the prefix, because the handler synthesizes
            // `p0`, `p1`… per distinct URI and a synthetic prefix with an empty
            // URI is exactly the illegal binding this must not emit.
            append('<').append(qualifiedTagOf(prop)).append("/>")
        }
        append("</D:prop>")
        if (condition != null) {
            append("<D:error><D:").append(condition).append("/></D:error>")
        }
        append("<D:status>HTTP/1.1 ").append(status.code).append(' ').append(status.reason)
        append("</D:status></D:propstat>")
    }

    /**
     * A `<D:propstat>` listing dead properties **with their values** — the shape
     * a PROPFIND needs, as opposed to [proppatchPropstat] which lists names only
     * because that is all a PROPPATCH *response* carries (RFC 4918 §9.2).
     *
     * A PROPPATCH that stores `Z:marker = hello` followed by a PROPFIND that
     * answers `<Z:marker/>` has not actually given the client its own data
     * back: Windows Explorer's comment column and most sync tools' bookkeeping
     * would come up empty while the round trip *looked* successful. RFC 4918
     * §9.1's allprop form — what a body-less PROPFIND is — returns values, so
     * this does too.
     *
     * The client's own prefix is echoed back, so the `xmlns:` binding that makes
     * it a legal name has to be declared too. [namespaceDeclarationsFor] puts it
     * on this element, where it scopes to exactly the properties that use it —
     * without it `<Z:marker>` is an unbound prefix and every namespace-aware
     * parser rejects the whole multistatus, which would silently reintroduce the
     * empty-listing bug this readback exists to fix.
     */
    fun deadPropertiesPropstat(properties: List<Pair<QualifiedName, String>>): String = buildString {
        append("<D:propstat").append(namespaceDeclarationsFor(properties.map { it.first })).append('>')
        append("<D:prop>")
        for ((name, value) in properties) {
            // A property with no namespace is emitted **unprefixed**: the only
            // way to say "no namespace" in XML is an unprefixed element with no
            // default declaration in scope (or `xmlns=""`, which means the same
            // thing). Emitting `<Z:plain>` with `xmlns:Z=""` looks equivalent but
            // is not — a prefixed namespace binding may not be empty, so every
            // namespace-aware parser rejects the document (measured: "带前缀的
            // 名称空间绑定不能为空"). That is the empty-listing bug in a new
            // coat: the value is stored, the readback is unparseable.
            //
            // The decision is made on the **namespace URI**, not the prefix: the
            // handler synthesizes `p0`, `p1`… per distinct URI to echo a URI back
            // (a URI contains `:` and `/` and cannot itself be a prefix), so a
            // property in no namespace arrives here as prefix `p0` with URI `""`.
            append('<').append(qualifiedTagOf(name)).append('>')
            append(escape(value))
            append("</").append(qualifiedTagOf(name)).append('>')
        }
        append("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>")
    }

    /**
     * The XML tag for [name]: `prefix:local` normally, bare `local` when the
     * property is in no namespace.
     *
     * Shared by every builder that emits a client-supplied name, so the
     * "no namespace ⇒ unprefixed" rule lives in one place instead of being
     * re-derived (and re-broken) per call site.
     */
    private fun qualifiedTagOf(name: QualifiedName): String =
        if (name.namespaceUri.isEmpty()) name.local else "${name.prefix}:${name.local}"

    /** Wraps [propstats] for one resource into a `<D:response>`. */
    fun proppatchResponse(href: String, propstats: List<String>): String = buildString {
        append("<D:response><D:href>").append(escape(href)).append("</D:href>")
        propstats.forEach { append(it) }
        append("</D:response>")
    }

    /** An HTTP status line's code plus reason phrase, for `<D:status>`. */
    class HttpStatus(val code: Int, val reason: String) {
        companion object {
            val OK = HttpStatus(200, "OK")
            val FORBIDDEN = HttpStatus(403, "Forbidden")
            val CONFLICT = HttpStatus(409, "Conflict")
        }
    }

    /**
     * `xmlns:` declarations for the prefixes [names] actually use, as a leading
     * `" xmlns:X=\"uri\"..."` fragment (empty when there are none to declare).
     *
     * A prefix is only a name once it is bound: an element `<Z:marker>` with no
     * `xmlns:Z` anywhere in scope is not namespace-well-formed, and the parsers
     * that matter here — Go's `x/net/webdav`, Windows' MiniRedir, litmus — all
     * reject the document outright rather than guess the URI. Declaring on the
     * element that uses the prefix scopes the binding to exactly the properties
     * that need it, so two properties from different namespaces can share one
     * propstat and a client that sends its own prefix reads back the same name
     * it wrote.
     *
     * The `DAV:` prefix is never declared here: every builder in this object
     * already emits `xmlns:D="DAV:"` on its root element.
     *
     * A name whose **namespace URI** is empty is skipped entirely here and
     * emitted unprefixed by its builder — a prefixed binding to "" is not legal
     * XML (a prefix may only be bound to a non-empty URI, or undeclared relative
     * to an ancestor that bound it), so declaring one would make the response
     * unparseable for exactly the clients this is meant to serve. No namespace is
     * a different place from the empty-namespace URI and must not be merged with
     * it, which the `{}` store key keeps distinct.
     *
     * The test is the **URI**, not the prefix: `deadPropertiesPropstats` in the
     * request handler generates a synthetic `p0`, `p1`… prefix per distinct
     * namespace URI precisely so that a URI — which contains `:` and `/` and is
     * therefore not a legal prefix — can still be echoed back. For a property in
     * no namespace that generation yields prefix `p0` with URI `""`, which is
     * exactly the illegal binding this guard exists to prevent. (Measured: the
     * readback emitted `<D:propstat xmlns:p0=""><p0:plain>` before the guard was
     * keyed on the URI.) No prefix is a subset of this and stays covered.
     */
    fun namespaceDeclarationsFor(names: List<QualifiedName>): String {
        val seen = LinkedHashMap<String, String>()
        for (name in names) {
            // `D` is already bound to `DAV:` on the root element of every builder
            // here, so declaring it again is redundant — and would be wrong if a
            // client bound `D` to something else, because the emitted element
            // would then name a *different* property than the client sent. The
            // parser refuses those: `isProtected` compares URIs, not prefixes.
            if (name.prefix == "D") continue
            // Nothing to bind when the property is in no namespace at all: see
            // the KDoc above.
            if (name.namespaceUri.isEmpty()) continue
            // One prefix, two URIs, is not expressible in XML. The first wins;
            // the duplicate keeps a name it can legally be read back by.
            val existing = seen[name.prefix]
            if (existing == null || existing != name.namespaceUri) seen.putIfAbsent(name.prefix, name.namespaceUri)
        }
        if (seen.isEmpty()) return ""
        return buildString {
            for ((prefix, uri) in seen) {
                append(" xmlns:").append(prefix).append("=\"").append(escape(uri)).append('"')
            }
        }
    }

    /**
     * A property name split into its XML prefix and local part.
     *
     * The prefix is the *document's* prefix, not the namespace URI: it is what
     * the client sent and what it will read back. Storing only the URI would
     * force every response to invent a prefix the client never used.
     *
     * Identity, though, is the namespace URI — RFC 4918 §4.4 keys a dead
     * property by `{namespace}local`, and two clients' `author` properties are
     * different properties. [qualified] is therefore only a *storage key*, and
     * two names collide there exactly when they share a prefix *and* local part
     * regardless of namespace — which is why the handler stores the namespace
     * alongside it rather than relying on this string.
     *
     * [namespaceUri] is a `var` so a parser can attach what it read from the
     * document without changing the equality this class is used for (prefix +
     * local, which is the response identity).
     */
    class QualifiedName(val prefix: String, val local: String) {
        /** `prefix:local` — the key a [DavPropertyStore] stores under. */
        val qualified: String get() = "$prefix:$local"

        /** Bound namespace URI, filled in by the parser; "" when unknown. */
        var namespaceUri: String = ""
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

    /**
     * RFC 4918 §16 condition codes — the **complete** set that document defines
     * in the `DAV:` namespace.
     *
     * Everything a conforming WebDAV client knows how to parse lives here.
     * Names that circulate in tutorials (`resource-must-be-null`,
     * `valid-resourcetype`, `needs-privileges`, `min-ttl`,
     * `quota-not-exceeded`, `number-of-matches-within-limits`,
     * `valid-sync-token`) come from RFC 3744 or vendor extensions and are
     * **not** part of RFC 4918; emitting them as if they were would make a
     * conforming client reject the whole error body.
     */
    object Conditions {
        const val LOCK_TOKEN_MATCHES_REQUEST_URI = "lock-token-matches-request-uri"
        const val LOCK_TOKEN_SUBMITTED = "lock-token-submitted"
        const val NO_CONFLICTING_LOCK = "no-conflicting-lock"
        const val NO_EXTERNAL_ENTITIES = "no-external-entities"
        const val PRESERVED_LIVE_PROPERTIES = "preserved-live-properties"
        const val PROPFIND_FINITE_DEPTH = "propfind-finite-depth"
        const val CANNOT_MODIFY_PROTECTED_PROPERTY = "cannot-modify-protected-property"
    }

    /**
     * Builds an RFC 4918 §14.5 `<D:error>` body.
     *
     * `<!ELEMENT error ANY>` means "at least one XML element" — no bare text and
     * no mixed content, which is exactly what the old plain-text reason phrases
     * produced. A client that parses the body (Go's `x/net/webdav`, Windows
     * MiniRedir and litmus all do) found nothing it understood and had to fall
     * back to the status code alone.
     *
     * [conditions] are element names in the `DAV:` namespace, i.e. members of
     * [Conditions]. An empty list is not expressible in the RFC — every
     * `<error>` must carry at least one element — so it falls back to the
     * custom-namespace escape hatch §16 permits for conditions it does not
     * define, rather than inventing a `DAV:` name.
     */
    fun error(vararg conditions: String): String = buildString {
        append("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
        append("<D:error xmlns:D=\"DAV:\"")
        if (conditions.isEmpty()) append(" xmlns:Z=\"https://jingjiangze.otgdrivebridge/ns#\"")
        append(">")
        if (conditions.isEmpty()) {
            append("<Z:condition-not-mapped/>")
        } else {
            for (condition in conditions) append("<D:").append(condition).append("/>")
        }
        append("</D:error>")
    }
}
