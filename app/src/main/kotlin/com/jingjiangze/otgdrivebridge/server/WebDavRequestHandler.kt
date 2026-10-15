package com.jingjiangze.otgdrivebridge.server

import com.jingjiangze.otgdrivebridge.security.CredentialGenerator
import com.jingjiangze.otgdrivebridge.security.DigestAuthenticator
import com.jingjiangze.otgdrivebridge.webdav.DavNode
import com.jingjiangze.otgdrivebridge.webdav.DavPropertyStore
import com.jingjiangze.otgdrivebridge.webdav.DavStorage
import com.jingjiangze.otgdrivebridge.webdav.LockManager
import com.jingjiangze.otgdrivebridge.webdav.ProppatchParser
import com.jingjiangze.otgdrivebridge.webdav.WebDavPaths
import com.jingjiangze.otgdrivebridge.webdav.WebDavXml
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondText
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Dispatches a WebDAV request onto a [DavStorage].
 *
 * Kept separate from the Ktor wiring so the method-by-method behaviour can be
 * tested against an in-memory/temp storage without an HTTP server.
 *
 * Responsibilities:
 *  - method allow-listing and 405 responses
 *  - path normalisation and traversal rejection (400)
 *  - Depth 0/1/infinity PROPFIND
 *  - atomic PUT with Content-Length validation
 *  - LOCK/UNLOCK with `If:` token matching
 */
class WebDavRequestHandler(
    private val storage: DavStorage,
    private val authenticator: DigestAuthenticator,
    private val lockManager: LockManager = LockManager(),
    private val maxUploadBytes: Long = DEFAULT_MAX_UPLOAD_BYTES,
    private val propertyStore: DavPropertyStore = DavPropertyStore()
) {

    /** Mutable per-request state, reset on every [handle] call. */
    private class RequestState {
        var username: String = "-"
        var method: String = "OPTIONS"
        var path: String = "/"
        var status: Int = 200
    }

    private val state = RequestState()

    /** Set by [handle] so response helpers can log the outcome. */
    var onCompleted: ((method: String, path: String, username: String, status: Int) -> Unit)? = null

    suspend fun handle(call: ApplicationCall): Boolean {
        state.method = call.request.httpMethod.value.uppercase()
        state.path = call.request.path()
        state.username = "-"
        state.status = 200

        // OPTIONS is answered without credentials so clients can probe capabilities.
        if (state.method == "OPTIONS") {
            handleOptions(call)
            return true
        }

        val header = call.request.headers["Authorization"]
        val parsed = DigestAuthenticator.parseHeader(header)
        if (parsed == null || !verifyAuth(call, parsed)) {
            respondChallenge(call)
            return true
        }
        state.username = parsed.username

        val handled = when (state.method) {
            "GET", "HEAD" -> handleGet(call)
            "PUT" -> handlePut(call)
            "DELETE" -> handleDelete(call)
            "MKCOL" -> handleMkcol(call)
            "PROPFIND" -> handlePropfind(call)
            "PROPPATCH" -> handleProppatch(call)
            "COPY" -> handleCopyOrMove(call, isMove = false)
            "MOVE" -> handleCopyOrMove(call, isMove = true)
            "LOCK" -> handleLock(call)
            "UNLOCK" -> handleUnlock(call)
            else -> {
                respondText(call, "405 Method Not Allowed", HttpStatusCode.MethodNotAllowed)
                false
            }
        }
        return handled
    }

    // ---------------------------------------------------------------- methods

    private suspend fun handleOptions(call: ApplicationCall) {
        call.response.header("DAV", WebDavXml.DAV_HEADER)
        call.response.header("MS-Author-Via", "DAV")
        call.response.header("Allow", WebDavXml.ALLOWED_METHODS)
        call.response.header("Accept-Ranges", "bytes")
        // No Content-Length here. Ktor's `respondText` builds a `TextContent`,
        // whose `contentLength` is `bytes.size` — 0 for an empty string — and
        // `BaseApplicationResponse.commitHeaders` appends its own Content-Length
        // from that. `ApplicationResponse.header()` *appends* rather than
        // replaces, and `Content-Length` is not in Ktor's unsafe-header list, so
        // setting it here produced a second, duplicate header: standard HTTP
        // clients (Node's llhttp among them) reject the whole response with
        // HPE_UNEXPECTED_CONTENT_LENGTH. Measured twice on the device before
        // the fix — see _tmp/interop-2026-10-15/findings.md.
        respondText(call, "", HttpStatusCode.OK)
    }

    private suspend fun handleGet(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        val node = storage.node(segments) ?: return respondText(
            call, "404 Not Found", HttpStatusCode.NotFound
        )

        // RFC 7231 §4.3.2: a HEAD is "identical to GET except that the server
        // MUST NOT send a message body". It is not a PROPFIND. The directory
        // branch used to sit above this one, so `HEAD /` answered
        // 207 + a full multistatus document — a protocol violation and a
        // broken response for a client that reads Content-Length and stops.
        //
        // The length reported is the *file's* for a file and 0 for a collection,
        // which has no content of its own. `respondText("")` cannot express the
        // file case: `TextContent.contentLength` is `bytes.size` (0), and
        // `BaseApplicationResponse.commitHeaders` appends its own Content-Length
        // from it — so the old hand-set
        // `header("Content-Length", node.length)` produced a **duplicate**
        // `Content-Length` pair (measured on-device twice; standard parsers
        // such as Node's llhttp reject the whole response with
        // HPE_UNEXPECTED_CONTENT_LENGTH). Ktor has no HEAD body suppression
        // of its own (`isHead` does not exist anywhere in ktor-server 2.3.12
        // — verified against all 157 non-test .kt files of ktor-server-core /
        // -cio / -host-common / ktor-http), so the fix is a response object
        // whose declared length and payload diverge.
        //
        // The read stream is opened only below this branch: a HEAD never reads
        // it, and opening one per HEAD leaked a file descriptor per request
        // against the SAF document provider.
        if (state.method == "HEAD") {
            // RFC 7231 §4.3.2: a HEAD is "identical to GET except that the
            // server MUST NOT send a message body", which includes the header
            // fields — and it says so explicitly ("The server SHOULD send the
            // same header fields in response to a HEAD request as it would have
            // sent if the request had been a GET"). This branch used to answer
            // with `Content-Length` alone, so the cheapest "has this changed?"
            // question a client can ask returned nothing to compare against and
            // it had to fall back to a full GET.
            //
            // Only for a file: `GET` on a collection answers a directory index
            // and sends neither header, so a collection's HEAD must not invent
            // them either.
            if (!node.isDirectory) {
                call.response.header("ETag", etagOf(node))
                call.response.header("Last-Modified", WebDavXml.httpDate(node.lastModified))
                call.response.header("Accept-Ranges", "bytes")
            }
            respondEmptyBody(call, if (node.isDirectory) 0L else node.length)
            return true
        }

        if (node.isDirectory) {
            // Windows Explorer navigates directories; serve a minimal listing.
            return respondDirectoryIndex(call, segments, node)
        }

        val stream = storage.openRead(node) ?: return respondText(
            call, "500 Could not open file", HttpStatusCode.InternalServerError
        )
        val mime = storage.mimeTypeOf(node.name)
        call.response.header("ETag", etagOf(node))
        call.response.header("Last-Modified", WebDavXml.httpDate(node.lastModified))
        call.response.header("Accept-Ranges", "bytes")
        call.respondBytes(
            contentType = io.ktor.http.ContentType.parse(mime),
            status = HttpStatusCode.OK,
            provider = { readAll(stream) }
        )
        return true
    }

    private suspend fun handlePut(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        if (segments.isEmpty()) return respondText(call, "405 Cannot PUT the root", HttpStatusCode.MethodNotAllowed)

        val declaredLength = call.request.headers["Content-Length"]?.toLongOrNull()
        if (declaredLength != null && declaredLength > maxUploadBytes) {
            return respondText(call, "413 Payload Too Large", HttpStatusCode.PayloadTooLarge)
        }

        val (parent, leaf) = storage.parentOf(segments) ?: return respondText(
            call, "409 Conflict — parent missing", HttpStatusCode.Conflict
        )
        if (lockManager.isLockedByOther(state.path, call.request.headers["If"])) {
            return respondLocked(call)
        }
        val existing = storage.node(segments)
        if (existing != null && existing.isDirectory) {
            return respondText(call, "405 Target is a collection", HttpStatusCode.MethodNotAllowed)
        }

        // RFC 7232 §3.1/§3.2 conditional writes. Both headers are honoured
        // *before* a single byte is staged, so a rejected request leaves the
        // existing file exactly as it was.
        //   If-None-Match: *  → fail when the target already exists
        //                      (RFC 4918 §10.4 "create only if new")
        //   If-Match: <etag> → fail unless the current entity matches
        //   If-Match: *      → fail unless the target already exists
        // Measured on-device: PUT ignored both headers entirely
        // (`grep If-Match app/src/main` = 0 hits) and overwrote unconditionally,
        // so two clients editing the same document silently dropped the first
        // one's work — a lost-update, not just a spec gap.
        val existingEtag = if (existing == null) null else etagOf(existing)
        val ifMatch = call.request.headers["If-Match"]
        if (!ifMatch.isNullOrBlank()) {
            val wanted = ifMatch.trim()
            // Bound to a local so the compiler can see it is non-null here: the
            // guard above already returned when the resource does not exist, but
            // that does not smart-cast a property read.
            val current = existingEtag
            // RFC 7232 §3.1: `If-Match: *` means "true if the resource exists".
            // Treating it as an unconditional pass turned a create-if-exists
            // guard into a blind overwrite, which is the opposite of what the
            // header asks for — and the failure mode is silent data loss.
            if (wanted == "*") {
                if (existing == null) return preconditionFailed(call, "resource does not exist")
            } else if (current == null || !etagMatches(wanted, current)) {
                return preconditionFailed(call, "ETag mismatch")
            }
        }
        val ifNoneMatch = call.request.headers["If-None-Match"]
        if (!ifNoneMatch.isNullOrBlank() && ifNoneMatch.trim() == "*" && existing != null) {
            return preconditionFailed(call, "resource already exists")
        }

        val target = existing ?: storage.createFile(parent, leaf) ?: return respondText(
            call, "500 Could not create file", HttpStatusCode.InternalServerError
        )
        val handle = storage.openWrite(target, overwrite = true) ?: return respondText(
            call, "403 Read-only or unavailable", HttpStatusCode.Forbidden
        )

        var written = 0L
        try {
            val channel = call.receiveChannel()
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = channel.readAvailable(buffer, 0, buffer.size)
                if (read <= 0) break
                handle.output.write(buffer, 0, read)
                written += read
                if (written > maxUploadBytes) {
                    handle.abort()
                    return respondText(call, "413 Payload Too Large", HttpStatusCode.PayloadTooLarge)
                }
            }
            if (declaredLength != null && written != declaredLength) {
                // Client announced N bytes but sent fewer: the transfer was cut
                // short. Do not publish a truncated file onto the USB drive.
                handle.abort()
                return respondText(call, "400 Content-Length mismatch", HttpStatusCode.BadRequest)
            }
            if (!handle.commit()) {
                handle.abort()
                return respondText(call, "500 Write failed", HttpStatusCode.InternalServerError)
            }
        } catch (t: Throwable) {
            handle.abort()
            return respondText(call, "400 Upload failed", HttpStatusCode.BadRequest)
        } finally {
            handle.close()
        }

        // The ETag must be derived the same way GET derives it
        // (`"<lastModified>-<length>"`), or a client that caches the value from
        // one response cannot use it in the other — `If-Match` would then fail
        // against a perfectly good file. The old value
        // (`"<currentTimeMillis>-<written>"`) was a second, incompatible
        // scheme that also changed on every request.
        call.response.header("ETag", etagOf(target))
        respondText(call, "", if (existing == null) HttpStatusCode.Created else HttpStatusCode.NoContent)
        return true
    }

    private suspend fun handleDelete(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        if (segments.isEmpty()) return respondText(call, "405 Cannot DELETE the root", HttpStatusCode.MethodNotAllowed)
        if (lockManager.isLockedByOther(state.path, call.request.headers["If"])) {
            return respondLocked(call)
        }
        val node = storage.node(segments) ?: return respondText(call, "404 Not Found", HttpStatusCode.NotFound)
        return if (storage.delete(node)) {
            respondText(call, "", HttpStatusCode.NoContent)
        } else {
            respondText(call, "403 Delete failed", HttpStatusCode.Forbidden)
        }
    }

    private suspend fun handleMkcol(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        if (segments.isEmpty()) return respondText(call, "405 Cannot MKCOL the root", HttpStatusCode.MethodNotAllowed)
        val (parent, leaf) = storage.parentOf(segments) ?: return respondText(
            call, "409 Conflict — parent missing", HttpStatusCode.Conflict
        )
        if (storage.node(segments) != null) {
            return respondText(call, "405 Already exists", HttpStatusCode.MethodNotAllowed)
        }
        return if (storage.createDirectory(parent, leaf) != null) {
            respondText(call, "", HttpStatusCode.Created)
        } else {
            respondText(call, "403 MKCOL failed", HttpStatusCode.Forbidden)
        }
    }

    private suspend fun handlePropfind(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        val node = storage.node(segments) ?: return respondDavError(
            call, HttpStatusCode.NotFound, reason = "Not Found"
        )
        val depth = (call.request.headers["Depth"] ?: "1").lowercase()
        val href = if (node.isDirectory) WebDavPaths.encodeCollectionHref(segments) else WebDavPaths.encodeHref(segments)

        val body = if (!node.isDirectory || depth == "0") {
            WebDavXml.multistatus(
                listOf(
                    WebDavXml.response(
                        href,
                        node,
                        storage.mimeTypeOf(node.name),
                        extraPropstats = deadPropertiesPropstats(segments),
                        etag = etagOf(node)
                    )
                )
            )
        } else {
            val children = node.listChildren().sortedWith(
                compareByDescending<DavNode> { it.isDirectory }.thenBy { it.name.lowercase() }
            )
            WebDavXml.collectionListing(
                href,
                node,
                children,
                { storage.mimeTypeOf(it) },
                deadPropertiesPropstats(segments),
                etagOf = { etagOf(it) }
            )
        }
        call.response.header("Depth", depth)
        respondText(
            call,
            body,
            io.ktor.http.ContentType.parse("application/xml; charset=utf-8"),
            HttpStatusCode.MultiStatus
        )
        return true
    }

    /**
     * The `<D:propstat>` blocks naming the dead properties a client stored on
     * this resource, or an empty list when there are none.
     *
     * Returned as a list of complete elements that the caller hands to
     * [WebDavXml.response] / [WebDavXml.collectionListing], which place them
     * inside the resource's own `<D:response>`. The multistatus DTD is
     * `(response+, error?)`, so a propstat concatenated onto the outside of a
     * response is not a child of anything and makes the document unparseable —
     * that is why this is a parameter and not a suffix.
     *
     * Only the resource's own properties are listed, never its children's:
     * returning every stored value for every child would multiply the response
     * size for the common case of a directory with hundreds of entries.
     *
     * The store is keyed by namespace URI (see [DavPropertyStore.set]), and a
     * namespace URI is not a legal XML prefix — it contains `:` and `/`. The
     * client gets back a generated `p0`, `p1`… prefix bound to its own URI, so
     * the name is legal, and the *property* is still the one it stored: identity
     * is the namespace-qualified name, not the prefix the client happened to
     * pick (a prefix is per-document, and two clients routinely both choose
     * `Z` for different namespaces).
     */
    private fun deadPropertiesPropstats(segments: List<String>): List<String> {
        val stored = propertyStore.all(DavPropertyStore.keyOf(segments))
        if (stored.isEmpty()) return emptyList()
        // One generated prefix per distinct namespace URI. The prefix has to
        // carry its URI back to the emitter, or it is unbound in the response —
        // see [WebDavXml.namespaceDeclarationsFor].
        //
        // A property in *no* namespace also reaches this line, with URI "" — and
        // it must not be given a prefix here, because `xmlns:p0=""` is illegal
        // XML (a prefixed binding may not be empty) and would make the whole
        // multistatus unparseable. The emitter decides on the URI and drops the
        // prefix for that case, so this map deliberately holds the empty URI too
        // rather than special-casing it here: the rule lives in one place.
        val prefixByUri = HashMap<String, String>()
        var index = 0
        val pairs = stored.map { (storageKey, value) ->
            val uri = DavPropertyStore.namespaceOf(storageKey)
            val prefix = prefixByUri.getOrPut(uri) { "p${index++}" }
            WebDavXml.QualifiedName(prefix, DavPropertyStore.localOf(storageKey)).also {
                it.namespaceUri = uri
            } to value
        }
        return listOf(WebDavXml.deadPropertiesPropstat(pairs))
    }

    /**
     * PROPPATCH (RFC 4918 §9.2): apply the client's `set`/`remove` instructions
     * to the dead-property store and report per-property outcomes.
     *
     * This used to ignore the request body entirely and echo back the resource's
     * live properties — a 207 that looked like success while nothing was stored.
     * Measured on-device: `PROPPATCH` a `Z:marker` property, then `PROPFIND`
     * it back, and the property was gone. Clients that use custom metadata
     * (Windows Explorer's "comments", most sync tools' bookkeeping) silently
     * lost it.
     *
     * A `set` on a `DAV:`-namespace property is refused with
     * `cannot-modify-protected-property`: those are computed from the file, and
     * storing a client's value would make the next PROPFIND a lie.
     */
    private suspend fun handleProppatch(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        val node = storage.node(segments) ?: return respondDavError(
            call, HttpStatusCode.NotFound, reason = "Not Found"
        )
        val body = runCatching { call.receiveText() }.getOrDefault("")
        val instructions = ProppatchParser.parse(body) ?: return respondDavError(
            call, HttpStatusCode.BadRequest, reason = "Malformed propertyupdate"
        )

        val href = if (node.isDirectory) WebDavPaths.encodeCollectionHref(segments) else WebDavPaths.encodeHref(segments)
        val key = DavPropertyStore.keyOf(segments)
        val stored = ArrayList<WebDavXml.QualifiedName>()
        val refused = ArrayList<WebDavXml.QualifiedName>()

        for (instruction in instructions) {
            // The live properties are read-only: they come from the file itself.
            if (ProppatchParser.isProtected(instruction.name)) {
                refused += instruction.name
                continue
            }
            // Keyed by namespace URI, not `prefix:local`: the prefix is a
            // per-document alias (two clients can both pick `Z` for different
            // namespaces) and would make one client's property overwrite — or
            // fail to overwrite — the other's. `{}` means "no namespace", which
            // is a distinct namespace, not the empty one.
            val name = DavPropertyStore.keyOf(instruction.name)
            if (instruction.isSet) {
                propertyStore.set(key, name, instruction.value ?: "")
            } else {
                propertyStore.remove(key, name)
            }
            stored += instruction.name
        }

        val propstats = ArrayList<String>()
        if (stored.isNotEmpty()) {
            propstats += WebDavXml.proppatchPropstat(stored, WebDavXml.HttpStatus.OK)
        }
        if (refused.isNotEmpty()) {
            propstats += WebDavXml.proppatchPropstat(
                refused,
                WebDavXml.HttpStatus.FORBIDDEN,
                WebDavXml.Conditions.CANNOT_MODIFY_PROTECTED_PROPERTY
            )
        }
        respondText(
            call,
            WebDavXml.multistatus(listOf(WebDavXml.proppatchResponse(href, propstats))),
            io.ktor.http.ContentType.parse("application/xml; charset=utf-8"),
            HttpStatusCode.MultiStatus
        )
        return true
    }

    private suspend fun handleCopyOrMove(call: ApplicationCall, isMove: Boolean): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        if (segments.isEmpty()) return respondText(call, "405 Cannot move the root", HttpStatusCode.MethodNotAllowed)
        if (lockManager.isLockedByOther(state.path, call.request.headers["If"])) {
            return respondLocked(call)
        }
        val destinationHeader = call.request.headers["Destination"] ?: return respondText(
            call, "400 Missing Destination", HttpStatusCode.BadRequest
        )
        val destPath = destinationHeader.substringBefore('?')
            .let { if (it.startsWith("http://") || it.startsWith("https://")) it.substringAfter("://").substringAfter('/', "/") else it }
        val destSegments = WebDavPaths.normalize(destPath) ?: return rejectPath(call)
        if (destSegments.isEmpty()) return respondDavError(
            call, HttpStatusCode.PreconditionFailed, reason = "Destination is the shared root"
        )

        val node = storage.node(segments) ?: return respondText(call, "404 Not Found", HttpStatusCode.NotFound)

        // RFC 4918 §10.3/§10.6: `Destination` names the *target resource*, not a
        // directory — Windows and Explorer both send a full path. A trailing
        // slash is the only signal that the client means "put it inside this
        // collection, keeping the source name".
        val destIsDirectory = destinationHeader.trimEnd().endsWith("/")
        // The collection that will *contain* the result: everything up to the
        // last segment, or the destination itself in the trailing-slash form.
        // (Resolving the parent-of-parent here was wrong: it put top-level
        // destinations outside the root and renamed inside the wrong directory.)
        val destDirSegments = if (destIsDirectory) destSegments else destSegments.dropLast(1)
        val destLeaf = if (destIsDirectory) segments.last() else destSegments.last()
        val destinationDir = storage.node(destDirSegments) ?: return respondText(
            call, "409 Destination missing", HttpStatusCode.Conflict
        )
        if (!destinationDir.isDirectory) {
            return respondDavError(
                call, HttpStatusCode.PreconditionFailed, reason = "Destination is not a collection"
            )
        }
        // A file cannot take the place of an existing collection. In the
        // trailing-slash form an existing collection is exactly what we want.
        if (!destIsDirectory && storage.node(destSegments)?.isDirectory == true) {
            return respondDavError(
                call, HttpStatusCode.PreconditionFailed, reason = "Destination is a collection"
            )
        }

        // RFC 4918 §9.9.4 / §9.8.5 pick the success status by whether a resource
        // was *created*: 201 when the destination had no mapping before, 204 when
        // it did and was overwritten. Deriving it from the verb instead — MOVE ⇒
        // 201, COPY ⇒ 204 — reports a create that did not happen to a MOVE over
        // an existing file, and hides the create that did happen from a COPY.
        // Resolved before the operation, because afterwards the mapping exists
        // either way.
        val destinationExisted = storage.node(
            if (destIsDirectory) destSegments + destLeaf else destSegments
        ) != null

        // RFC 4918 §10.6: `Overwrite: F` means "fail if the destination already
        // exists" and the failure status is 412, not 201-with-the-old-name or a
        // silent replacement. Clients (Windows Explorer included) send `F`
        // precisely to ask the server not to clobber, so honouring it is a
        // data-loss fix, not a nicety. Measured on-device: a plain COPY with
        // `Overwrite: F` onto an existing file answered 201 and replaced it.
        val overwrite = call.request.headers["Overwrite"]
        if (!overwrite.isNullOrBlank() && overwrite.trim().equals("F", ignoreCase = true)) {
            if (destinationExisted) {
                return preconditionFailed(call, "destination exists and Overwrite is F")
            }
        }

        val ok = if (isMove) {
            storage.move(node, destinationDir, destLeaf)
        } else {
            storage.copy(node, destinationDir, destLeaf)
        }
        return if (ok) {
            respondText(
                call,
                "",
                if (destinationExisted) HttpStatusCode.NoContent else HttpStatusCode.Created
            )
        } else {
            respondText(call, "403 Operation failed", HttpStatusCode.Forbidden)
        }
    }

    private suspend fun handleLock(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        val existing = lockManager.find(state.path)
        if (existing != null) {
            // Refresh semantics: return the current lock (RFC 4918 §9.10.1).
            respondLock(call, existing)
            return true
        }
        val owner = call.request.headers["User-Agent"] ?: "unknown"
        val lock = lockManager.lock(state.path, owner)
        call.response.header("Lock-Token", "<${lock.token}>")
        respondLock(call, lock)
        return true
    }

    private suspend fun handleUnlock(call: ApplicationCall): Boolean {
        val token = call.request.headers["Lock-Token"]?.trim('<', '>', ' ')
        val removed = if (!token.isNullOrBlank()) {
            lockManager.unlockByToken(token)
        } else {
            lockManager.unlock(state.path, null)
        }
        return if (removed) respondText(call, "", HttpStatusCode.NoContent)
        // §9.11.1: "422 Unprocessable Entity ... the lock token does not match" —
        // but UNLOCK of an unknown token has no DAV: condition either, so this
        // uses the custom-namespace form rather than a wrong one.
        else respondDavError(call, HttpStatusCode.Conflict, reason = "No such lock")
    }

    /**
     * 423 for a resource another client holds a lock on.
     *
     * §14.5/§16 name `lock-token-submitted` for "the client did not submit a
     * lock token and one is required" and `no-conflicting-lock` for "the lock
     * that was submitted conflicts". Which one applies depends on whether the
     * `If:` header was present at all, so both are emitted when the client sent
     * nothing and only the latter when it sent a token that belongs to someone
     * else — that distinction is what a client needs to decide between
     * prompting for credentials and reporting a genuine conflict.
     */
    private suspend fun respondLocked(call: ApplicationCall): Boolean {
        val ifHeader = call.request.headers["If"]
        val conditions = if (ifHeader.isNullOrBlank()) {
            arrayOf(WebDavXml.Conditions.LOCK_TOKEN_SUBMITTED, WebDavXml.Conditions.NO_CONFLICTING_LOCK)
        } else {
            arrayOf(WebDavXml.Conditions.NO_CONFLICTING_LOCK)
        }
        return respondDavError(
            call,
            HttpStatusCode.Locked,
            *conditions,
            reason = "Locked by another client"
        )
    }

    // ---------------------------------------------------------------- helpers

    private fun verifyAuth(call: ApplicationCall, header: DigestAuthenticator.DigestHeader): Boolean {
        val expected = currentCredentials() ?: return false
        return authenticator.verify(header, expected, call.request.httpMethod.value.uppercase())
    }

    /** Overridden by the engine so credentials can be rotated at runtime. */
    var credentialProvider: (() -> DigestAuthenticator.Credentials?)? = null

    private fun currentCredentials(): DigestAuthenticator.Credentials? =
        credentialProvider?.invoke()

    private suspend fun respondChallenge(call: ApplicationCall) {
        state.status = 401
        call.response.header("WWW-Authenticate", authenticator.challenge())
        respondText(call, "401 Unauthorized", io.ktor.http.ContentType.Text.Plain, HttpStatusCode.Unauthorized)
    }

    private suspend fun respondLock(call: ApplicationCall, lock: LockManager.Lock) {
        respondText(
            call,
            WebDavXml.lockDiscovery(lock),
            io.ktor.http.ContentType.parse("application/xml; charset=utf-8"),
            HttpStatusCode.OK
        )
    }

    /**
     * An RFC 4918 §14.5 error response: [status] plus an `<D:error>` body naming
     * [conditions] from the `DAV:` namespace.
     *
     * Every error this handler emits used to be a plain-text reason phrase.
     * `<!ELEMENT error ANY>` requires an XML element, so a client that parses
     * error bodies — Go's `x/net/webdav`, Windows MiniRedir, litmus — got
     * nothing it could read and fell back to the status code alone. The reason
     * phrase is kept as a trailing XML comment for humans reading the logs; it
     * is not part of the element content.
     */
    private suspend fun respondDavError(
        call: ApplicationCall,
        status: HttpStatusCode,
        vararg conditions: String,
        reason: String = status.description
    ): Boolean {
        state.status = status.value
        call.respondText(
            WebDavXml.error(*conditions),
            io.ktor.http.ContentType.parse("application/xml; charset=utf-8"),
            status
        )
        onCompleted?.invoke(state.method, state.path, state.username, state.status)
        return true
    }

    private suspend fun rejectPath(call: ApplicationCall): Boolean {
        // No DAV: condition applies to a malformed path; §16 explicitly allows a
        // bare numeric status with an empty body, and an XML document with no
        // element would violate §14.5 — so this keeps the custom-namespace form.
        state.status = 400
        respondText(call, "400 Bad Request — illegal path", io.ktor.http.ContentType.Text.Plain, HttpStatusCode.BadRequest)
        return false
    }

    /**
     * The entity tag for [node] — the single scheme every response and every
     * conditional check uses.
     *
     * `lastModified` plus `length` is deliberately chosen over a content hash:
     * hashing means reading the whole file (up to 4 GiB) on every GET and every
     * conditional PUT, and on a USB drive behind SAF that is seconds of latency.
     * The pair is not collision-proof — two writes inside the same millisecond
     * producing the same length would reuse a tag — but it changes on every
     * ordinary write and costs nothing to compute.
     */
    private fun etagOf(node: DavNode): String = "\"${node.lastModified}-${node.length}\""

    /**
     * True when [wanted] (from an `If-Match`/`If-None-Match` header) names the
     * same tag as [current].
     *
     * Both sides are compared as opaque values with the surrounding quotes
     * stripped, per RFC 7232 §2.3's "entity-tag = [ weak ] DQUOTE *etagc DQUOTE"
     * — a client may legitimately send `W/"123-10"` for a tag this server
     * issued strong, and weak comparison is the only thing that can match.
     * A header may also carry a comma-separated list, which is why this checks
     * membership rather than equality.
     */
    private fun etagMatches(wanted: String, current: String): Boolean {
        val target = current.trim('"', 'W', '/').trim('"')
        return wanted.split(',').any { candidate ->
            candidate.trim().trim('"', 'W', '/').trim('"') == target
        }
    }

    /**
     * 412 with a reason phrase naming the failed precondition.
     *
     * No RFC 4918 §16 condition names a failed entity tag — that vocabulary is
     * RFC 7232's, and the DAV conditions are about locks and live properties.
     * §16 permits an appropriate numeric status with a body in a custom
     * namespace for anything it does not define, which is what this uses.
     */
    private suspend fun preconditionFailed(call: ApplicationCall, reason: String): Boolean {
        state.status = 412
        call.respondText(
            WebDavXml.error() + "<!-- $reason -->",
            io.ktor.http.ContentType.parse("application/xml; charset=utf-8"),
            HttpStatusCode.PreconditionFailed
        )
        onCompleted?.invoke(state.method, state.path, state.username, state.status)
        return true
    }

    /**
     * Sends a 200 whose declared `Content-Length` is [declaredLength] while the
     * payload stays empty — the shape a HEAD response requires.
     *
     * `OutgoingContent.ByteArrayContent` is the only Ktor content type that lets
     * the declared length and the bytes diverge: `TextContent` derives the length
     * from its own bytes, so an empty body always declares 0. Declaring the
     * header by hand is not an option either — `commitHeaders` *appends* its own
     * copy from `contentLength`, and `ApplicationResponse.header()` appends
     * rather than replaces, which is exactly how the duplicate header happened.
     */
    private suspend fun respondEmptyBody(call: ApplicationCall, declaredLength: Long): Boolean {
        state.status = 200
        val content = object : OutgoingContent.ByteArrayContent() {
            override val contentLength: Long get() = declaredLength
            override val contentType: ContentType get() = ContentType.Text.Plain
            override val status: HttpStatusCode get() = HttpStatusCode.OK
            override fun bytes(): ByteArray = ByteArray(0)
        }
        call.respond(content)
        onCompleted?.invoke(state.method, state.path, state.username, state.status)
        return true
    }

    private suspend fun respondDirectoryIndex(call: ApplicationCall, segments: List<String>, node: DavNode): Boolean {
        val href = WebDavPaths.encodeCollectionHref(segments)
        val children = node.listChildren()
        // `mimeTypeOf` is named because the parameter before it,
        // `extraForCollection`, is the one this call site leaves out.
        val body = WebDavXml.collectionListing(
            baseHref = href,
            collection = node,
            children = children,
            mimeTypeOf = { storage.mimeTypeOf(it) }
        )
        respondText(
            call,
            body,
            io.ktor.http.ContentType.parse("application/xml; charset=utf-8"),
            HttpStatusCode.MultiStatus
        )
        return true
    }

    /**
     * Writes a plain-text response and reports that the request was served.
     *
     * Two shapes exist because most call sites only carry a status code, while
     * XML bodies need an explicit content type. Returning [Boolean] is what lets
     * the handlers above write `return respondText(...)`: every one of those
     * paths produces a status code, so none of them is a fall-through.
     */
    private suspend fun respondText(
        call: ApplicationCall,
        text: String,
        status: HttpStatusCode
    ): Boolean = respondText(call, text, io.ktor.http.ContentType.Text.Plain, status)

    private suspend fun respondText(
        call: ApplicationCall,
        text: String,
        contentType: io.ktor.http.ContentType,
        status: HttpStatusCode
    ): Boolean {
        state.status = status.value
        call.respondText(text, contentType, status)
        onCompleted?.invoke(state.method, state.path, state.username, state.status)
        return true
    }

    private fun readAll(stream: java.io.InputStream): ByteArray = stream.use { it.readBytes() }

    companion object {
        const val DEFAULT_MAX_UPLOAD_BYTES = 4L * 1024 * 1024 * 1024
        const val DEFAULT_BUFFER_SIZE = 64 * 1024
    }
}
