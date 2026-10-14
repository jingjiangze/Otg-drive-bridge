package com.jingjiangze.otgdrivebridge.server

import com.jingjiangze.otgdrivebridge.security.CredentialGenerator
import com.jingjiangze.otgdrivebridge.security.DigestAuthenticator
import com.jingjiangze.otgdrivebridge.webdav.DavStorage
import com.jingjiangze.otgdrivebridge.webdav.DavNode
import com.jingjiangze.otgdrivebridge.webdav.LockManager
import com.jingjiangze.otgdrivebridge.webdav.WebDavPaths
import com.jingjiangze.otgdrivebridge.webdav.WebDavXml
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.request.receiveChannel
import io.ktor.server.response.header
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
    private val maxUploadBytes: Long = DEFAULT_MAX_UPLOAD_BYTES
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
        call.response.header("Content-Length", "0")
        respondText(call, "", HttpStatusCode.OK)
    }

    private suspend fun handleGet(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        val node = storage.node(segments) ?: return respondText(
            call, "404 Not Found", HttpStatusCode.NotFound
        )
        if (node.isDirectory) {
            // Windows Explorer navigates directories; serve a minimal listing.
            return respondDirectoryIndex(call, segments, node)
        }
        val stream = storage.openRead(node) ?: return respondText(
            call, "500 Could not open file", HttpStatusCode.InternalServerError
        )
        val mime = storage.mimeTypeOf(node.name)
        val etag = "\"${node.lastModified}-${node.length}\""
        call.response.header("ETag", etag)
        call.response.header("Last-Modified", WebDavXml.httpDate(node.lastModified))
        call.response.header("Accept-Ranges", "bytes")
        if (state.method == "HEAD") {
            stream.close()
            call.response.header("Content-Length", node.length.toString())
            respondText(call, "", HttpStatusCode.OK)
            return true
        }
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
            return respondText(call, "423 Locked", HttpStatusCode.Locked)
        }
        val existing = storage.node(segments)
        if (existing != null && existing.isDirectory) {
            return respondText(call, "405 Target is a collection", HttpStatusCode.MethodNotAllowed)
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

        call.response.header("ETag", "\"${System.currentTimeMillis()}-$written\"")
        respondText(call, "", if (existing == null) HttpStatusCode.Created else HttpStatusCode.NoContent)
        return true
    }

    private suspend fun handleDelete(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        if (segments.isEmpty()) return respondText(call, "405 Cannot DELETE the root", HttpStatusCode.MethodNotAllowed)
        if (lockManager.isLockedByOther(state.path, call.request.headers["If"])) {
            return respondText(call, "423 Locked", HttpStatusCode.Locked)
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
        val node = storage.node(segments) ?: return respondText(call, "404 Not Found", HttpStatusCode.NotFound)
        val depth = (call.request.headers["Depth"] ?: "1").lowercase()
        val href = WebDavPaths.encodeHref(segments) + if (node.isDirectory) "/" else ""

        val body = if (!node.isDirectory || depth == "0") {
            WebDavXml.multistatus(
                listOf(WebDavXml.response(href, node, storage.mimeTypeOf(node.name)))
            )
        } else {
            val children = node.listChildren().sortedWith(
                compareByDescending<DavNode> { it.isDirectory }.thenBy { it.name.lowercase() }
            )
            WebDavXml.collectionListing(href, node, children) { storage.mimeTypeOf(it) }
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

    private suspend fun handleProppatch(call: ApplicationCall): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        val node = storage.node(segments) ?: return respondText(call, "404 Not Found", HttpStatusCode.NotFound)
        val href = WebDavPaths.encodeHref(segments) + if (node.isDirectory) "/" else ""
        val body = WebDavXml.multistatus(
            listOf(WebDavXml.response(href, node, storage.mimeTypeOf(node.name)))
        )
        respondText(
            call,
            body,
            io.ktor.http.ContentType.parse("application/xml; charset=utf-8"),
            HttpStatusCode.MultiStatus
        )
        return true
    }

    private suspend fun handleCopyOrMove(call: ApplicationCall, isMove: Boolean): Boolean {
        val segments = WebDavPaths.normalize(state.path) ?: return rejectPath(call)
        if (segments.isEmpty()) return respondText(call, "405 Cannot move the root", HttpStatusCode.MethodNotAllowed)
        if (lockManager.isLockedByOther(state.path, call.request.headers["If"])) {
            return respondText(call, "423 Locked", HttpStatusCode.Locked)
        }
        val destinationHeader = call.request.headers["Destination"] ?: return respondText(
            call, "400 Missing Destination", HttpStatusCode.BadRequest
        )
        val destPath = destinationHeader.substringBefore('?')
            .let { if (it.startsWith("http://") || it.startsWith("https://")) it.substringAfter("://").substringAfter('/', "/") else it }
        val destSegments = WebDavPaths.normalize(destPath) ?: return rejectPath(call)
        if (destSegments.isEmpty()) return respondText(call, "412 Bad destination", HttpStatusCode.PreconditionFailed)

        val node = storage.node(segments) ?: return respondText(call, "404 Not Found", HttpStatusCode.NotFound)

        // RFC 4918 §10.3/§10.6: `Destination` names the *target resource*, not a
        // directory — Windows and Explorer both send a full path. Only the
        // trailing-slash form (".../dir/") means "into this directory".
        val destIsDirectory = destinationHeader.trimEnd().endsWith("/")
        val destParent = if (destIsDirectory) destSegments else destSegments.dropLast(1)
        val destLeaf = if (destIsDirectory) segments.last() else destSegments.last()
        val destinationDir = storage.parentOf(destParent)?.first ?: return respondText(
            call, "409 Destination missing", HttpStatusCode.Conflict
        )
        if (!destinationDir.isDirectory) return respondText(call, "412 Destination not a collection", HttpStatusCode.PreconditionFailed)
        if (storage.node(destSegments)?.isDirectory == true) {
            return respondText(call, "412 Destination is a collection", HttpStatusCode.PreconditionFailed)
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
                if (isMove) HttpStatusCode.Created else HttpStatusCode.NoContent
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
        else respondText(call, "409 No such lock", HttpStatusCode.Conflict)
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

    private suspend fun rejectPath(call: ApplicationCall): Boolean {
        state.status = 400
        respondText(call, "400 Bad Request — illegal path", io.ktor.http.ContentType.Text.Plain, HttpStatusCode.BadRequest)
        return false
    }

    private suspend fun respondDirectoryIndex(call: ApplicationCall, segments: List<String>, node: DavNode): Boolean {
        val href = WebDavPaths.encodeHref(segments) + "/"
        val children = node.listChildren()
        val body = WebDavXml.collectionListing(href, node, children) { storage.mimeTypeOf(it) }
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
