package com.jingjiangze.otgdrivebridge.server

import com.jingjiangze.otgdrivebridge.security.DigestAuthenticator
import com.jingjiangze.otgdrivebridge.webdav.FileSystemDavStorage
import com.jingjiangze.otgdrivebridge.webdav.LockManager
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.DefaultRequest
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * End-to-end WebDAV over a real Ktor server.
 *
 * This is the closest CI can get to what Windows does: a real HTTP client that
 * answers the Digest challenge, then exercises read, write, rename, delete and
 * locking. It replaces the "no device available" gap the audit flagged for the
 * protocol layer (device-dependent behaviour still needs a phone — see V1–V8).
 *
 * The server is started through [ServerBootstrap] on purpose: the cross-language
 * interop harness boots the very same function, so a difference this test sees
 * and the harness does not (or the other way round) cannot be an assembly
 * difference — it has to be a protocol one.
 */
class WebDavEndToEndTest {

    private companion object {
        const val USERNAME = "otg"
        const val PASSWORD = "SuperSecretPassw0rd"
        const val PORT = 18080
    }

    private lateinit var root: java.io.File
    private lateinit var server: ServerBootstrap.StartedServer
    private lateinit var client: HttpClient
    private val authenticator = DigestAuthenticator()

    @BeforeEach
    fun setUp() {
        root = Files.createTempDirectory("otg-e2e").toFile()
        server = ServerBootstrap.start(
            port = PORT,
            storage = FileSystemDavStorage(root),
            credentialProvider = { DigestAuthenticator.Credentials(USERNAME, PASSWORD) },
            host = "127.0.0.1",
            authenticator = authenticator,
            lockManager = LockManager()
        )
        client = HttpClient(CIO) {
            expectSuccess = false
        }
    }

    @AfterEach
    fun tearDown() {
        runCatching { client.close() }
        runCatching { server.close() }
        runCatching { root.deleteRecursively() }
    }

    @Test
    fun `options advertises dav support without credentials`() = runBlocking {
        val response = request("OPTIONS", "/")
        assertEquals(HttpStatusCode.OK, response.status)
        assertEquals("1, 2", response.headers["DAV"])
        assertTrue(response.headers["Allow"]!!.contains("PROPFIND"))
        assertTrue(response.headers["Allow"]!!.contains("LOCK"))
        assertFalse(response.headers.contains("WWW-Authenticate"))
    }

    @Test
    fun `unauthenticated propfind is challenged with digest`() = runBlocking {
        val response = request("PROPFIND", "/")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        val challenge = response.headers["WWW-Authenticate"]!!
        assertTrue(challenge.startsWith("Digest "))
        assertTrue(challenge.contains("qop=\"auth\""))
    }

    @Test
    fun `authenticated propfind lists the empty root`() = runBlocking {
        val response = authorizedRequest("PROPFIND", "/")
        assertEquals(HttpStatusCode.MultiStatus, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("xmlns:D=\"DAV:\""))
        assertTrue(body.contains("<D:multistatus"))
        assertTrue(body.contains("<D:iscollection>1</D:iscollection>"))
    }

    @Test
    fun `put creates a file and get reads it back`() = runBlocking {
        val put = authorizedRequest("PUT", "/hello.txt") { setBody("Hello OTG") }
        assertEquals(HttpStatusCode.Created, put.status)
        assertTrue(java.io.File(root, "hello.txt").exists())

        val get = authorizedRequest("GET", "/hello.txt")
        assertEquals(HttpStatusCode.OK, get.status)
        assertEquals("Hello OTG", get.bodyAsText())
    }

    @Test
    fun `put overwrites and reports 204`() = runBlocking {
        authorizedRequest("PUT", "/f.txt") { setBody("first") }
        val overwrite = authorizedRequest("PUT", "/f.txt") { setBody("second") }
        assertEquals(HttpStatusCode.NoContent, overwrite.status)
        assertEquals("second", authorizedRequest("GET", "/f.txt").bodyAsText())
    }

    @Test
    fun `an overwrite leaves no residue from the previous payload`() = runBlocking {
        authorizedRequest("PUT", "/keep.bin") { setBody("COMPLETE-PAYLOAD") }
        val overwrite = authorizedRequest("PUT", "/keep.bin") { setBody("SHORT") }
        // NOTE: this is not the Content-Length-mismatch path. Ktor's client always
        // sends the real length, so the 400 the handler returns for a declared/
        // actual mismatch can only be driven by a raw socket request — that case
        // belongs to the cross-language interop suite, not here.
        assertEquals(HttpStatusCode.NoContent, overwrite.status)
        assertEquals("SHORT", authorizedRequest("GET", "/keep.bin").bodyAsText())
    }

    @Test
    fun `mkcol creates a directory and propfind shows it`() = runBlocking {
        val mkcol = authorizedRequest("MKCOL", "/docs")
        assertEquals(HttpStatusCode.Created, mkcol.status)
        assertTrue(java.io.File(root, "docs").isDirectory)

        val body = authorizedRequest("PROPFIND", "/").bodyAsText()
        assertTrue(body.contains("/docs/"))
    }

    @Test
    fun `put into a missing parent is 409`() = runBlocking {
        val response = authorizedRequest("PUT", "/nope/deep/file.txt") { setBody("x") }
        assertEquals(HttpStatusCode.Conflict, response.status)
    }

    @Test
    fun `encoded traversal is rejected with 400`() = runBlocking {
        // Note: a literal "/../" is normalised away by the HTTP stack before it
        // reaches the handler, so the encoded forms are the ones that must be
        // caught in application code (covered exhaustively in WebDavPathsTest).
        assertEquals(
            HttpStatusCode.BadRequest,
            authorizedRequest("GET", "/%2e%2e/%2e%2e/etc").status
        )
        assertEquals(
            HttpStatusCode.BadRequest,
            authorizedRequest("GET", "/..%2f..%2fetc").status
        )
        assertEquals(
            HttpStatusCode.BadRequest,
            authorizedRequest("GET", "/%2e%2e%5c%2e%2e%5cwindows").status
        )
        assertEquals(
            HttpStatusCode.BadRequest,
            authorizedRequest("GET", "/CON").status
        )
    }

    @Test
    fun `move renames and delete removes`() = runBlocking {
        authorizedRequest("MKCOL", "/docs")
        authorizedRequest("PUT", "/docs/a.txt") { setBody("A") }

        val move = authorizedRequest("MOVE", "/docs/a.txt") {
            header("Destination", "http://127.0.0.1:$PORT/docs/b.txt")
        }
        assertEquals(HttpStatusCode.Created, move.status)
        assertFalse(java.io.File(root, "docs/a.txt").exists())
        assertTrue(java.io.File(root, "docs/b.txt").exists())

        val delete = authorizedRequest("DELETE", "/docs/b.txt")
        assertEquals(HttpStatusCode.NoContent, delete.status)
        assertFalse(java.io.File(root, "docs/b.txt").exists())
    }

    @Test
    fun `copy duplicates`() = runBlocking {
        authorizedRequest("PUT", "/src.txt") { setBody("data") }
        val copy = authorizedRequest("COPY", "/src.txt") {
            header("Destination", "http://127.0.0.1:$PORT/dst.txt")
        }
        // 201, not 204. RFC 4918 §9.8.5 gives 201 when "the COPY operation
        // resulted in the creation of a new resource" and reserves 204 for a
        // "preexisting destination resource"; `dst.txt` did not exist, so a
        // resource *was* created. These assertions read 204 while the status was
        // chosen by the verb instead of by the destination.
        assertEquals(HttpStatusCode.Created, copy.status)
        assertEquals("data", authorizedRequest("GET", "/dst.txt").bodyAsText())
    }

    @Test
    fun `move into a directory keeps the name when destination has a trailing slash`() = runBlocking {
        authorizedRequest("MKCOL", "/inbox")
        authorizedRequest("PUT", "/mail.txt") { setBody("letter") }
        val move = authorizedRequest("MOVE", "/mail.txt") {
            header("Destination", "http://127.0.0.1:$PORT/inbox/")
        }
        assertEquals(HttpStatusCode.Created, move.status)
        assertTrue(java.io.File(root, "inbox/mail.txt").isFile)
        assertFalse(java.io.File(root, "mail.txt").exists())
    }

    @Test
    fun `copy a directory recursively`() = runBlocking {
        authorizedRequest("MKCOL", "/tree")
        authorizedRequest("PUT", "/tree/a.txt") { setBody("A") }
        authorizedRequest("MKCOL", "/tree/sub")
        authorizedRequest("PUT", "/tree/sub/b.txt") { setBody("B") }

        val copy = authorizedRequest("COPY", "/tree") {
            header("Destination", "http://127.0.0.1:$PORT/tree-copy")
        }
        // 201 for the same reason as `copy duplicates`: `/tree-copy` did not
        // exist, so the COPY created it (RFC 4918 §9.8.5).
        assertEquals(HttpStatusCode.Created, copy.status)
        assertEquals("A", authorizedRequest("GET", "/tree-copy/a.txt").bodyAsText())
        assertEquals("B", authorizedRequest("GET", "/tree-copy/sub/b.txt").bodyAsText())
    }

    @Test
    fun `lock then unqualified write is refused with 423`() = runBlocking {
        authorizedRequest("PUT", "/locked.txt") { setBody("v1") }

        val lockResponse = authorizedRequest("LOCK", "/locked.txt")
        assertEquals(HttpStatusCode.OK, lockResponse.status)
        val lockBody = lockResponse.bodyAsText()
        val token = Regex("opaquelocktoken:[0-9a-f-]+").find(lockBody)!!.value
        assertTrue(lockBody.contains("<D:lockscope><D:exclusive/></D:lockscope>"))

        val blocked = authorizedRequest("PUT", "/locked.txt") { setBody("v2") }
        assertEquals(HttpStatusCode.Locked, blocked.status)
        assertEquals("v1", authorizedRequest("GET", "/locked.txt").bodyAsText())

        val unlock = authorizedRequest("UNLOCK", "/locked.txt") {
            header("Lock-Token", "<$token>")
        }
        assertEquals(HttpStatusCode.NoContent, unlock.status)

        val afterUnlock = authorizedRequest("PUT", "/locked.txt") { setBody("v2") }
        assertEquals(HttpStatusCode.NoContent, afterUnlock.status)
        assertEquals("v2", authorizedRequest("GET", "/locked.txt").bodyAsText())
    }

    @Test
    fun `a write carrying the lock token is allowed`() = runBlocking {
        authorizedRequest("PUT", "/tok.txt") { setBody("v1") }
        val lockBody = authorizedRequest("LOCK", "/tok.txt").bodyAsText()
        val token = Regex("opaquelocktoken:[0-9a-f-]+").find(lockBody)!!.value

        val response = authorizedRequest("PUT", "/tok.txt") {
            header("If", "<$token>")
            setBody("v2")
        }
        assertEquals(HttpStatusCode.NoContent, response.status)
    }

    @Test
    fun `wrong password is rejected`() = runBlocking {
        val badClient = HttpClient(CIO) {
            expectSuccess = false
            install(DefaultRequest) {
                header("Authorization", "Digest username=\"otg\", realm=\"nope\", nonce=\"x\", uri=\"/\", response=\"bad\"")
            }
        }
        val response = badClient.request("http://127.0.0.1:$PORT/") {
            method = HttpMethod("PROPFIND")
        }
        assertEquals(HttpStatusCode.Unauthorized, response.status)
        runCatching { badClient.close() }
    }

    @Test
    fun `unknown method returns 405`() = runBlocking {
        // TRACE is not registered as a route, so Ktor answers 405 itself.
        val response = authorizedRequest("TRACE", "/")
        assertEquals(HttpStatusCode.MethodNotAllowed, response.status)
    }

    @Test
    fun `post is refused`() = runBlocking {
        // POST is routed but has no handler branch, so the handler answers 405.
        val response = authorizedRequest("POST", "/")
        assertEquals(HttpStatusCode.MethodNotAllowed, response.status)
    }

    @Test
    fun `head reports the content length`() = runBlocking {
        authorizedRequest("PUT", "/sized.bin") { setBody("0123456789") }
        val head = authorizedRequest("HEAD", "/sized.bin")
        assertEquals(HttpStatusCode.OK, head.status)
        assertEquals("10", head.headers["Content-Length"])
    }

    @Test
    fun `head on a collection is a 200 with no multistatus body`() = runBlocking {
        // RFC 7231 §4.3.2: a HEAD is "identical to GET except that the server
        // MUST NOT send a message body". It is not a PROPFIND, so answering 207
        // with a directory listing — which is what this did before — makes every
        // HEAD-based existence check see a "file" and the wrong length.
        authorizedRequest("MKCOL", "/docs")
        val head = authorizedRequest("HEAD", "/docs")
        assertEquals(HttpStatusCode.OK, head.status)
        assertEquals("0", head.headers["Content-Length"])
        assertTrue(head.bodyAsText().isEmpty(), "HEAD must not carry a body")
        assertFalse(head.bodyAsText().contains("multistatus"))
    }

    @Test
    fun `head on a collection with children still reports zero`() = runBlocking {
        // The length of a collection is not the sum of its children: it has no
        // body at all, so a HEAD must declare 0 even when the listing is long.
        authorizedRequest("MKCOL", "/docs")
        authorizedRequest("PUT", "/docs/a.txt") { setBody("A") }
        val head = authorizedRequest("HEAD", "/docs")
        assertEquals(HttpStatusCode.OK, head.status)
        assertEquals("0", head.headers["Content-Length"])
    }

    @Test
    fun `put with a stale if-match is refused with 412`() = runBlocking {
        authorizedRequest("PUT", "/guarded.txt") { setBody("v1") }
        val etag = authorizedRequest("GET", "/guarded.txt").headers["ETag"]!!
        assertTrue(etag.isNotBlank(), "GET must publish an ETag for If-Match to work at all")

        val stale = authorizedRequest("PUT", "/guarded.txt") {
            header("If-Match", "\"0-0\"")
            setBody("v2")
        }
        assertEquals(HttpStatusCode.PreconditionFailed, stale.status)
        // The rejection must happen before any byte is staged, or a lost update
        // is exactly what the client was trying to avoid.
        assertEquals("v1", authorizedRequest("GET", "/guarded.txt").bodyAsText())
    }

    @Test
    fun `put with a matching if-match succeeds`() = runBlocking {
        authorizedRequest("PUT", "/guarded.txt") { setBody("v1") }
        val etag = authorizedRequest("GET", "/guarded.txt").headers["ETag"]!!

        val ok = authorizedRequest("PUT", "/guarded.txt") {
            header("If-Match", etag)
            setBody("v2")
        }
        assertEquals(HttpStatusCode.NoContent, ok.status)
        assertEquals("v2", authorizedRequest("GET", "/guarded.txt").bodyAsText())
    }

    @Test
    fun `put with if-match star requires the resource to exist`() = runBlocking {
        val missing = authorizedRequest("PUT", "/nope.txt") {
            header("If-Match", "*")
            setBody("x")
        }
        assertEquals(HttpStatusCode.PreconditionFailed, missing.status)

        authorizedRequest("PUT", "/there.txt") { setBody("v1") }
        val ok = authorizedRequest("PUT", "/there.txt") {
            header("If-Match", "*")
            setBody("v2")
        }
        assertEquals(HttpStatusCode.NoContent, ok.status)
    }

    @Test
    fun `if-match accepts a weak tag and a comma separated list`() = runBlocking {
        // RFC 7232 §2.3: a client may send W/"..." for a tag this server issued
        // strong, and a header may carry a list. Weak comparison is the only
        // thing that can match both.
        authorizedRequest("PUT", "/weak.txt") { setBody("v1") }
        val etag = authorizedRequest("GET", "/weak.txt").headers["ETag"]!!
        val bare = etag.trim('"')

        val weak = authorizedRequest("PUT", "/weak.txt") {
            header("If-Match", "W/\"$bare\"")
            setBody("v2")
        }
        assertEquals(HttpStatusCode.NoContent, weak.status)

        // Re-read the tag: the ETag is `<lastModified>-<length>`, and the
        // successful PUT above just changed the mtime. Sending the stale one is
        // a genuine lost-update guard firing, which is what the server must do
        // — but that is not what this test is about, so fetch the current tag.
        val current = authorizedRequest("GET", "/weak.txt").headers["ETag"]!!
        val currentBare = current.trim('"')

        val list = authorizedRequest("PUT", "/weak.txt") {
            header("If-Match", "\"nomatch\", \"$currentBare\", \"other\"")
            setBody("v3")
        }
        assertEquals(HttpStatusCode.NoContent, list.status)
    }

    @Test
    fun `if-match rejects a stale tag after the file has been rewritten`() = runBlocking {
        // The mirror image of the test above, and the reason a comma list has to
        // be re-fetched: once the ETag has moved on, the old value is a real
        // precondition failure, not something to be papered over by weakening
        // the comparison. A client that edits on top of its own stale copy must
        // lose, otherwise the first writer's work is silently dropped.
        authorizedRequest("PUT", "/stale.txt") { setBody("v1") }
        val first = authorizedRequest("GET", "/stale.txt").headers["ETag"]!!
        val firstBare = first.trim('"')

        // Someone else rewrites the file.
        authorizedRequest("PUT", "/stale.txt") { setBody("v2") }

        val stale = authorizedRequest("PUT", "/stale.txt") {
            header("If-Match", "\"nomatch\", \"$firstBare\"")
            setBody("v3")
        }
        assertEquals(HttpStatusCode.PreconditionFailed, stale.status)
        assertEquals("v2", authorizedRequest("GET", "/stale.txt").bodyAsText())
    }

    @Test
    fun `put with if-none-match star refuses to clobber`() = runBlocking {
        // RFC 4918 §10.4: "create only if new". Without this, two clients racing
        // to create the same file both get 201 and the second silently wins.
        val created = authorizedRequest("PUT", "/new.txt") {
            header("If-None-Match", "*")
            setBody("mine")
        }
        assertEquals(HttpStatusCode.Created, created.status)

        val refused = authorizedRequest("PUT", "/new.txt") {
            header("If-None-Match", "*")
            setBody("theirs")
        }
        assertEquals(HttpStatusCode.PreconditionFailed, refused.status)
        assertEquals("mine", authorizedRequest("GET", "/new.txt").bodyAsText())
    }

    @Test
    fun `if-none-match star is ignored for a fresh file`() = runBlocking {
        val created = authorizedRequest("PUT", "/fresh.txt") {
            header("If-None-Match", "*")
            setBody("brand new")
        }
        assertEquals(HttpStatusCode.Created, created.status)
        assertEquals("brand new", authorizedRequest("GET", "/fresh.txt").bodyAsText())
    }

    @Test
    fun `the etag put publishes is the etag get reads`() = runBlocking {
        // Two incompatible schemes is the classic way this breaks: PUT used to
        // answer `"<currentTimeMillis>-<written>"` while GET answered
        // `"<lastModified>-<length>"`, so a client that cached one could never
        // use it against the other.
        val put = authorizedRequest("PUT", "/tagged.txt") { setBody("v1") }
        val putEtag = put.headers["ETag"]!!
        val getEtag = authorizedRequest("GET", "/tagged.txt").headers["ETag"]!!
        assertEquals(putEtag, getEtag)

        // And the tag must actually change on the next write, or If-Match would
        // accept a stale client's write forever.
        val overwrite = authorizedRequest("PUT", "/tagged.txt") { setBody("v2-longer") }
        assertTrue(
            overwrite.headers["ETag"]!! != putEtag,
            "ETag did not change after a write: ${overwrite.headers["ETag"]} vs $putEtag"
        )
    }

    @Test
    fun `a 412 body is xml with an element in it`() = runBlocking {
        // RFC 4918 §14.5: `<!ELEMENT error ANY>` — at least one XML element, no
        // bare text. Go's x/net/webdav, Windows MiniRedir and litmus all parse
        // the body; a plain-text reason phrase left them with nothing to read.
        authorizedRequest("PUT", "/exists.txt") { setBody("v1") }
        val refused = authorizedRequest("PUT", "/exists.txt") {
            header("If-None-Match", "*")
            setBody("v2")
        }
        assertEquals(HttpStatusCode.PreconditionFailed, refused.status)
        val body = refused.bodyAsText()
        assertTrue(body.contains("<?xml"), body)
        assertTrue(body.contains("<D:error"), body)
        assertTrue(body.contains("</D:error>"), body)
        assertTrue(Regex("<[A-Za-z]:[^>]*/>").containsMatchIn(body), "no element in $body")
    }

    @Test
    fun `copy with overwrite f onto an existing destination is 412`() = runBlocking {
        // RFC 4918 §10.6, and a data-loss fix rather than a nicety: Windows
        // Explorer sends `F` precisely to ask the server not to clobber. Measured
        // on-device: a plain COPY with `Overwrite: F` onto an existing file
        // answered 201 and replaced it.
        authorizedRequest("PUT", "/src.txt") { setBody("source") }
        authorizedRequest("PUT", "/dst.txt") { setBody("do not clobber") }

        val refused = authorizedRequest("COPY", "/src.txt") {
            header("Destination", "http://127.0.0.1:$PORT/dst.txt")
            header("Overwrite", "F")
        }
        assertEquals(HttpStatusCode.PreconditionFailed, refused.status)
        assertEquals(
            "do not clobber",
            authorizedRequest("GET", "/dst.txt").bodyAsText(),
            "Overwrite: F must leave the destination byte-for-byte intact"
        )
    }

    @Test
    fun `move with overwrite f onto an existing destination is 412`() = runBlocking {
        authorizedRequest("PUT", "/a.txt") { setBody("a") }
        authorizedRequest("PUT", "/b.txt") { setBody("b") }
        val refused = authorizedRequest("MOVE", "/a.txt") {
            header("Destination", "http://127.0.0.1:$PORT/b.txt")
            header("Overwrite", "F")
        }
        assertEquals(HttpStatusCode.PreconditionFailed, refused.status)
        assertTrue(java.io.File(root, "a.txt").exists(), "a refused MOVE must not move anything")
        assertEquals("b", authorizedRequest("GET", "/b.txt").bodyAsText())
    }

    @Test
    fun `copy with overwrite f onto a free destination succeeds`() = runBlocking {
        authorizedRequest("PUT", "/src.txt") { setBody("source") }
        val copy = authorizedRequest("COPY", "/src.txt") {
            header("Destination", "http://127.0.0.1:$PORT/free.txt")
            header("Overwrite", "F")
        }
        // The point of this case is that the copy *succeeds*; the status is 201
        // because `/free.txt` did not exist (RFC 4918 §9.8.5).
        assertEquals(HttpStatusCode.Created, copy.status)
        assertEquals("source", authorizedRequest("GET", "/free.txt").bodyAsText())
    }

    @Test
    fun `copy with overwrite t still replaces the destination`() = runBlocking {
        // The default is T; making it work proves the F path is a real refusal
        // and not a blanket "COPY is broken" regression.
        authorizedRequest("PUT", "/src.txt") { setBody("new") }
        authorizedRequest("PUT", "/dst.txt") { setBody("old") }
        val copy = authorizedRequest("COPY", "/src.txt") {
            header("Destination", "http://127.0.0.1:$PORT/dst.txt")
            header("Overwrite", "T")
        }
        assertEquals(HttpStatusCode.NoContent, copy.status)
        assertEquals("new", authorizedRequest("GET", "/dst.txt").bodyAsText())
    }

    @Test
    fun `a trailing dot in the request path is 400 not 201`() = runBlocking {
        // Windows strips the trailing dot when it resolves the name, so the
        // client would get 201 for `/dot.` and then find nothing on the next GET.
        // Measured on-device: PUT /dot. answered 201 and created `con..bin`.
        val response = authorizedRequest("PUT", "/dot.") { setBody("x") }
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertFalse(java.io.File(root, "con..bin").exists())
    }

    @Test
    fun `a 404 body is xml with an element in it`() = runBlocking {
        val response = authorizedRequest("PROPFIND", "/missing")
        assertEquals(HttpStatusCode.NotFound, response.status)
        val body = response.bodyAsText()
        assertTrue(body.contains("<D:error"), body)
        assertTrue(Regex("<[A-Za-z]:[^>]*/>").containsMatchIn(body), "no element in $body")
    }

    @Test
    fun `a 423 body names a lock condition`() = runBlocking {
        // RFC 4918 §16: the client needs to know *which* condition failed to
        // decide whether to retry with a lock token or give up. A bare status
        // left every client guessing.
        authorizedRequest("PUT", "/locked.txt") { setBody("v1") }
        authorizedRequest("LOCK", "/locked.txt")
        val blocked = authorizedRequest("PUT", "/locked.txt") { setBody("v2") }
        assertEquals(HttpStatusCode.Locked, blocked.status)
        val body = blocked.bodyAsText()
        assertTrue(body.contains("<D:lock-token-submitted/>"), body)
        assertTrue(body.contains("<D:no-conflicting-lock/>"), body)
    }

    @Test
    fun `proppatch stores a dead property and propfind reads the value back`() = runBlocking {
        // The whole point of #6: this used to answer 207 while storing nothing,
        // so Windows Explorer's comment column and sync tools' bookkeeping were
        // silently lost. Measured on-device: PROPPATCH a Z:marker, then PROPFIND
        // it back — gone.
        authorizedRequest("PUT", "/doc.txt") { setBody("body") }
        val patch = authorizedRequest("PROPPATCH", "/doc.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:marker>hello</Z:marker></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.MultiStatus, patch.status)
        val patchBody = patch.bodyAsText()
        assertTrue(patchBody.contains("200 OK"), patchBody)

        val find = authorizedRequest("PROPFIND", "/doc.txt")
        val findBody = find.bodyAsText()
        // The client sent `Z` bound to `urn:example:test`, so the server answers
        // in *that* namespace — a prefix it generates itself, because a prefix is
        // a per-document alias and echoing the client's is optional. What matters
        // is the namespace-qualified name and the value.
        assertTrue(findBody.contains("xmlns:p0=\"urn:example:test\""), "unbound prefix: $findBody")
        assertTrue(
            Regex("<p0:marker>hello</p0:marker>").containsMatchIn(findBody),
            "the stored value must come back: $findBody"
        )
        // ...and the value must be *inside* the multistatus, not appended after
        // the closing tag where no parser will ever see it.
        val end = findBody.lastIndexOf("</D:multistatus>")
        val marker = findBody.indexOf("<p0:marker>hello</p0:marker>")
        assertTrue(marker in 0 until end, "marker landed outside the multistatus")
    }

    @Test
    fun `a property with no namespace round trips as no namespace`() = runBlocking {
        // The client puts the property in *no* namespace. The only way to write
        // that in XML is an unprefixed element under `xmlns=""` — `xmlns:Z=""`
        // is not a legal way to ask for it, because a prefix can only be
        // undeclared relative to an ancestor that bound it (verified with a
        // namespace-aware parser: "must not undeclare prefix"). The parser must
        // accept the unprefixed form, which is what a real client sends.
        authorizedRequest("PUT", "/doc.txt") { setBody("body") }
        val patch = authorizedRequest("PROPPATCH", "/doc.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:">
  <D:set><D:prop><plain xmlns="">no-ns</plain></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.MultiStatus, patch.status)
        assertTrue(patch.bodyAsText().contains("200 OK"), patch.bodyAsText())

        val findBody = authorizedRequest("PROPFIND", "/doc.txt").bodyAsText()
        // The property is in *no* namespace, so it comes back unprefixed — a
        // prefixed binding to "" is illegal XML and would make the whole
        // multistatus unparseable for exactly the clients this readback serves.
        assertTrue(
            Regex("<plain>no-ns</plain>").containsMatchIn(findBody),
            "the stored value must come back: $findBody"
        )
        // Both spellings of the illegal binding must be absent. The obvious one
        // is `xmlns:=""`; the one that actually reached the wire is
        // `xmlns:p0=""`, because the handler synthesizes a `p0`, `p1`… prefix per
        // distinct namespace URI so it can echo a URI back (a URI contains `:`
        // and `/` and cannot itself be a prefix). For a property in no namespace
        // that generation yields prefix `p0` with URI `""` — measured on the
        // readback as `<D:propstat xmlns:p0=""><p0:plain>` before the emitter was
        // keyed on the URI rather than the prefix.
        assertFalse(
            Regex("xmlns:[A-Za-z0-9_]+=\"\"").containsMatchIn(findBody),
            "no empty prefixed binding: $findBody"
        )
        assertFalse(findBody.contains("xmlns:=\"\""), "no empty prefixed binding: $findBody")
    }

    @Test
    fun `a no-namespace property and a real one coexist in one readback`() = runBlocking {
        // The two together are what the single-property test above cannot show:
        // with both present, the handler allocates one synthetic prefix per
        // distinct namespace URI, and the no-namespace property must not consume
        // one — otherwise it gets a binding to "" and the whole multistatus is
        // unparseable, taking the *other* property down with it.
        authorizedRequest("PUT", "/both.txt") { setBody("body") }
        val patch = authorizedRequest("PROPPATCH", "/both.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:marker>hello</Z:marker></D:prop></D:set>
  <D:set><D:prop><plain xmlns="">no-ns</plain></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.MultiStatus, patch.status)

        val findBody = authorizedRequest("PROPFIND", "/both.txt").bodyAsText()
        assertTrue(
            Regex("<plain>no-ns</plain>").containsMatchIn(findBody),
            "no-namespace value: $findBody"
        )
        assertTrue(
            Regex("<p\\d:marker>hello</p\\d:marker>").containsMatchIn(findBody),
            "real-namespace value: $findBody"
        )
        assertTrue(
            Regex("xmlns:p\\d=\"urn:example:test\"").containsMatchIn(findBody),
            "the real URI must be declared: $findBody"
        )
        assertFalse(
            Regex("xmlns:p\\d=\"\"").containsMatchIn(findBody),
            "no synthetic prefix may bind the empty URI: $findBody"
        )
    }

    @Test
    fun `a proppatch that tries to undeclare a prefix is refused`() = runBlocking {
        // `xmlns:Z=""` can only *undeclare* a prefix some ancestor bound. Using
        // it to mean "no namespace" is malformed XML — every namespace-aware
        // parser (Windows MiniRedir, Go's x/net/webdav, litmus) rejects the
        // document — so a 400 here is correct and is what keeps the server from
        // having to define behaviour for input no client can send. The legal
        // spelling is `xmlns=""` on an unprefixed element, covered above.
        authorizedRequest("PUT", "/doc.txt") { setBody("body") }
        val patch = authorizedRequest("PROPPATCH", "/doc.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="">
  <D:set><D:prop><Z:plain>no-ns</Z:plain></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.BadRequest, patch.status)
    }

    @Test
    fun `proppatch on a directory reports the dead properties on the collection href`() = runBlocking {
        authorizedRequest("MKCOL", "/docs")
        val patch = authorizedRequest("PROPPATCH", "/docs") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:label>Receipts</Z:label></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.MultiStatus, patch.status)
        assertTrue(patch.bodyAsText().contains("<D:href>/docs/</D:href>"), patch.bodyAsText())

        val find = authorizedRequest("PROPFIND", "/docs")
        val findBody = find.bodyAsText()
        assertTrue(findBody.contains("<p0:label>Receipts</p0:label>"), findBody)
        assertTrue(findBody.contains("xmlns:p0=\"urn:example:test\""), findBody)
    }

    @Test
    fun `a dav namespaced set is refused with cannot-modify-protected-property`() = runBlocking {
        // Live properties are computed from the file. Storing a client's value
        // would make the next PROPFIND a lie — so this is a 403 inside the 207,
        // not a silent acceptance and not a whole-request failure.
        authorizedRequest("PUT", "/doc.txt") { setBody("body") }
        val patch = authorizedRequest("PROPPATCH", "/doc.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><D:getcontentlength>99999</D:getcontentlength></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.MultiStatus, patch.status)
        val body = patch.bodyAsText()
        assertTrue(body.contains("<D:cannot-modify-protected-property/>"), body)
        assertTrue(body.contains("403 Forbidden"), body)
        // The live property must still tell the truth.
        val find = authorizedRequest("PROPFIND", "/doc.txt").bodyAsText()
        assertTrue(find.contains("<D:getcontentlength>4</D:getcontentlength>"), find)
    }

    @Test
    fun `a mixed proppatch reports both outcomes`() = runBlocking {
        // One request, two answers: 200 for what was stored, 403 for what was
        // refused. A single blanket status for the whole request is what made
        // the old implementation unfixable from the client side.
        authorizedRequest("PUT", "/doc.txt") { setBody("body") }
        val patch = authorizedRequest("PROPPATCH", "/doc.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:marker>kept</Z:marker></D:prop></D:set>
  <D:set><D:prop><D:getcontenttype>text/plain</D:getcontenttype></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.MultiStatus, patch.status)
        val body = patch.bodyAsText()
        // The response echoes the client's own prefix, so it must be bound.
        assertTrue(body.contains("xmlns:Z=\"urn:example:test\""), "unbound prefix: $body")
        assertTrue(body.contains("<Z:marker/>"), body)
        assertTrue(body.contains("<D:getcontenttype/>"), body)
        assertTrue(body.contains("200 OK"), body)
        assertTrue(body.contains("403 Forbidden"), body)

        val find = authorizedRequest("PROPFIND", "/doc.txt").bodyAsText()
        assertTrue(find.contains("<p0:marker>kept</p0:marker>"), find)
    }

    @Test
    fun `proppatch remove drops the property again`() = runBlocking {
        authorizedRequest("PUT", "/doc.txt") { setBody("body") }
        val set = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:marker>here</Z:marker></D:prop></D:set>
</D:propertyupdate>"""
        authorizedRequest("PROPPATCH", "/doc.txt") { setBody(set) }
        val stored = authorizedRequest("PROPFIND", "/doc.txt").bodyAsText()
        assertTrue(stored.contains("<p0:marker>here</p0:marker>"), stored)

        val remove = """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:remove><D:prop><Z:marker/></D:prop></D:remove>
</D:propertyupdate>"""
        assertEquals(HttpStatusCode.MultiStatus, authorizedRequest("PROPPATCH", "/doc.txt") { setBody(remove) }.status)
        assertFalse(authorizedRequest("PROPFIND", "/doc.txt").bodyAsText().contains("marker>here"))
    }

    @Test
    fun `a malformed proppatch body is 400`() = runBlocking {
        authorizedRequest("PUT", "/doc.txt") { setBody("body") }
        val response = authorizedRequest("PROPPATCH", "/doc.txt") { setBody("<not-a-propertyupdate/>") }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `proppatch on a missing resource is 404`() = runBlocking {
        val response = authorizedRequest("PROPPATCH", "/nope.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:marker>x</Z:marker></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `dead properties are scoped to one resource`() = runBlocking {
        // A property set on one file must not leak into a sibling's listing —
        // that is how a store keyed by name alone turns into cross-client
        // metadata bleed.
        authorizedRequest("PUT", "/a.txt") { setBody("A") }
        authorizedRequest("PUT", "/b.txt") { setBody("B") }
        authorizedRequest("PROPPATCH", "/a.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:marker>only-a</Z:marker></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        assertTrue(authorizedRequest("PROPFIND", "/a.txt").bodyAsText().contains("<p0:marker>only-a</p0:marker>"))
        assertFalse(authorizedRequest("PROPFIND", "/b.txt").bodyAsText().contains("marker>only-a"))
    }

    @Test
    fun `the root listing does not repeat a child's dead properties`() = runBlocking {
        // Only the resource's own properties belong in its own response; echoing
        // a child's into the parent's listing would make a directory of 500
        // files carry 500 extra propstats.
        authorizedRequest("PUT", "/a.txt") { setBody("A") }
        authorizedRequest("PROPPATCH", "/a.txt") {
            setBody(
                """<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:example:test">
  <D:set><D:prop><Z:marker>child-only</Z:marker></D:prop></D:set>
</D:propertyupdate>"""
            )
        }
        val rootListing = authorizedRequest("PROPFIND", "/").bodyAsText()
        assertFalse(rootListing.contains("marker>child-only"), rootListing)
        assertTrue(rootListing.contains("/a.txt"))
    }

    @Test
    fun `utf-8 filenames round trip`() = runBlocking {
        val put = authorizedRequest("PUT", "/%E4%B8%AD%E6%96%87%E6%96%87%E4%BB%B6.txt") { setBody("内容") }
        assertEquals(HttpStatusCode.Created, put.status)
        assertTrue(java.io.File(root, "中文文件.txt").isFile)
        assertEquals("内容", authorizedRequest("GET", "/%E4%B8%AD%E6%96%87%E6%96%87%E4%BB%B6.txt").bodyAsText())
        val listing = authorizedRequest("PROPFIND", "/").bodyAsText()
        assertTrue(listing.contains("%E4%B8%AD"))
    }

    @Test
    fun `head sends the header fields get would send`() = runBlocking {
        // RFC 7231 §4.3.2: HEAD is "identical to GET except that the server MUST
        // NOT send a message body", and it spells out the rest — "The server
        // SHOULD send the same header fields in response to a HEAD request as it
        // would have sent if the request had been a GET". Answering with
        // Content-Length alone left a client no `ETag` to compare, so the
        // cheapest "has this changed?" question it can ask had no answer and it
        // had to fall back to a full GET. Measured on-device before the fix.
        authorizedRequest("PUT", "/head-hdr.bin") { setBody("0123456789") }

        val get = authorizedRequest("GET", "/head-hdr.bin")
        val head = authorizedRequest("HEAD", "/head-hdr.bin")

        assertEquals(HttpStatusCode.OK, head.status)
        assertTrue(head.headers["ETag"] != null, "HEAD carried no ETag")
        assertEquals(get.headers["ETag"], head.headers["ETag"])
        assertEquals(get.headers["Last-Modified"], head.headers["Last-Modified"])
        assertEquals("10", head.headers["Content-Length"])
        assertTrue(head.bodyAsText().isEmpty(), "HEAD must not carry a body")
    }

    @Test
    fun `head on a collection invents no entity tag`() = runBlocking {
        // GET on a collection answers a directory index and sends neither an
        // ETag nor a Last-Modified, so a HEAD must not either — the invariant is
        // "the same headers GET would send", not "always send these headers".
        authorizedRequest("MKCOL", "/head-dir")
        val head = authorizedRequest("HEAD", "/head-dir")
        assertEquals(HttpStatusCode.OK, head.status)
        assertEquals(null, head.headers["ETag"])
        assertEquals("0", head.headers["Content-Length"])
    }

    @Test
    fun `propfind reports the entity tag that get reports`() = runBlocking {
        // RFC 4918 §15.6: "The getetag property MUST be defined on any
        // DAV-compliant resource that returns the Etag header." This server
        // sends one on GET, so a listing has to carry it too, or a client cannot
        // ask a folder whether anything changed without fetching every file.
        authorizedRequest("PUT", "/tagged.txt") { setBody("payload") }
        val etag = authorizedRequest("GET", "/tagged.txt").headers["ETag"]!!
        val xml = authorizedRequest("PROPFIND", "/tagged.txt").bodyAsText()
        val escaped = etag.replace("\"", "&quot;")
        assertTrue(xml.contains("<D:getetag>$escaped</D:getetag>"), xml)
    }

    @Test
    fun `a collection listing carries each file's entity tag`() = runBlocking {
        authorizedRequest("PUT", "/in-listing.txt") { setBody("x") }
        val etag = authorizedRequest("GET", "/in-listing.txt").headers["ETag"]!!
        val listing = authorizedRequest("PROPFIND", "/").bodyAsText()
        assertTrue(listing.contains("<D:getetag>${etag.replace("\"", "&quot;")}</D:getetag>"), listing)
    }

    @Test
    fun `move onto an existing destination answers 204`() = runBlocking {
        // RFC 4918 §9.9.4: 201 is "a new URL mapping was created at the
        // destination"; 204 is "moved to a URL that was already mapped". The
        // destination existed here, so a 201 reports a create that never
        // happened — measured on-device at 201 before the fix.
        authorizedRequest("PUT", "/mv-src.txt") { setBody("src") }
        authorizedRequest("PUT", "/mv-dst.txt") { setBody("old") }
        val moved = authorizedRequest("MOVE", "/mv-src.txt") {
            header("Destination", "http://127.0.0.1:$PORT/mv-dst.txt")
        }
        assertEquals(HttpStatusCode.NoContent, moved.status)
        assertEquals("src", authorizedRequest("GET", "/mv-dst.txt").bodyAsText())
        assertEquals(HttpStatusCode.NotFound, authorizedRequest("GET", "/mv-src.txt").status)
    }

    @Test
    fun `move to a free destination answers 201`() = runBlocking {
        authorizedRequest("PUT", "/mv2-src.txt") { setBody("src") }
        val moved = authorizedRequest("MOVE", "/mv2-src.txt") {
            header("Destination", "http://127.0.0.1:$PORT/mv2-dst.txt")
        }
        assertEquals(HttpStatusCode.Created, moved.status)
    }

    @Test
    fun `copy over an existing destination answers 204`() = runBlocking {
        authorizedRequest("PUT", "/cp-src.txt") { setBody("new") }
        authorizedRequest("PUT", "/cp-dst.txt") { setBody("old") }
        val copied = authorizedRequest("COPY", "/cp-src.txt") {
            header("Destination", "http://127.0.0.1:$PORT/cp-dst.txt")
        }
        assertEquals(HttpStatusCode.NoContent, copied.status)
        assertEquals("new", authorizedRequest("GET", "/cp-dst.txt").bodyAsText())
    }

    // ---------------------------------------------------------------- helpers

    private suspend fun request(
        method: String,
        path: String,
        block: io.ktor.client.request.HttpRequestBuilder.() -> Unit = {}
    ): HttpResponse = client.request("http://127.0.0.1:$PORT$path") {
        this.method = HttpMethod(method)
        block()
    }

    /** Performs the Digest handshake and returns the authorized response. */
    private suspend fun authorizedRequest(
        method: String,
        path: String,
        block: io.ktor.client.request.HttpRequestBuilder.() -> Unit = {}
    ): HttpResponse {
        val probe = request(method, path) {
            header("Authorization", "Digest username=\"$USERNAME\"")
        }
        if (probe.status != HttpStatusCode.Unauthorized) return probe

        val challenge = DigestAuthenticator.parseChallenge(probe.headers["WWW-Authenticate"])
            ?: error("no usable digest challenge")
        val cnonce = "abcdef012345"
        val nc = "00000001"
        val response = authenticator.computeResponse(
            username = USERNAME,
            password = PASSWORD,
            method = method,
            uri = path,
            nonce = challenge.nonce,
            nc = nc,
            cnonce = cnonce,
            qop = "auth"
        )
        return request(method, path) {
            header(
                "Authorization",
                "Digest username=\"$USERNAME\", realm=\"${challenge.realm}\", nonce=\"${challenge.nonce}\", " +
                    "uri=\"$path\", response=\"$response\", qop=auth, nc=$nc, cnonce=\"$cnonce\", " +
                    "opaque=\"${challenge.opaque}\""
            )
            block()
        }
    }
}
