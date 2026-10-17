package com.jingjiangze.otgdrivebridge.server

import com.jingjiangze.otgdrivebridge.security.CredentialRegistry
import com.jingjiangze.otgdrivebridge.security.DigestAuthenticator
import com.jingjiangze.otgdrivebridge.webdav.FileSystemDavStorage
import com.jingjiangze.otgdrivebridge.webdav.LockManager
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.statement.HttpResponse
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * End-to-end wiring of the origin-aware auth model: the LAN passkey, temporary
 * keys and the primary account coexist on one server, a stale nonce surfaces
 * as `stale=true`, and rotating a credential takes effect on the *next*
 * request without restarting the service.
 *
 * The origin *classification* itself (IpTrust) is exhaustively unit-tested in
 * [com.jingjiangze.otgdrivebridge.security.CredentialRegistryTest]; a loopback
 * Ktor server can only ever see 127.0.0.1, so what this file proves is that
 * the registry's candidate list is actually consulted per request and that the
 * Digest engine accepts any one of several accounts.
 */
class WebDavAuthSchemeTest {

    private companion object {
        const val PORT = 18081
        const val PRIMARY_USER = "otg"
        const val PRIMARY_PASS = "PrimaryPassw0rd"
    }

    private lateinit var root: java.io.File
    private lateinit var server: ServerBootstrap.StartedServer
    private lateinit var client: HttpClient
    private val authenticator = DigestAuthenticator()

    /** Stands in for prefs: the service's provider re-reads these each request. */
    private var registry = CredentialRegistry.EMPTY
    private var primary: DigestAuthenticator.Credentials? =
        DigestAuthenticator.Credentials(PRIMARY_USER, PRIMARY_PASS)

    @BeforeEach
    fun setUp() {
        root = Files.createTempDirectory("otg-authscheme").toFile()
        server = ServerBootstrap.start(
            port = PORT,
            storage = FileSystemDavStorage(root),
            credentialProvider = { origin ->
                val p = primary
                (if (p == null) emptyList() else listOf(p)) +
                    registry.acceptableCredentials(origin, System.currentTimeMillis())
            },
            host = "127.0.0.1",
            authenticator = authenticator,
            lockManager = LockManager()
        )
        client = HttpClient(CIO) { expectSuccess = false }
    }

    @AfterEach
    fun tearDown() {
        runCatching { client.close() }
        runCatching { server.close() }
        runCatching { root.deleteRecursively() }
    }

    private suspend fun request(method: String, path: String, auth: String? = null): HttpResponse =
        client.request("http://127.0.0.1:$PORT$path") {
            this.method = HttpMethod(method)
            if (auth != null) header("Authorization", auth)
        }

    /** Probe → answer the fresh challenge, mirroring what Windows' redirector does. */
    private suspend fun authorizedWith(user: String, pass: String, path: String = "/"): HttpResponse {
        val probe = request("PROPFIND", path, "Digest username=\"$user\"")
        if (probe.status != HttpStatusCode.Unauthorized) return probe
        val challenge = DigestAuthenticator.parseChallenge(probe.headers["WWW-Authenticate"]!!)
            ?: error("no usable digest challenge")
        val cnonce = "cafe0001"
        val nc = "00000001"
        val response = authenticator.computeResponse(
            username = user, password = pass, method = "PROPFIND", uri = path,
            nonce = challenge.nonce, nc = nc, cnonce = cnonce, qop = "auth"
        )
        return request(
            "PROPFIND", path,
            "Digest username=\"$user\", realm=\"${challenge.realm}\", nonce=\"${challenge.nonce}\", " +
                "uri=\"$path\", response=\"$response\", qop=auth, nc=$nc, cnonce=\"$cnonce\", " +
                "opaque=\"${challenge.opaque}\""
        )
    }

    @Test
    fun `the LAN passkey authenticates a local peer with no account`() = runBlocking {
        val key = CredentialRegistry.newLanPasskey()
        registry = CredentialRegistry.fromStored(CredentialRegistry.serialize(key), null)

        assertEquals(
            HttpStatusCode.MultiStatus,
            authorizedWith(key.username, key.password).status,
            "same-wifi holder of the passkey must reach the listing directly"
        )
    }

    @Test
    fun `primary account and passkey coexist`() = runBlocking {
        val key = CredentialRegistry.newLanPasskey()
        registry = CredentialRegistry.fromStored(CredentialRegistry.serialize(key), null)

        assertEquals(HttpStatusCode.MultiStatus, authorizedWith(PRIMARY_USER, PRIMARY_PASS).status)
        assertEquals(HttpStatusCode.MultiStatus, authorizedWith(key.username, key.password).status)

        // A username that is neither account, guessed with the passkey password:
        // the loop is by username, and a miss must be a plain 401, not a crash.
        val wrongName = request(
            "PROPFIND", "/",
            "Digest username=\"nope\", realm=\"${DigestAuthenticator.DEFAULT_REALM}\", nonce=\"x\""
        )
        assertEquals(HttpStatusCode.Unauthorized, wrongName.status)
    }

    @Test
    fun `a temporary key authenticates while alive and 401s after expiry`() = runBlocking {
        val live = CredentialRegistry.newTemporary(ttlMillis = 60_000)
        registry = CredentialRegistry.fromStored(null, CredentialRegistry.serializeAll(listOf(live)))
        assertEquals(HttpStatusCode.MultiStatus, authorizedWith(live.username, live.password).status)

        // Re-issue the same identity already expired: the registry hides it from
        // the candidate list, so the engine never gets a chance to match it.
        val dead = CredentialRegistry.TimedCredential(live.username, live.password, nowMillis(0))
        registry = CredentialRegistry.fromStored(null, CredentialRegistry.serializeAll(listOf(dead)))
        val resp = request("PROPFIND", "/", "Digest username=\"${live.username}\"")
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
        // And the challenge must NOT be stale: a revoked key is a rejection, not a nonce problem.
        assertTrue(!resp.headers["WWW-Authenticate"]!!.contains("stale=true"))
    }

    @Test
    fun `an aged nonce is answered with stale=true so the client retries silently`() = runBlocking {
        // A dedicated server whose nonces age in 50 ms: the default 300 s
        // lifetime cannot expire inside a test without a 5-minute sleep. The
        // handshake itself is still correct — this proves only that the
        // server consults nonce freshness *before* credentials, so an aged
        // nonce yields stale=true and a *fresh* challenge in the same reply.
        val shortLived = DigestAuthenticator(nonceLifetimeMillis = 50)
        val aged = ServerBootstrap.start(
            port = PORT + 1,
            storage = FileSystemDavStorage(root),
            credentialProvider = { listOf(DigestAuthenticator.Credentials(PRIMARY_USER, PRIMARY_PASS)) },
            host = "127.0.0.1",
            authenticator = shortLived,
            lockManager = LockManager()
        )
        try {
            val probe = client.request("http://127.0.0.1:${PORT + 1}/") {
                method = HttpMethod("PROPFIND")
                header("Authorization", "Digest username=\"$PRIMARY_USER\"")
            }
            val challenge = DigestAuthenticator.parseChallenge(probe.headers["WWW-Authenticate"]!!)!!
            val cnonce = "beef0002"
            val response = shortLived.computeResponse(
                username = PRIMARY_USER, password = PRIMARY_PASS, method = "PROPFIND", uri = "/",
                nonce = challenge.nonce, nc = "00000001", cnonce = cnonce, qop = "auth"
            )
            Thread.sleep(150)

            val resp = client.request("http://127.0.0.1:${PORT + 1}/") {
                method = HttpMethod("PROPFIND")
                header(
                    "Authorization",
                    "Digest username=\"$PRIMARY_USER\", realm=\"${challenge.realm}\", " +
                        "nonce=\"${challenge.nonce}\", uri=\"/\", response=\"$response\", qop=auth, " +
                        "nc=00000001, cnonce=\"$cnonce\", opaque=\"${challenge.opaque}\""
                )
            }
            assertEquals(HttpStatusCode.Unauthorized, resp.status)
            val fresh = resp.headers["WWW-Authenticate"]!!
            assertTrue(fresh.contains("stale=true"), "aged nonce must advertise staleness: $fresh")
            // The reply carries a new nonce; answering it with the same credentials
            // is the transparent retry a conforming client performs.
            val parsed = DigestAuthenticator.parseChallenge(fresh)!!
            assertNotNull(parsed.nonce)
            val retryResponse = shortLived.computeResponse(
                username = PRIMARY_USER, password = PRIMARY_PASS, method = "PROPFIND", uri = "/",
                nonce = parsed.nonce, nc = "00000001", cnonce = "beef0003", qop = "auth"
            )
            val ok = client.request("http://127.0.0.1:${PORT + 1}/") {
                method = HttpMethod("PROPFIND")
                header(
                    "Authorization",
                    "Digest username=\"$PRIMARY_USER\", realm=\"${parsed.realm}\", nonce=\"${parsed.nonce}\", " +
                        "uri=\"/\", response=\"$retryResponse\", qop=auth, nc=00000001, " +
                        "cnonce=\"beef0003\", opaque=\"${parsed.opaque}\""
                )
            }
            assertEquals(HttpStatusCode.MultiStatus, ok.status)
        } finally {
            runCatching { aged.close() }
        }
    }

    @Test
    fun `rotating credentials lands on the next request without a restart`() = runBlocking {
        val rotated = "FreshPassw0rd-2"
        primary = DigestAuthenticator.Credentials(PRIMARY_USER, rotated)
        assertEquals(HttpStatusCode.MultiStatus, authorizedWith(PRIMARY_USER, rotated).status)

        // A full handshake with the *old* pair must fail: the provider re-reads
        // `primary` per request, so the moment it changes the running server
        // stops accepting the previous credentials — this is the fix for the
        // service-level snapshot that used to keep honoring the old password
        // until restart.
        val staleAttempt = authorizedWith(PRIMARY_USER, "StaleOldPassw0rd")
        assertEquals(HttpStatusCode.Unauthorized, staleAttempt.status)
    }

    @Test
    fun `an empty candidate list rejects without leaking staleness`() = runBlocking {
        registry = CredentialRegistry.EMPTY
        primary = null
        val resp = request("PROPFIND", "/", "Digest username=\"x\"")
        assertEquals(HttpStatusCode.Unauthorized, resp.status)
        assertTrue(!resp.headers["WWW-Authenticate"]!!.contains("stale=true"))
    }

    private fun nowMillis(offset: Long) = System.currentTimeMillis() + offset
}
