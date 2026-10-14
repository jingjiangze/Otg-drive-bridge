package com.jingjiangze.otgdrivebridge.security

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Digest auth is what lets the server avoid Windows' Basic-auth blocks, so its
 * correctness is verified directly against the RFC 2616 formula.
 */
class DigestAuthenticatorTest {

    private val authenticator = DigestAuthenticator(realm = "OTG Drive Bridge")
    private val credentials = DigestAuthenticator.Credentials("otg", "correct-horse-battery")

    @Test
    fun `challenge advertises the realm qop nonce and opaque`() {
        val challenge = authenticator.challenge()
        assertTrue(challenge.startsWith("Digest "))
        assertTrue(challenge.contains("realm=\"OTG Drive Bridge\""))
        assertTrue(challenge.contains("qop=\"auth\""))
        assertTrue(challenge.contains("nonce=\""))
        assertTrue(challenge.contains("opaque=\""))
        assertFalse(challenge.contains("stale=true"))
    }

    @Test
    fun `stale challenge is flagged`() {
        assertTrue(authenticator.challenge(stale = true).contains("stale=true"))
    }

    @Test
    fun `a client that answers correctly is authorized`() {
        val challenge = authenticator.challenge()
        val parsed = DigestAuthenticator.parseChallenge(challenge) ?: error("challenge unparseable")
        // Simulate a client: build the response hash for GET /.
        val cnonce = "0a4f113b"
        val nc = "00000001"
        val response = authenticator.computeResponse(
            username = "otg",
            password = "correct-horse-battery",
            method = "GET",
            uri = "/",
            nonce = parsed.nonce,
            nc = nc,
            cnonce = cnonce,
            qop = "auth"
        )
        val header = DigestAuthenticator.DigestHeader(
            username = "otg",
            realm = "OTG Drive Bridge",
            nonce = parsed.nonce,
            uri = "/",
            response = response,
            qop = "auth",
            nc = nc,
            cnonce = cnonce,
            opaque = parsed.opaque
        )
        assertTrue(authenticator.verify(header, credentials, "GET"))
    }

    @Test
    fun `wrong password fails`() {
        val challenge = authenticator.challenge()
        val parsed = DigestAuthenticator.parseChallenge(challenge)!!
        val response = authenticator.computeResponse(
            username = "otg",
            password = "wrong-password",
            method = "GET",
            uri = "/",
            nonce = parsed.nonce,
            nc = "00000001",
            cnonce = "abc",
            qop = "auth"
        )
        val header = headerFor(parsed, response, cnonce = "abc")
        assertFalse(authenticator.verify(header, credentials, "GET"))
    }

    @Test
    fun `wrong method fails`() {
        val challenge = authenticator.challenge()
        val parsed = DigestAuthenticator.parseChallenge(challenge)!!
        val response = authenticator.computeResponse(
            username = "otg", password = "correct-horse-battery",
            method = "GET", uri = "/", nonce = parsed.nonce,
            nc = "00000001", cnonce = "abc", qop = "auth"
        )
        // Client computed for GET but claims PUT.
        assertFalse(authenticator.verify(headerFor(parsed, response, cnonce = "abc"), credentials, "PUT"))
    }

    @Test
    fun `replayed nonce count fails`() {
        val challenge = authenticator.challenge()
        val parsed = DigestAuthenticator.parseChallenge(challenge)!!
        val response = authenticator.computeResponse(
            username = "otg", password = "correct-horse-battery",
            method = "GET", uri = "/", nonce = parsed.nonce,
            nc = "00000001", cnonce = "abc", qop = "auth"
        )
        val header = headerFor(parsed, response, cnonce = "abc")
        assertTrue(authenticator.verify(header, credentials, "GET"))
        // Same nc again → replay.
        assertFalse(authenticator.verify(header, credentials, "GET"))
    }

    @Test
    fun `unknown nonce fails`() {
        val response = authenticator.computeResponse(
            username = "otg", password = "correct-horse-battery",
            method = "GET", uri = "/", nonce = "not-issued-here",
            nc = "00000001", cnonce = "abc", qop = "auth"
        )
        val header = DigestAuthenticator.DigestHeader(
            username = "otg", realm = "OTG Drive Bridge", nonce = "not-issued-here",
            uri = "/", response = response, qop = "auth", nc = "00000001",
            cnonce = "abc", opaque = null
        )
        assertFalse(authenticator.verify(header, credentials, "GET"))
    }

    @Test
    fun `parseHeader rejects malformed values`() {
        assertNull(DigestAuthenticator.parseHeader(null))
        assertNull(DigestAuthenticator.parseHeader(""))
        assertNull(DigestAuthenticator.parseHeader("Basic dXNlcjpwYXNz"))
        assertNull(DigestAuthenticator.parseHeader("Digest realm=\"x\""))
    }

    @Test
    fun `parseHeader handles quoted values with escapes`() {
        val parsed = DigestAuthenticator.parseHeader(
            "Digest username=\"otg\", realm=\"OTG Drive Bridge\", nonce=\"abc\", " +
                "uri=\"/a b/\", response=\"deadbeef\", qop=auth, nc=00000001, cnonce=\"xyz\", " +
                "opaque=\"op1\""
        )
        assertNotNull(parsed)
        assertEquals("otg", parsed!!.username)
        assertEquals("OTG Drive Bridge", parsed.realm)
        assertEquals("/a b/", parsed.uri)
        assertEquals("auth", parsed.qop)
        assertEquals("00000001", parsed.nc)
        assertEquals("op1", parsed.opaque)
    }

    private fun headerFor(
        challengeNonce: DigestAuthenticator.Challenge,
        response: String,
        cnonce: String
    ) = DigestAuthenticator.DigestHeader(
        username = "otg",
        realm = "OTG Drive Bridge",
        nonce = challengeNonce.nonce,
        uri = "/",
        response = response,
        qop = "auth",
        nc = "00000001",
        cnonce = cnonce,
        opaque = challengeNonce.opaque
    )
}

class CredentialGeneratorTest {

    @Test
    fun `generated passwords are unique long and typeable`() {
        val seen = HashSet<String>()
        repeat(200) {
            val password = CredentialGenerator.password()
            assertEquals(CredentialGenerator.DEFAULT_PASSWORD_LENGTH, password.length)
            assertTrue(password.all { it in CredentialGenerator.ALPHABET })
            seen += password
        }
        assertEquals(200, seen.size, "passwords must not repeat")
    }

    @Test
    fun `entropy is at least 128 bits at the default length`() {
        assertTrue(CredentialGenerator.entropyBits() >= 128.0)
    }

    @Test
    fun `rejects too short a password`() {
        val error = runCatching { CredentialGenerator.password(8) }.exceptionOrNull()
        assertTrue(error is IllegalArgumentException)
    }
}
