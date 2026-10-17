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
        // A fabricated nonce is a rejection, NOT staleness: claiming stale here
        // would tell an attacker their credentials were otherwise acceptable.
        assertEquals(
            DigestAuthenticator.Outcome.Rejected,
            authenticator.verifyOutcome(header, listOf(credentials), "GET")
        )
    }

    @Test
    fun `an expired nonce yields Stale before credentials are consulted`() {
        val shortLived = DigestAuthenticator(nonceLifetimeMillis = 30)
        val parsed = DigestAuthenticator.parseChallenge(shortLived.challenge())!!
        // Even with the right password, age wins — and the outcome says "retry
        // the same credentials", which is exactly the stale=true contract.
        val header = digestFor(shortLived, parsed, "otg", "correct-horse-battery", "GET", "00000001")
        Thread.sleep(120)
        assertEquals(
            DigestAuthenticator.Outcome.Stale,
            shortLived.verifyOutcome(header, listOf(credentials), "GET")
        )
    }

    @Test
    fun `a nonce rotates after maxNonceCount requests`() {
        val bounded = DigestAuthenticator(nonceLifetimeMillis = 600_000, maxNonceCount = 2)
        val parsed = DigestAuthenticator.parseChallenge(bounded.challenge())!!
        for (nc in listOf("00000001", "00000002")) {
            val header = digestFor(bounded, parsed, "otg", "correct-horse-battery", "GET", nc)
            assertEquals(DigestAuthenticator.Outcome.Authorized, bounded.verifyOutcome(header, listOf(credentials), "GET"))
        }
        val third = digestFor(bounded, parsed, "otg", "correct-horse-battery", "GET", "00000003")
        assertEquals(
            DigestAuthenticator.Outcome.Stale,
            bounded.verifyOutcome(third, listOf(credentials), "GET"),
            "the third request must rotate the nonce — maxNonceCount was dead code before"
        )
    }

    @Test
    fun `any matching candidate authorizes and a wrong password among many does not leak`() {
        val parsed = DigestAuthenticator.parseChallenge(authenticator.challenge())!!
        val other = DigestAuthenticator.Credentials("lan", "lan-passkey")
        val good = digestFor(authenticator, parsed, "lan", "lan-passkey", "GET", "00000001")
        assertEquals(
            DigestAuthenticator.Outcome.Authorized,
            authenticator.verifyOutcome(good, listOf(credentials, other), "GET")
        )
        // Right username, wrong secret, among several valid accounts: Rejected,
        // not Stale — the client must not interpret it as "just retry".
        val badParsed = DigestAuthenticator.parseChallenge(authenticator.challenge())!!
        val bad = digestFor(authenticator, badParsed, "lan", "wrong", "GET", "00000001")
        assertEquals(
            DigestAuthenticator.Outcome.Rejected,
            authenticator.verifyOutcome(bad, listOf(credentials, other), "GET")
        )
    }

    /** Builds a correctly-signed header for one candidate account. */
    private fun digestFor(
        auth: DigestAuthenticator,
        challenge: DigestAuthenticator.Challenge,
        user: String,
        pass: String,
        method: String,
        nc: String
    ): DigestAuthenticator.DigestHeader {
        val cnonce = "cn-$nc"
        val response = auth.computeResponse(
            username = user, password = pass, method = method, uri = "/",
            nonce = challenge.nonce, nc = nc, cnonce = cnonce, qop = "auth"
        )
        return DigestAuthenticator.DigestHeader(
            username = user, realm = challenge.realm, nonce = challenge.nonce, uri = "/",
            response = response, qop = "auth", nc = nc, cnonce = cnonce, opaque = challenge.opaque
        )
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
