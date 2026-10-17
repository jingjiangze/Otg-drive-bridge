package com.jingjiangze.otgdrivebridge.security

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The origin gate is the whole LAN trust model, so its table is exhaustive on
 * the spellings a hostile client can hand the server: leading zeros, extra
 * octets, IPv6 scope ids, CGNAT space, link-local. Everything that is not a
 * literal site-local address must classify as remote.
 */
class CredentialRegistryTest {

    @Test
    fun `site-local literals are local`() {
        for (host in listOf("127.0.0.1", "10.1.2.3", "192.168.4.20", "172.16.0.1", "172.31.255.255", "::1", "fc12::34", "fd00::1")) {
            assertTrue(IpTrust.isLocalOrigin(host), "$host should be local")
        }
    }

    @Test
    fun `everything else is remote`() {
        for (host in listOf(
            "203.0.113.7",          // public
            "172.32.0.1",           // just outside 172.16/12
            "169.254.1.1",          // link-local IPv4
            "fe80::1",              // link-local IPv6 — every interface has one
            "100.64.0.1",           // CGNAT / tailnet space: *not* same-Wi-Fi
            "010.0.0.1",            // leading zero: parses differently per stack
            "10.0.0.1.7",           // five octets
            "10.0.0.999",           // octet out of range
            "localhost",            // a name — and the rule is never to resolve one
            "evil.127.0.0.1.attacker.example",
            "",
            "   "
        )) {
            assertFalse(IpTrust.isLocalOrigin(host), "$host must not be trusted as local")
        }
    }

    @Test
    fun `the lan passkey is only offered to local origins and temporaries always`() {
        val now = 1_000_000L
        val registry = CredentialRegistry.fromStored(
            lanPasskeyLine = CredentialRegistry.serialize(
                CredentialRegistry.TimedCredential(CredentialRegistry.LAN_USERNAME, "lansecret", null)
            ),
            temporaryLines = CredentialRegistry.serializeAll(
                listOf(
                    CredentialRegistry.TimedCredential("tmp-ab12", "tempsecret", now + 1),
                    CredentialRegistry.TimedCredential("tmp-expd", "oldsecret", now - 1)
                )
            )
        )

        val local = registry.acceptableCredentials("192.168.1.9", now).map { it.username }
        assertTrue("lan" in local)
        assertTrue("tmp-ab12" in local)
        assertFalse("tmp-expd" in local, "expired keys must not be offered anywhere")

        val remote = registry.acceptableCredentials("203.0.113.7", now).map { it.username }
        assertFalse("lan" in remote, "the LAN passkey must never be a remote option")
        assertTrue("tmp-ab12" in remote)
    }

    @Test
    fun `a garbage line drops that entry, not the set`() {
        val good = CredentialRegistry.serialize(
            CredentialRegistry.TimedCredential(CredentialRegistry.LAN_USERNAME, "s3cret", null)
        )
        val registry = CredentialRegistry.fromStored(
            lanPasskeyLine = "no-separator\n$good\nlan|has spaces but wrong field count|extra|tail",
            temporaryLines = "tmp-x|only-two-fields\nbogus|password|not-a-number\ntmp-ok|p4ss|5000"
        )
        assertEquals(CredentialRegistry.LAN_USERNAME, registry.lanPasskey?.username)
        assertEquals(listOf("tmp-ok"), registry.temporaries.map { it.username })
        assertEquals(5000L, registry.temporaries.single().expiresAtMillis)
    }

    @Test
    fun `a never-expiring entry round-trips through the 0 sentinel`() {
        val entry = CredentialRegistry.TimedCredential("lan", "pw", null)
        val parsed = CredentialRegistry.parseEntries(CredentialRegistry.serialize(entry)).single()
        assertEquals(entry, parsed)
        assertNull(parsed.expiresAtMillis)
        assertTrue(parsed.isAlive(Long.MAX_VALUE))
    }

    @Test
    fun `issued keys carry the usernames the server and UI agree on`() {
        val lan = CredentialRegistry.newLanPasskey()
        val temp = CredentialRegistry.newTemporary(ttlMillis = 60_000, nowMillis = 1000L)
        assertEquals(CredentialRegistry.LAN_USERNAME, lan.username)
        assertNull(lan.expiresAtMillis, "the LAN passkey rotates by user action, not by clock")
        assertTrue(temp.username.startsWith("tmp-"))
        assertEquals(61_000L, temp.expiresAtMillis)
        assertTrue(temp.password.length >= CredentialGenerator.MIN_LENGTH)
    }
}
