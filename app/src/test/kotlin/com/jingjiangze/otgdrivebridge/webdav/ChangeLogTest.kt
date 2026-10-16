package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * The change log that backs `DAV:sync-collection`.
 *
 * What matters here is not that a map records things — it is the three
 * behaviours a sync report depends on and can get silently wrong: hierarchy
 * (a file's change must be visible at its parent collection), ordering (a
 * token must split "before" from "after" exactly once), and the no-op case
 * (an unchanged tree must report nothing, or every client re-syncs forever).
 */
class ChangeLogTest {

    @Test
    fun `a file change is visible at the file and every ancestor`() {
        val log = ChangeLog()
        log.record("/a/b/c.txt")
        val (atRoot, _) = log.changesSince("/", 0)
        val (atA, _) = log.changesSince("/a", 0)
        val (atB, _) = log.changesSince("/a/b", 0)
        val (atC, _) = log.changesSince("/a/b/c.txt", 0)
        // `/b` is deliberately absent: it is *not* an ancestor of `/a/b/c.txt`,
        // and a prefix test that matched anywhere in the path would make every
        // directory report every file whose name merely contains it.
        val (atUnrelated, _) = log.changesSince("/b", 0)
        assertTrue(atRoot.contains("/a/b/c.txt"), atRoot.toString())
        assertTrue(atA.contains("/a/b/c.txt"), atA.toString())
        assertTrue(atB.contains("/a/b/c.txt"), atB.toString())
        assertFalse(atUnrelated.contains("/a/b/c.txt"), atUnrelated.toString())
        assertEquals(listOf("/a/b/c.txt"), atC)
    }

    @Test
    fun `nothing changed means nothing reported`() {
        val log = ChangeLog()
        val (hits, token) = log.changesSince("/", 0)
        assertTrue(hits.isEmpty())
        assertEquals(0, token)
    }

    @Test
    fun `a token taken before a write does not see it and one taken after does`() {
        val log = ChangeLog()
        log.record("/one.txt")
        val (_, tokenAfterOne) = log.changesSince("/", 0)
        log.record("/two.txt")
        val (sinceFirst, _) = log.changesSince("/", tokenAfterOne)
        assertEquals(listOf("/two.txt"), sinceFirst, "only the second write is after the token")
    }

    @Test
    fun `siblings stay distinct`() {
        val log = ChangeLog()
        log.record("/keep.txt")
        log.record("/drop.txt")
        val (hits, _) = log.changesSince("/", 0)
        assertEquals(listOf("/drop.txt", "/keep.txt"), hits)
    }

    @Test
    fun `the same path changed twice reports once with the latest token`() {
        val log = ChangeLog()
        log.record("/x.txt")
        log.record("/x.txt")
        val (hits, token) = log.changesSince("/", 0)
        assertEquals(listOf("/x.txt"), hits, "a member URL appears only once per report (RFC 6578 §3.2)")
        assertEquals(log.currentToken(), token)
    }

    @Test
    fun `changes under one directory do not leak into another`() {
        val log = ChangeLog()
        log.record("/docs/a.txt")
        val (docs, _) = log.changesSince("/docs", 0)
        val (photos, _) = log.changesSince("/photos", 0)
        assertTrue(docs.isNotEmpty(), docs.toString())
        assertTrue(photos.isEmpty(), photos.toString())
    }

    @Test
    fun `a path recorded without a leading slash still matches the collection form`() {
        // Both spellings arrive in practice — handler paths are normalised to
        // `/a/b`, while some call sites hold `a/b` from a join. The log must
        // not become two parallel histories over the spelling.
        val log = ChangeLog()
        log.record("a/b.txt")
        val (fromRoot, _) = log.changesSince("/", 0)
        assertTrue(fromRoot.contains("/a/b.txt"), fromRoot.toString())
    }
}
