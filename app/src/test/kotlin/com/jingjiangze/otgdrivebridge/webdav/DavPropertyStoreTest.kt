package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Dead-property store (RFC 4918 §4.4).
 *
 * These are unit tests rather than end-to-end ones on purpose: the store is
 * where the persistence guarantee actually lives, and a bug here is invisible
 * over HTTP — a PROPFIND that comes back empty looks exactly like a client that
 * never sent a PROPPATCH.
 */
class DavPropertyStoreTest {

    @Test
    fun `set then all returns the value`() {
        val store = DavPropertyStore()
        val key = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        store.set("/docs/a.txt", key, "Ada")
        assertEquals(mapOf(key to "Ada"), store.all("/docs/a.txt"))
    }

    @Test
    fun `set overwrites the previous value for the same name`() {
        val store = DavPropertyStore()
        val key = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        store.set("/a.txt", key, "Ada")
        store.set("/a.txt", key, "Grace")
        assertEquals("Grace", store.get("/a.txt", key))
    }

    @Test
    fun `two namespaces with the same local name stay distinct`() {
        val store = DavPropertyStore()
        val first = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        val second = DavPropertyStore.keyOf(name("X", "author", "urn:other:author"))
        store.set("/a.txt", first, "Ada")
        store.set("/a.txt", second, "Grace")
        assertEquals(2, store.all("/a.txt").size)
        assertEquals("Ada", store.get("/a.txt", first))
        assertEquals("Grace", store.get("/a.txt", second))
    }

    @Test
    fun `the same prefix in two namespaces does not collide`() {
        // The prefix is a per-document alias: two clients both pick `Z` for
        // unrelated namespaces. Keying on `Z:author` would let one client
        // overwrite the other's property — the exact bug the namespace-URI key
        // exists to prevent.
        val store = DavPropertyStore()
        val mine = DavPropertyStore.keyOf(name("Z", "author", "urn:example:mine"))
        val theirs = DavPropertyStore.keyOf(name("Z", "author", "urn:example:theirs"))
        store.set("/a.txt", mine, "mine")
        store.set("/a.txt", theirs, "theirs")
        assertEquals(2, store.all("/a.txt").size)
        assertEquals("mine", store.get("/a.txt", mine))
        assertEquals("theirs", store.get("/a.txt", theirs))
    }

    @Test
    fun `an element with no namespace is its own namespace`() {
        // `{}local` must not merge with a property bound to the empty URI, and
        // must not merge with the same local part in a real namespace.
        val store = DavPropertyStore()
        val none = DavPropertyStore.keyOf(name("Z", "author", ""))
        val empty = DavPropertyStore.keyOf(name("Z", "author", "urn:example:empty"))
        store.set("/a.txt", none, "no-namespace")
        store.set("/a.txt", empty, "empty-uri")
        assertEquals(2, store.all("/a.txt").size)
    }

    @Test
    fun `remove drops only the named property`() {
        val store = DavPropertyStore()
        val author = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        val reviewed = DavPropertyStore.keyOf(name("Z", "reviewed", "urn:example:reviewed"))
        store.set("/a.txt", author, "Ada")
        store.set("/a.txt", reviewed, "true")
        assertTrue(store.remove("/a.txt", author))
        assertNull(store.get("/a.txt", author))
        assertEquals("true", store.get("/a.txt", reviewed))
    }

    @Test
    fun `remove of an absent property reports false`() {
        val store = DavPropertyStore()
        val author = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        store.set("/a.txt", author, "Ada")
        assertFalse(store.remove("/a.txt", DavPropertyStore.keyOf(name("Z", "nope", "urn:example:nope"))))
        assertFalse(store.remove("/b.txt", author))
    }

    @Test
    fun `properties are scoped per path`() {
        val store = DavPropertyStore()
        val author = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        store.set("/a.txt", author, "Ada")
        assertNull(store.get("/b.txt", author))
        assertEquals(1, store.pathCount())
    }

    @Test
    fun `an empty value round trips`() {
        // A client clearing a property by setting "" is different from removing
        // it, and `all()` must not treat "" as "absent" — that would resurrect
        // the property on the next PROPFIND.
        val store = DavPropertyStore()
        val key = DavPropertyStore.keyOf(name("Z", "comment", "urn:example:comment"))
        store.set("/a.txt", key, "")
        assertTrue(store.all("/a.txt").containsKey(key))
        assertEquals("", store.get("/a.txt", key))
    }

    @Test
    fun `clear drops every path`() {
        val store = DavPropertyStore()
        val author = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        store.set("/a.txt", author, "Ada")
        store.set("/docs/b.txt", author, "Grace")
        store.clear()
        assertEquals(0, store.pathCount())
        assertTrue(store.all("/a.txt").isEmpty())
    }

    @Test
    fun `keyOf maps the root to a slash and paths to leading slash`() {
        assertEquals("/", DavPropertyStore.keyOf(emptyList()))
        assertEquals("/a.txt", DavPropertyStore.keyOf(listOf("a.txt")))
        assertEquals("/docs/a.txt", DavPropertyStore.keyOf(listOf("docs", "a.txt")))
    }

    @Test
    fun `a property key round trips its namespace and local part`() {
        val key = DavPropertyStore.keyOf(name("Z", "author", "urn:example:author"))
        assertEquals("urn:example:author", DavPropertyStore.namespaceOf(key))
        assertEquals("author", DavPropertyStore.localOf(key))
        // A local part containing the separator character must not be split:
        // `localOf` cuts at the closing brace, not at the last colon.
        val odd = DavPropertyStore.keyOf(name("Z", "a:b", "urn:example:x"))
        assertEquals("a:b", DavPropertyStore.localOf(odd))
    }

    @Test
    fun `concurrent writers do not lose or corrupt entries`() {
        // PROPPATCH runs on a Ktor worker thread while PROPFIND runs on another;
        // an unsynchronised HashMap read during a write is UB, not a race that
        // merely delays. 8 threads x 500 properties must all land.
        val store = DavPropertyStore()
        val threads = (0 until 8).map { t ->
            Thread {
                for (i in 0 until 500) {
                    store.set("/p$t.txt", DavPropertyStore.keyOf(name("Z", "n$i", "urn:example:n$i")), "v$i")
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        for (t in 0 until 8) {
            assertEquals(500, store.all("/p$t.txt").size, "thread $t lost entries")
        }
        assertEquals(8, store.pathCount())
    }

    private fun name(prefix: String, local: String, namespaceUri: String) =
        WebDavXml.QualifiedName(prefix, local).also { it.namespaceUri = namespaceUri }
}
