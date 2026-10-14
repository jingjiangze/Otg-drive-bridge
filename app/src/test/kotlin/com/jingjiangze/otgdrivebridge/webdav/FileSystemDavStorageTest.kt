package com.jingjiangze.otgdrivebridge.webdav

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.file.Files

/**
 * Storage-layer contract, including the atomic-write guarantee that makes an
 * interrupted upload safe on a non-journaled FAT32/exFAT USB drive.
 */
class FileSystemDavStorageTest {

    private lateinit var root: java.io.File
    private lateinit var storage: FileSystemDavStorage

    private fun setup() {
        root = Files.createTempDirectory("otg-storage").toFile()
        storage = FileSystemDavStorage(root)
    }

    @Test
    fun `creates lists and deletes files`() {
        setup()
        val rootNode = storage.node(emptyList())!!
        assertTrue(rootNode.isDirectory)

        val created = storage.createFile(rootNode, "notes.txt")
        assertNotNull(created)
        assertEquals("notes.txt", created!!.name)
        assertFalse(created.isDirectory)

        val found = storage.node(listOf("notes.txt"))
        assertEquals("notes.txt", found?.name)
        assertTrue(storage.delete(found!!))
        assertNull(storage.node(listOf("notes.txt")))
    }

    @Test
    fun `creates nested directories`() {
        setup()
        val docs = storage.createDirectory(storage.node(emptyList())!!, "docs")!!
        val sub = storage.createDirectory(docs, "sub")!!
        assertTrue(storage.node(listOf("docs", "sub"))!!.isDirectory)
        assertNull(storage.node(listOf("docs", "missing")))
    }

    @Test
    fun `parentOf returns the directory and leaf name`() {
        setup()
        val docs = storage.createDirectory(storage.node(emptyList())!!, "docs")!!
        storage.createFile(docs, "a.txt")
        val (parent, leaf) = storage.parentOf(listOf("docs", "a.txt"))!!
        assertEquals("docs", parent.name)
        assertEquals("a.txt", leaf)
    }

    @Test
    fun `an aborted write leaves the original file untouched`() {
        setup()
        val target = storage.createFile(storage.node(emptyList())!!, "keep.bin")!!
        storage.openWrite(target, overwrite = true)!!.use { handle ->
            handle.output.write("COMPLETE".toByteArray())
            handle.commit()
        }
        assertEquals("COMPLETE", readViaStorage(storage, listOf("keep.bin")))

        // Simulate a client that disconnects mid-upload: never commit.
        val handle = storage.openWrite(target, overwrite = true)!!
        handle.output.write("HALF".toByteArray())
        handle.abort()

        // The published file must still hold the previous, complete contents.
        assertEquals("COMPLETE", readViaStorage(storage, listOf("keep.bin")))
    }

    @Test
    fun `closing a handle without commit discards the upload`() {
        setup()
        val target = storage.createFile(storage.node(emptyList())!!, "drop.txt")!!
        val handle = storage.openWrite(target, overwrite = true)!!
        handle.output.write("partial".toByteArray())
        handle.close()
        assertEquals("", readViaStorage(storage, listOf("drop.txt")))
    }

    @Test
    fun `openWrite refuses an existing file when overwrite is false`() {
        setup()
        storage.createFile(storage.node(emptyList())!!, "x.txt")
        val existing = storage.node(listOf("x.txt"))!!
        assertNull(storage.openWrite(existing, overwrite = false))
        assertNotNull(storage.openWrite(existing, overwrite = true))
    }

    @Test
    fun `move relocates a file`() {
        setup()
        val rootNode = storage.node(emptyList())!!
        storage.createFile(rootNode, "a.txt")
        val docs = storage.createDirectory(rootNode, "docs")!!
        val file = storage.node(listOf("a.txt"))!!
        assertTrue(storage.move(file, docs))
        assertNull(storage.node(listOf("a.txt")))
        assertNotNull(storage.node(listOf("docs", "a.txt")))
    }

    @Test
    fun `move can rename into a new name`() {
        setup()
        val rootNode = storage.node(emptyList())!!
        storage.createFile(rootNode, "a.txt")
        val docs = storage.createDirectory(rootNode, "docs")!!
        val file = storage.node(listOf("a.txt"))!!
        assertTrue(storage.move(file, docs, "renamed.txt"))
        assertNull(storage.node(listOf("a.txt")))
        assertNull(storage.node(listOf("docs", "a.txt")))
        assertNotNull(storage.node(listOf("docs", "renamed.txt")))
    }

    @Test
    fun `copy duplicates a tree`() {
        setup()
        val rootNode = storage.node(emptyList())!!
        val src = storage.createDirectory(rootNode, "src")!!
        storage.createFile(src, "in.txt").let { node ->
            storage.openWrite(node!!, overwrite = true)!!.use {
                it.output.write("payload".toByteArray()); it.commit()
            }
        }
        val dest = storage.createDirectory(rootNode, "dest")!!
        assertTrue(storage.copy(src, dest))
        assertEquals("payload", readViaStorage(storage, listOf("dest", "src", "in.txt")))
    }

    @Test
    fun `copy honours the requested name`() {
        setup()
        val rootNode = storage.node(emptyList())!!
        storage.createFile(rootNode, "a.txt").let { node ->
            storage.openWrite(node!!, overwrite = true)!!.use {
                it.output.write("payload".toByteArray()); it.commit()
            }
        }
        val docs = storage.createDirectory(rootNode, "docs")!!
        val file = storage.node(listOf("a.txt"))!!
        assertTrue(storage.copy(file, docs, "b.txt"))
        assertEquals("payload", readViaStorage(storage, listOf("docs", "b.txt")))
        assertNotNull(storage.node(listOf("a.txt")))
    }

    @Test
    fun `delete removes directories recursively`() {
        setup()
        val rootNode = storage.node(emptyList())!!
        val docs = storage.createDirectory(rootNode, "docs")!!
        storage.createFile(docs, "a.txt")
        storage.createDirectory(docs, "nested")
        assertTrue(storage.delete(docs))
        assertNull(storage.node(listOf("docs")))
    }

    @Test
    fun `mimeTypeOf maps common extensions`() {
        setup()
        assertEquals("text/plain", storage.mimeTypeOf("a.txt"))
        assertEquals("image/png", storage.mimeTypeOf("a.PNG"))
        assertEquals("application/octet-stream", storage.mimeTypeOf("a.unknownext"))
    }

    @Test
    fun `isRootAvailable is true for a writable directory`() {
        setup()
        assertTrue(storage.isRootAvailable())
    }

    private fun readViaStorage(storage: DavStorage, segments: List<String>): String {
        val node = storage.node(segments)!!
        return storage.openRead(node)!!.use { it.readBytes().toString(Charsets.UTF_8) }
    }
}

class LockManagerTest {

    @Test
    fun `lock unlock round trip`() {
        val manager = LockManager()
        val lock = manager.lock("/docs/a.txt", "Office/16.0")
        assertTrue(lock.token.startsWith("opaquelocktoken:"))
        assertEquals(1, manager.activeCount())
        assertTrue(manager.isLockedByOther("/docs/a.txt", "<${lock.token}>") == false)
        assertTrue(manager.unlock("/docs/a.txt", lock.token))
        assertEquals(0, manager.activeCount())
    }

    @Test
    fun `an unqualified write to a locked path is refused`() {
        val manager = LockManager()
        manager.lock("/a.txt", "client")
        assertTrue(manager.isLockedByOther("/a.txt", null))
        assertTrue(manager.isLockedByOther("/a.txt", ""))
    }

    @Test
    fun `a matching If token unlocks the write`() {
        val manager = LockManager()
        val lock = manager.lock("/a.txt", "client")
        assertFalse(manager.isLockedByOther("/a.txt", "<${lock.token}> (\"tag\")"))
    }

    @Test
    fun `expired locks are purged`() {
        val manager = LockManager()
        manager.lock("/a.txt", "client", timeoutSeconds = 0)
        // A zero timeout still clamps to 1s; force expiry by manipulating time.
        Thread.sleep(1100)
        assertFalse(manager.isLockedByOther("/a.txt", null))
    }

    @Test
    fun `unlockByToken works without a path`() {
        val manager = LockManager()
        val lock = manager.lock("/a.txt", "client")
        assertTrue(manager.unlockByToken(lock.token))
        assertFalse(manager.unlockByToken(lock.token))
    }

    @Test
    fun `ifHeaderTokens extracts bracketed values`() {
        val tokens = LockManager.ifHeaderTokens("<opaquelocktoken:1> (<opaquelocktoken:2>)")
        assertEquals(setOf("opaquelocktoken:1", "opaquelocktoken:2"), tokens)
    }
}
