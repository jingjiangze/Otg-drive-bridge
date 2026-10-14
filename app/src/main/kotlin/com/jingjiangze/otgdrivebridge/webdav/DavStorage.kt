package com.jingjiangze.otgdrivebridge.webdav

/**
 * The storage abstraction the WebDAV layer talks to.
 *
 * Deliberately an interface, not `android.content.Context`-bound: it lets the
 * whole protocol layer be unit-tested on the JVM with a temp-directory
 * implementation, while the Android build supplies a SAF/DocumentFile-backed
 * implementation. This is the seam the audit identified as "no reusable asset".
 */
interface DavStorage {

    /** True when the shared root is still readable and writable. */
    fun isRootAvailable(): Boolean

    /**
     * Resolves a normalised [segments] path to a node, or null when missing.
     * Must never escape the root — paths arrive already validated by
     * [WebDavPaths.normalize].
     */
    fun node(segments: List<String>): DavNode?

    /** Resolves the parent directory of a path plus the leaf name. */
    fun parentOf(segments: List<String>): Pair<DavNode, String>?

    /** Creates a file under [parent]; returns the created node, or the existing one. */
    fun createFile(parent: DavNode, name: String): DavNode?

    /** Creates a directory under [parent]; returns the created node, or the existing one. */
    fun createDirectory(parent: DavNode, name: String): DavNode?

    /** Deletes a node recursively. Returns false when it could not be removed. */
    fun delete(node: DavNode): Boolean

    /**
     * Moves/renames [node] into [destination] (a directory) as [newName].
     * [newName] defaults to the node's current name (a plain move).
     */
    fun move(node: DavNode, destination: DavNode, newName: String = node.name): Boolean

    /** Copies [node] into [destination] (a directory) as [newName]. */
    fun copy(node: DavNode, destination: DavNode, newName: String = node.name): Boolean

    /** Opens [node] for reading, or null when unavailable. */
    fun openRead(node: DavNode): java.io.InputStream?

    /**
     * Opens [node] for writing. Implementations must write to a temporary file
     * and atomically rename on close (see [AtomicWriteHandle]) so an interrupted
     * transfer never leaves a truncated file on the USB drive.
     */
    fun openWrite(node: DavNode, overwrite: Boolean): AtomicWriteHandle?

    /** Best-effort MIME type for a name. */
    fun mimeTypeOf(name: String): String
}

/** A file or directory inside the shared root. */
interface DavNode {
    val name: String
    val isDirectory: Boolean
    val length: Long
    val lastModified: Long
    fun listChildren(): List<DavNode>
    fun exists(): Boolean
}

/**
 * Write handle that stages bytes in a temp file and only publishes them via
 * rename on [commit]. If the client disconnects mid-PUT, [abort] removes the
 * temp file and the destination keeps its previous contents — this is what
 * makes an interrupted transfer safe on a non-journaled FAT32/exFAT drive.
 */
interface AtomicWriteHandle : AutoCloseable {
    val output: java.io.OutputStream

    /** Publishes the staged bytes. Returns false on failure. */
    fun commit(): Boolean

    /** Discards the staged bytes; the destination is untouched. */
    fun abort()
}
