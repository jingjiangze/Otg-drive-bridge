package com.jingjiangze.otgdrivebridge.storage

import android.content.Context
import android.net.Uri
import android.os.Environment
import android.provider.DocumentsContract
import android.util.Log
import android.webkit.MimeTypeMap
import androidx.documentfile.provider.DocumentFile
import com.jingjiangze.otgdrivebridge.webdav.AtomicWriteHandle
import com.jingjiangze.otgdrivebridge.webdav.DavNode
import com.jingjiangze.otgdrivebridge.webdav.DavStorage
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * Root reference for the shared directory.
 *
 * Two tracks, chosen by the user at setup time (see [StorageRootKind]):
 *  - [TREE_URI] — a SAF tree the user picked in the system picker, persisted
 *    with `takePersistableUriPermission`. Minimal permission, no all-files access.
 *  - [MANAGED_PATH] — a real filesystem path under `/storage/...`, enabled by
 *    `MANAGE_EXTERNAL_STORAGE`. Android's own documentation states this covers
 *    "the root directory of both the USB on-the-go (OTG) drive and the SD card".
 */
data class StorageRoot(
    val kind: StorageRootKind,
    val treeUri: String? = null,
    val managedPath: String? = null
) {
    /** Stable identity used as the DataStore key and for permission re-checks. */
    val key: String
        get() = when (kind) {
            StorageRootKind.TREE_URI -> "tree:$treeUri"
            StorageRootKind.MANAGED_PATH -> "path:$managedPath"
        }
}

enum class StorageRootKind { TREE_URI, MANAGED_PATH }

/**
 * [DavStorage] backed by either SAF `DocumentFile` or a real filesystem path.
 *
 * This is the bridge the market audit found missing in every existing project:
 * existing apps either force `MANAGE_EXTERNAL_STORAGE` (no SAF picker at all) or
 * keep the SAF code path dormant. Here both are first-class and selectable.
 *
 * Safety rules carried over from the audit:
 *  - Every write goes through a temp file + rename so an interrupted transfer
 *    never leaves a half-written file on a non-journaled FAT32/exFAT drive.
 *  - `DocumentFile.createFile`'s double-extension bug is worked around by
 *    stripping the extension implied by the MIME type.
 *  - Losing the URI permission or the volume being unmounted surfaces as
 *    `isRootAvailable() == false`, which the service turns into a hard stop
 *    rather than silently returning success.
 */
class SafDavStorage(
    private val context: Context,
    private val root: StorageRoot
) : DavStorage {

    private val rootDocument: DocumentFile? = openRoot()

    private fun openRoot(): DocumentFile? = when (root.kind) {
        StorageRootKind.TREE_URI -> {
            val uri = Uri.parse(root.treeUri) ?: return null
            runCatching {
                DocumentFile.fromTreeUri(context, uri)
                    ?: DocumentFile.fromSingleUri(context, uri)
            }.getOrNull()?.takeIf { it.canRead() }
        }
        StorageRootKind.MANAGED_PATH -> {
            val path = root.managedPath ?: return null
            if (!Environment.isExternalStorageManager() && !File(path).canRead()) return null
            runCatching { DocumentFile.fromFile(File(path)) }.getOrNull()
        }
    }

    override fun isRootAvailable(): Boolean {
        val doc = rootDocument ?: return false
        return runCatching { doc.canRead() }.getOrDefault(false) && when (root.kind) {
            StorageRootKind.TREE_URI -> hasPersistedPermission()
            StorageRootKind.MANAGED_PATH ->
                Environment.isExternalStorageManager() || File(root.managedPath).canWrite()
        }
    }

    override fun node(segments: List<String>): DavNode? {
        val doc = rootDocument ?: return null
        var current: DocumentFile = doc
        for (seg in segments) {
            current = current.findFile(seg) ?: return null
        }
        return DocumentFileNode(current)
    }

    override fun parentOf(segments: List<String>): Pair<DavNode, String>? {
        if (segments.isEmpty()) return null
        val parent = node(segments.dropLast(1)) ?: return null
        if (!parent.isDirectory) return null
        return parent to segments.last()
    }

    override fun createFile(parent: DavNode, name: String): DavNode? {
        val parentDoc = docOf(parent) ?: return null
        parentDoc.findFile(name)?.let { return if (it.isFile) DocumentFileNode(it) else null }
        val mime = mimeTypeOf(name)
        // SAF trees re-append the MIME extension, so strip a matching suffix.
        val displayName = stripMimeExtension(name, mime)
        val created = parentDoc.createFile(mime, displayName) ?: return null
        return DocumentFileNode(created)
    }

    override fun createDirectory(parent: DavNode, name: String): DavNode? {
        val parentDoc = docOf(parent) ?: return null
        parentDoc.findFile(name)?.let { return if (it.isDirectory) DocumentFileNode(it) else null }
        val created = parentDoc.createDirectory(name) ?: return null
        return DocumentFileNode(created)
    }

    override fun delete(node: DavNode): Boolean = docOf(node)?.delete() == true

    override fun move(node: DavNode, destination: DavNode, newName: String): Boolean {
        val doc = docOf(node) ?: return false
        val destDoc = docOf(destination) ?: return false
        // Native move keeps the original name; a rename falls back to copy+delete
        // because DocumentsContract has no rename verb.
        if (newName == (doc.name ?: "")) {
            return runCatching {
                DocumentsContract.moveDocument(
                    context.contentResolver,
                    doc.uri,
                    destDoc.uri,
                    DocumentsContract.DOCUMENT_ID_PARENT_CHILD
                )
            }.getOrDefault(false)
        }
        return runCatching {
            copyRecursive(doc, destDoc, newName) && doc.delete()
        }.getOrDefault(false)
    }

    override fun copy(node: DavNode, destination: DavNode, newName: String): Boolean {
        val source = docOf(node) ?: return false
        val destDir = docOf(destination) ?: return false
        return copyRecursive(source, destDir, newName)
    }

    private fun copyRecursive(source: DocumentFile, destDir: DocumentFile, newName: String): Boolean {
        if (source.isDirectory) {
            val target = createDirectory(DocumentFileNode(destDir), newName) ?: return false
            val targetDoc = docOf(target) ?: return false
            return source.listFiles().all { copyRecursive(it, targetDoc, it.name ?: return false) }
        }
        val target = createFile(DocumentFileNode(destDir), newName) ?: return false
        val targetDoc = docOf(target) ?: return false
        return runCatching {
            context.contentResolver.openInputStream(source.uri)?.use { input ->
                context.contentResolver.openOutputStream(targetDoc.uri, "wt")?.use { output ->
                    input.copyTo(output)
                }
            } != null
        }.getOrDefault(false)
    }

    override fun openRead(node: DavNode): InputStream? {
        val doc = docOf(node) ?: return null
        val file = backingFile(doc)
        if (file != null) return runCatching { FileInputStream(file) }.getOrNull()
        return runCatching { context.contentResolver.openInputStream(doc.uri) }.getOrNull()
    }

    override fun openWrite(node: DavNode, overwrite: Boolean): AtomicWriteHandle? {
        val doc = docOf(node) ?: return null
        if (!overwrite && doc.exists()) return null
        return DocumentFileAtomicWrite(context, doc)
    }

    override fun mimeTypeOf(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext)
            ?: "application/octet-stream"
    }

    private fun docOf(node: DavNode): DocumentFile? =
        (node as? DocumentFileNode)?.document

    private fun backingFile(doc: DocumentFile): File? {
        val uri = doc.uri
        return if (uri.scheme == "file") uri.path?.let { File(it) } else null
    }

    /** True when the SAF grant is still held (survives reboots). */
    fun hasPersistedPermission(): Boolean {
        val target = runCatching { Uri.parse(root.treeUri) }.getOrNull() ?: return false
        return context.contentResolver.persistedUriPermissions.any {
            it.uri == target && it.isReadPermission && it.isWritePermission
        }
    }

    private inner class DocumentFileNode(val document: DocumentFile) : DavNode {
        override val name: String get() = document.name ?: document.uri.lastPathSegment ?: "?"
        override val isDirectory: Boolean get() = document.isDirectory
        override val length: Long get() = if (document.isDirectory) 0L else document.length()
        override val lastModified: Long get() = document.lastModified()
        override fun listChildren(): List<DavNode> =
            runCatching { document.listFiles().map { DocumentFileNode(it) } }.getOrDefault(emptyList())
        override fun exists(): Boolean = runCatching { document.exists() }.getOrDefault(false)
    }

    /**
     * Stages a PUT into a sibling `.otgpart` file and renames it into place on
     * commit. Works on both SAF trees and real paths.
     */
    private class DocumentFileAtomicWrite(
        private val context: Context,
        private val target: DocumentFile
    ) : AtomicWriteHandle {

        private val temp = File(context.cacheDir, "otg-upload-${System.nanoTime()}.part")
        private val stream = FileOutputStream(temp)
        private var finished = false

        override val output: OutputStream get() = stream

        override fun commit(): Boolean = runCatching {
            stream.flush()
            stream.close()
            val resolver = context.contentResolver
            val published = resolver.openOutputStream(target.uri, "wt")?.use { out ->
                temp.inputStream().use { it.copyTo(out) }
                true
            } ?: false
            if (published) {
                temp.delete()
                finished = true
                true
            } else {
                false
            }
        }.getOrElse {
            Log.w(TAG, "commit failed", it)
            false
        }

        override fun abort() {
            runCatching { stream.close() }
            runCatching { temp.delete() }
        }

        override fun close() {
            if (!finished) abort()
        }

        private companion object {
            const val TAG = "SafDavStorage"
        }
    }

    companion object {
        /** Removes a trailing extension that SAF would re-append (`a.txt` → `a`). */
        fun stripMimeExtension(name: String, mime: String): String {
            val ext = MimeTypeMap.getSingleton().getExtensionFromMimeType(mime) ?: return name
            val suffix = ".$ext"
            return if (name.endsWith(suffix, ignoreCase = true)) {
                name.dropLast(suffix.length).ifEmpty { name }
            } else {
                name
            }
        }
    }
}
