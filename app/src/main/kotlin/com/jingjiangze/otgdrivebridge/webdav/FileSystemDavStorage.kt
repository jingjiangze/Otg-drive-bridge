package com.jingjiangze.otgdrivebridge.webdav

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * A [DavStorage] over a plain directory, used by the JVM unit tests.
 *
 * It mirrors the Android SAF implementation's contract (including atomic
 * writes) without needing the Android framework, so the protocol layer and the
 * integrity rules can be verified on CI runners that have no emulator.
 */
class FileSystemDavStorage(private val root: File) : DavStorage {

    init {
        require(root.isDirectory) { "root must be an existing directory: ${root.path}" }
    }

    override fun isRootAvailable(): Boolean =
        root.isDirectory && root.canRead() && root.canWrite()

    override fun node(segments: List<String>): DavNode? {
        val file = resolve(segments) ?: return null
        return if (file.exists()) FileNode(file) else null
    }

    override fun parentOf(segments: List<String>): Pair<DavNode, String>? {
        if (segments.isEmpty()) return null
        val parentFile = resolve(segments.dropLast(1)) ?: return null
        if (!parentFile.isDirectory) return null
        return FileNode(parentFile) to segments.last()
    }

    override fun createFile(parent: DavNode, name: String): DavNode? {
        val parentDir = fileOf(parent) ?: return null
        val target = File(parentDir, name)
        if (target.exists()) return if (target.isFile) FileNode(target) else null
        return if (target.createNewFile()) FileNode(target) else null
    }

    override fun createDirectory(parent: DavNode, name: String): DavNode? {
        val parentDir = fileOf(parent) ?: return null
        val target = File(parentDir, name)
        if (target.exists()) return if (target.isDirectory) FileNode(target) else null
        return if (target.mkdir()) FileNode(target) else null
    }

    override fun delete(node: DavNode): Boolean = fileOf(node)?.deleteRecursively() == true

    override fun move(node: DavNode, destination: DavNode, newName: String): Boolean {
        val src = fileOf(node) ?: return false
        val dstDir = fileOf(destination) ?: return false
        val target = File(dstDir, newName)
        if (target.exists()) return false
        return src.renameTo(target)
    }

    override fun copy(node: DavNode, destination: DavNode, newName: String): Boolean {
        val src = fileOf(node) ?: return false
        val dstDir = fileOf(destination) ?: return false
        val target = File(dstDir, newName)
        if (target.exists()) return false
        if (src.isDirectory) {
            if (!target.mkdirs()) return false
            src.listFiles()?.forEach { child ->
                if (!copy(FileNode(child), FileNode(target), child.name)) return false
            }
            return true
        }
        return runCatching {
            src.copyTo(target, overwrite = false)
            true
        }.getOrDefault(false)
    }

    override fun openRead(node: DavNode): InputStream? =
        fileOf(node)?.takeIf { it.isFile }?.let { FileInputStream(it) }

    override fun openWrite(node: DavNode, overwrite: Boolean): AtomicWriteHandle? {
        val target = fileOf(node) ?: return null
        if (target.exists() && !overwrite) return null
        if (target.isDirectory) return null
        return FileAtomicWriteHandle(target)
    }

    override fun mimeTypeOf(name: String): String {
        val ext = name.substringAfterLast('.', "").lowercase()
        return when (ext) {
            "txt", "log", "md" -> "text/plain"
            "html", "htm" -> "text/html"
            "xml" -> "application/xml"
            "json" -> "application/json"
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "pdf" -> "application/pdf"
            "zip" -> "application/zip"
            else -> "application/octet-stream"
        }
    }

    /** Resolves a path under [root], refusing to leave it even if segments misbehave. */
    private fun resolve(segments: List<String>): File? {
        var current = root
        for (seg in segments) {
            if (!WebDavPaths.isSafeSegment(seg)) return null
            current = File(current, seg)
            if (!current.canonicalPath.startsWith(root.canonicalPath + File.separator) &&
                current.canonicalPath != root.canonicalPath
            ) {
                return null
            }
        }
        return current
    }

    private fun fileOf(node: DavNode): File? =
        if (node is FileNode) node.file.takeIf { it.exists() } else null

    private class FileNode(val file: File) : DavNode {
        override val name: String get() = file.name
        override val isDirectory: Boolean get() = file.isDirectory
        override val length: Long get() = if (file.isFile) file.length() else 0L
        override val lastModified: Long get() = file.lastModified()
        override fun listChildren(): List<DavNode> =
            file.listFiles()?.map { FileNode(it) } ?: emptyList()
        override fun exists(): Boolean = file.exists()
    }

    /**
     * Stages into `<name>.otgpart` and renames on commit, so a dropped
     * connection leaves the original file intact.
     */
    private class FileAtomicWriteHandle(private val target: File) : AtomicWriteHandle {
        private val temp = File(target.parentFile, target.name + ".otgpart")
        private val stream = FileOutputStream(temp)
        private var done = false

        override val output: OutputStream get() = stream

        override fun commit(): Boolean = runCatching {
            stream.flush()
            stream.close()
            if (target.exists() && !target.delete()) return false
            if (!temp.renameTo(target)) {
                temp.copyTo(target, overwrite = true)
                temp.delete()
            }
            done = true
            true
        }.getOrElse { false }

        override fun abort() {
            runCatching { stream.close() }
            runCatching { temp.delete() }
        }

        override fun close() {
            if (!done) abort()
        }
    }
}
