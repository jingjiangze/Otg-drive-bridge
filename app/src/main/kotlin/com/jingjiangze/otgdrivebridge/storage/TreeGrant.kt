package com.jingjiangze.otgdrivebridge.storage

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.result.ActivityResultLauncher
import java.io.File

/**
 * The SAF bridge the audit flagged as missing everywhere else.
 *
 * Existing projects either ship no SAF picker at all (`webdav-server-apk`) or
 * only reach removable volumes through `MANAGE_EXTERNAL_STORAGE`
 * (`NetworkShare`). This launcher is the minimal piece that wires the system
 * picker into the WebDAV root:
 *
 *  1. [pickTree] opens `ACTION_OPEN_DOCUMENT_TREE` on the OTG volume.
 *  2. [onTreePicked] takes a persistable read/write grant so it survives reboots.
 *  3. The resulting [StorageRoot] is handed to [SafDavStorage].
 *
 * It also reports whether a stored grant is still valid, which the service uses
 * to stop rather than serve a stale root.
 */
class TreeGrant(
    private val context: Context,
    /**
     * Only needed to open the picker. The grant *checks* — [onTreePicked],
     * [isGrantValid], [releaseGrant] — never touch it, which is why the service
     * and the Compose screen can build a checker without an Activity result
     * registry.
     */
    private val launcher: ActivityResultLauncher<Uri?>? = null
) {

    /**
     * Opens the system picker on the primary/shared storage volume.
     *
     * Android 11+ refuses to select the *root* of some removable volumes; the
     * caller must allow the user to pick a subdirectory. [initialUri] seeds the
     * picker with the removable volume so the user lands in the right place.
     *
     * Does nothing when this instance was built without a launcher.
     */
    fun pickTree(initialUri: Uri? = null) {
        val target = launcher ?: return
        runCatching {
            target.launch(initialUri)
        }
    }

    /**
     * Persists the grant for [treeUri] and returns the [StorageRoot].
     * Returns null when the system refused to grant write access.
     */
    fun onTreePicked(treeUri: Uri?): StorageRoot? {
        if (treeUri == null) return null
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        val granted = runCatching {
            context.contentResolver.takePersistableUriPermission(treeUri, flags)
            true
        }.getOrDefault(false)
        if (!granted) return null
        return StorageRoot(
            kind = StorageRootKind.TREE_URI,
            treeUri = treeUri.toString()
        )
    }

    /** Re-checks a stored root; false means the service must stop. */
    fun isGrantValid(root: StorageRoot): Boolean = when (root.kind) {
        StorageRootKind.TREE_URI -> {
            val uri = runCatching { Uri.parse(root.treeUri) }.getOrNull() ?: return false
            context.contentResolver.persistedUriPermissions.any {
                it.uri == uri && it.isReadPermission && it.isWritePermission
            }
        }
        StorageRootKind.MANAGED_PATH -> {
            val path = root.managedPath ?: return false
            hasAllFilesAccess() || File(path).canWrite()
        }
    }

    /** Releases a grant the user has revoked or replaced. */
    fun releaseGrant(root: StorageRoot) {
        if (root.kind != StorageRootKind.TREE_URI) return
        val uri = runCatching { Uri.parse(root.treeUri) }.getOrNull() ?: return
        runCatching {
            context.contentResolver.releasePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )
        }
    }

    /**
     * Seeds the picker with the first removable volume's document id, so the
     * user does not have to navigate the drawer. Returns null when no removable
     * volume is visible (then the picker opens on internal storage).
     */
    fun removableVolumeUri(): Uri? {
        val volumes = runCatching {
            context.getExternalFilesDirs(null).mapNotNull { dir ->
                dir ?: return@mapNotNull null
                val marker = "/Android/"
                val idx = dir.absolutePath.indexOf(marker)
                if (idx < 0) null else dir.absolutePath.substring(0, idx)
            }.distinct()
        }.getOrDefault(emptyList())
        val removable = volumes.firstOrNull { it.startsWith("/storage/") && !it.contains("emulated") }
            ?: return null
        return runCatching {
            DocumentsContract.buildDocumentUri(
                "com.android.externalstorage.documents",
                "$removable:"
            )
        }.getOrNull()
    }

    companion object {
        /** MIME of the volume root, accepted by the picker for directories. */
        const val TREE_MIME = DocumentsContract.Document.MIME_TYPE_DIR
    }
}
