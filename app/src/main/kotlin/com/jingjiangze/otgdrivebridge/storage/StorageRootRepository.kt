package com.jingjiangze.otgdrivebridge.storage

import com.jingjiangze.otgdrivebridge.OtgDriveBridgeApp

/**
 * Application-scoped store for the shared root and the WebDAV credentials.
 *
 * It sits in the `storage` package next to [StorageRoot]: every caller
 * (`MainActivity`, `WebDavService`) imports it from here, so the root package
 * only holds the [OtgDriveBridgeApp] application class.
 */
object StorageRootRepository {
    private const val PREFS = "otg_bridge"
    private const val KEY_KIND = "root_kind"
    private const val KEY_TREE = "root_tree_uri"
    private const val KEY_PATH = "root_managed_path"
    private const val KEY_USERNAME = "username"
    private const val KEY_PASSWORD = "password"

    fun save(root: StorageRoot) {
        val prefs = OtgDriveBridgeApp.instance.getSharedPreferences(PREFS, 0)
        prefs.edit()
            .putString(KEY_KIND, root.kind.name)
            .putString(KEY_TREE, root.treeUri)
            .putString(KEY_PATH, root.managedPath)
            .apply()
    }

    fun load(): StorageRoot? {
        val prefs = OtgDriveBridgeApp.instance.getSharedPreferences(PREFS, 0)
        val kind = prefs.getString(KEY_KIND, null) ?: return null
        return when (kind) {
            "TREE_URI" -> prefs.getString(KEY_TREE, null)?.let {
                StorageRoot(StorageRootKind.TREE_URI, treeUri = it)
            }
            "MANAGED_PATH" -> prefs.getString(KEY_PATH, null)?.let {
                StorageRoot(StorageRootKind.MANAGED_PATH, managedPath = it)
            }
            else -> null
        }
    }

    fun clear() {
        OtgDriveBridgeApp.instance.getSharedPreferences(PREFS, 0).edit().clear().apply()
    }

    fun saveCredentials(username: String, password: String) {
        OtgDriveBridgeApp.instance.getSharedPreferences(PREFS, 0).edit()
            .putString(KEY_USERNAME, username)
            .putString(KEY_PASSWORD, password)
            .apply()
    }

    fun credentials(): Pair<String, String>? {
        val prefs = OtgDriveBridgeApp.instance.getSharedPreferences(PREFS, 0)
        val user = prefs.getString(KEY_USERNAME, null) ?: return null
        val pass = prefs.getString(KEY_PASSWORD, null) ?: return null
        return user to pass
    }
}
