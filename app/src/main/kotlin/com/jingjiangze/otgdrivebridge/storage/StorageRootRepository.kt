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
    private const val KEY_LAN_PASSKEY = "lan_passkey"
    private const val KEY_TEMPORARY_KEYS = "temporary_keys"
    private const val KEY_P2P_TOKEN = "openp2p_token"

    private fun prefs() = OtgDriveBridgeApp.instance.getSharedPreferences(PREFS, 0)

    fun save(root: StorageRoot) {
        prefs().edit()
            .putString(KEY_KIND, root.kind.name)
            .putString(KEY_TREE, root.treeUri)
            .putString(KEY_PATH, root.managedPath)
            .apply()
    }

    fun load(): StorageRoot? {
        val kind = prefs().getString(KEY_KIND, null) ?: return null
        return when (kind) {
            "TREE_URI" -> prefs().getString(KEY_TREE, null)?.let {
                StorageRoot(StorageRootKind.TREE_URI, treeUri = it)
            }
            "MANAGED_PATH" -> prefs().getString(KEY_PATH, null)?.let {
                StorageRoot(StorageRootKind.MANAGED_PATH, managedPath = it)
            }
            else -> null
        }
    }

    fun clear() {
        prefs().edit().clear().apply()
    }

    fun saveCredentials(username: String, password: String) {
        prefs().edit()
            .putString(KEY_USERNAME, username)
            .putString(KEY_PASSWORD, password)
            .apply()
    }

    fun credentials(): Pair<String, String>? {
        val prefs = prefs()
        val user = prefs.getString(KEY_USERNAME, null) ?: return null
        val pass = prefs.getString(KEY_PASSWORD, null) ?: return null
        return user to pass
    }

    /**
     * The openp2p network token, as the string the engine's `runAsModule`
     * expects. It is a credential: kept in app-private prefs like the WebDAV
     * password, never logged, never put in the join string the UI shows.
     * `allowBackup="false"` keeps it out of cloud backups.
     */
    fun saveP2pToken(token: String) {
        if (token.isBlank()) {
            prefs().edit().remove(KEY_P2P_TOKEN).apply()
        } else {
            prefs().edit().putString(KEY_P2P_TOKEN, token.trim()).apply()
        }
    }

    fun p2pToken(): String? = prefs().getString(KEY_P2P_TOKEN, null)?.takeIf { it.isNotBlank() }

    /**
     * The LAN passkey, stored as one serialized `CredentialRegistry` entry (or
     * absent = LAN key-only is off). Written by the UI, read per request through
     * [registry] — never snapshotted at service start.
     */
    fun saveLanPasskey(entry: com.jingjiangze.otgdrivebridge.security.CredentialRegistry.TimedCredential?) {
        if (entry == null) {
            prefs().edit().remove(KEY_LAN_PASSKEY).apply()
        } else {
            prefs().edit().putString(KEY_LAN_PASSKEY,
                com.jingjiangze.otgdrivebridge.security.CredentialRegistry.serialize(entry)).apply()
        }
    }

    /** Issues (or rotates) the LAN passkey, persists it, and returns it. */
    fun rotateLanPasskey(): com.jingjiangze.otgdrivebridge.security.CredentialRegistry.TimedCredential {
        val entry = com.jingjiangze.otgdrivebridge.security.CredentialRegistry.newLanPasskey()
        saveLanPasskey(entry)
        return entry
    }

    /**
     * Replaces the whole temporary-key list. Entries carry absolute expiry, so
     * compaction happens here on write: a revoked or expired key leaves prefs
     * instead of lingering until the next rotation.
     */
    fun saveTemporaryKeys(entries: List<com.jingjiangze.otgdrivebridge.security.CredentialRegistry.TimedCredential>) {
        val live = entries.filter {
            it.isAlive(System.currentTimeMillis())
        }
        prefs().edit().putString(
            KEY_TEMPORARY_KEYS,
            com.jingjiangze.otgdrivebridge.security.CredentialRegistry.serializeAll(live)
        ).apply()
    }

    /**
     * The full auth surface read fresh from disk. This is the function the
     * server's per-request provider calls — reading prefs on every request is
     * what fixes the old "rotate the password, the running service still speaks
     * the old one" breakage, and it makes LAN/temporary changes live without a
     * service restart.
     */
    fun registry(): com.jingjiangze.otgdrivebridge.security.CredentialRegistry {
        val prefs = prefs()
        return com.jingjiangze.otgdrivebridge.security.CredentialRegistry.fromStored(
            lanPasskeyLine = prefs.getString(KEY_LAN_PASSKEY, null),
            temporaryLines = prefs.getString(KEY_TEMPORARY_KEYS, null)
        )
    }
}
