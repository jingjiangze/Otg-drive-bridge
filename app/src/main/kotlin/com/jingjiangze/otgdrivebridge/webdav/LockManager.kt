package com.jingjiangze.otgdrivebridge.webdav

/**
 * WebDAV lock manager (RFC 4918 §6).
 *
 * Windows/Explorer and Office issue LOCK before editing, then send UNLOCK (or
 * rely on the lock's timeout) afterwards. Without this, Office "save as" fails
 * and stale locks can block later writes.
 *
 * Design:
 *  - Locks are keyed by the *request path*, not the node, so a lock survives
 *    the node being replaced by a PUT (Office overwrites in place).
 *  - A lock carries an opaque token and an expiry; expired locks are purged
 *    lazily on access, so a crashed client cannot wedge the file forever.
 *  - `If:` header tokens are honoured: a write whose token matches an existing
 *    lock (even held by another session) is allowed.
 */
class LockManager(private val defaultTimeoutSeconds: Int = DEFAULT_TIMEOUT_SECONDS) {

    data class Lock(
        val path: String,
        val token: String,
        val owner: String,
        val expiresAtMillis: Long,
        val scope: String = "exclusive",
        val depth: String = "infinity"
    )

    private val locks = java.util.concurrent.ConcurrentHashMap<String, Lock>()

    fun lock(
        path: String,
        owner: String,
        timeoutSeconds: Int? = null,
        requestedToken: String? = null
    ): Lock {
        purgeExpired()
        val seconds = (timeoutSeconds ?: defaultTimeoutSeconds).coerceIn(1, MAX_TIMEOUT_SECONDS)
        val token = requestedToken?.takeIf { it.isNotBlank() } ?: newToken()
        val lock = Lock(
            path = path,
            token = token,
            owner = owner,
            expiresAtMillis = System.currentTimeMillis() + seconds * 1000L
        )
        locks[path] = lock
        return lock
    }

    fun unlock(path: String, token: String?): Boolean {
        val existing = locks[path] ?: return false
        if (token != null && token != existing.token) return false
        locks.remove(path)
        return true
    }

    /** Removes a lock by token alone (used by UNLOCK without a path match). */
    fun unlockByToken(token: String): Boolean {
        val entry = locks.entries.firstOrNull { it.value.token == token } ?: return false
        return locks.remove(entry.key, entry.value)
    }

    /**
     * True when the path is locked by somebody whose token is not in [ifHeader].
     * A missing/blank `If:` header never matches a lock, so unqualified writes
     * to a locked path are refused with 423.
     */
    fun isLockedByOther(path: String, ifHeader: String?): Boolean {
        purgeExpired()
        val lock = locks[path] ?: return false
        if (ifHeader.isNullOrBlank()) return true
        return !ifHeaderTokens(ifHeader).contains(lock.token)
    }

    fun find(path: String): Lock? {
        purgeExpired()
        return locks[path]
    }

    fun activeCount(): Int {
        purgeExpired()
        return locks.size
    }

    /** Clears every lock — called when the shared root or network changes. */
    fun clear() = locks.clear()

    /** RFC 4918 §10.1 lock token format: `opaquelocktoken:<uuid>`. */
    private fun newToken(): String {
        val uuid = java.util.UUID.randomUUID().toString()
        return "opaquelocktoken:$uuid"
    }

    private fun purgeExpired() {
        val now = System.currentTimeMillis()
        locks.entries.removeIf { it.value.expiresAtMillis <= now }
    }

    companion object {
        const val DEFAULT_TIMEOUT_SECONDS = 1800
        const val MAX_TIMEOUT_SECONDS = 86400

        /** Extracts `opaquelocktoken:...` values from an `If:` header. */
        fun ifHeaderTokens(ifHeader: String): Set<String> =
            Regex("<([^>]+)>").findAll(ifHeader).map { it.groupValues[1].trim() }.toSet()
    }
}
