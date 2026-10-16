package com.jingjiangze.otgdrivebridge.webdav

/**
 * The change log behind `DAV:sync-collection` (RFC 6578): which paths changed,
 * in what order, so a client holding an old token can ask "what changed since".
 *
 * Why this exists at all: the storage layers have no change journal to lean on —
 * FAT32/exFAT have none (a Microsoft filesystem-comparison table lists "File
 * change log: NTFS=Yes, exFAT=No, FAT32=No"), and SAF documents neither. But
 * the server is on the path of *every* write — PUT, DELETE, MOVE, COPY, MKCOL,
 * PROPPATCH all funnel through the request handler — so recording the change
 * here is complete, and costs nothing when nobody reports.
 *
 * Durability is deliberately **none**. A token that survives a restart would
 * have to be written to the shared drive on every mutation, and the drive may
 * be FAT — the exact place this project avoids writing sidecars (see
 * [DavPropertyStore]). RFC 6578 §3.2 explicitly allows a server to invalidate
 * tokens ("Servers might be unable to maintain all of the change data … Servers
 * MUST limit themselves to invalidating tokens only when absolutely necessary");
 * a restart is such a case, and the client's recovery is a full re-sync with an
 * empty token, which is one PROPFIND-shaped round trip, not a data transfer.
 *
 * Hierarchy: reporting runs on a *collection*, so a change to `/a/b.txt` is
 * visible at `/a/b.txt`, at `/a`, and at `/`. Recording every ancestor is what
 * makes `sync-level: infinite` and `sync-level: 1` both work from the same log
 * — the report filters by depth, the log only needs to be findable per level.
 *
 * Concurrency: writes arrive on Ktor worker threads and the report reads while
 * they do; every access is synchronized, matching [DavPropertyStore].
 */
class ChangeLog {

    private val lock = Any()
    private var counter = 0L

    /** path -> last change sequence. Presence means "changed at or after the token before that sequence". */
    private val changed = HashMap<String, Long>()

    /**
     * Records a change to [path] and all of its ancestor collections.
     * [path] is root-relative (`"/a/b.txt"`); the root itself is `"/"`.
     */
    fun record(path: String) = synchronized(lock) {
        val canonical = canonical(path)
        counter += 1
        val sequence = counter
        if (canonical != "/") changed[canonical] = sequence
        // Walk up to the root, marking each parent collection. `/a/b.txt` ->
        // `/a` -> `/`. `substringBeforeLast('/')` on `/a` yields `""`, which is
        // the root by another spelling — normalised so lookups agree.
        //
        // The root itself is deliberately *not* stamped. A sync report names the
        // members of the collection that changed, and the root is the collection
        // being reported on, never a member of itself — stamping it made every
        // report carry a `/` href the client then had to recognise as "not a
        // member" (measured: a two-file sync answered three members).
        var segment = canonical
        while (segment != "/") {
            segment = segment.substringBeforeLast('/').ifEmpty { "/" }
            if (segment == "/") break
            changed[segment] = sequence
        }
    }

    /**
     * One spelling for a path: leading slash, no trailing one (except the root).
     *
     * Both spellings arrive in practice — handler paths are normalised to
     * `/a/b`, while some call sites hold `a/b` from a join. Without this the log
     * becomes two parallel histories over the spelling, and a client syncing one
     * never sees the other's changes.
     */
    private fun canonical(path: String): String {
        var value = path.trim()
        if (!value.startsWith("/")) value = "/$value"
        if (value.length > 1) value = value.trimEnd('/')
        return value.ifEmpty { "/" }
    }

    /**
     * Paths under [collectionPath] (itself included) changed after [token],
     * with the token to hand back afterwards.
     *
     * [token] is a sequence previously returned by [currentToken]; 0 means
     * "from the beginning", which is the initial-sync case of RFC 6578 §3.4.
     */
    fun changesSince(collectionPath: String, token: Long): Pair<List<String>, Long> = synchronized(lock) {
        val target = canonical(collectionPath)
        val prefix = if (target.endsWith("/")) target else "$target/"
        val hits = changed.entries
            .filter { (path, seq) ->
                seq > token && (path == target || path.startsWith(prefix))
            }
            .map { it.key }
            .sorted()
        hits to counter
    }

    /** The token to advertise right now. Opaque to clients; a URI is built around it. */
    fun currentToken(): Long = synchronized(lock) { counter }

    /** Drops everything — used when the storage root changes. */
    fun clear() = synchronized(lock) {
        changed.clear()
        counter = 0
    }
}
