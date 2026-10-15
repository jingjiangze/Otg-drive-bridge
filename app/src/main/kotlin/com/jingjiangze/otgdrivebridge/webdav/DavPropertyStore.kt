package com.jingjiangze.otgdrivebridge.webdav

/**
 * Client-set "dead properties" (RFC 4918 §4.4) — the custom metadata a PROPPATCH
 * stores and a later PROPFIND reads back.
 *
 * Deliberately **not** written next to the file on the USB drive. Two reasons:
 *
 *  1. A sidecar file next to every document shows up in the user's own file
 *     manager and in the directory listing this server returns, which is a
 *     surprising place to find server bookkeeping.
 *  2. FAT32/exFAT have no place to put it at all, and SAF documents are not
 *     guaranteed to have a writable sibling. Persisting to the app's private
 *     directory keeps the shared tree byte-for-byte what the user put there.
 *
 * The trade-off is that properties do not travel with the file when it is copied
 * off the device by other means — which is the same trade-off Windows makes with
 * its alternate data streams.
 *
 * Concurrency: every public method is `synchronized` on [lock]. PROPPATCH and
 * PROPFIND can be in flight on different Ktor worker threads at the same time,
 * and a `HashMap` read during a concurrent write is undefined behaviour.
 */
class DavPropertyStore {

    private val lock = Any()

    /** path (root-relative, "/" joined) -> property name -> value. */
    private val properties = HashMap<String, MutableMap<String, String>>()

    /**
     * Stores [value] for [name] on [path].
     *
     * [name] is the key built by [keyOf] — `{namespace-uri}local`. The namespace
     * is what makes two clients' `author` properties distinct, and dropping it
     * is how a store ends up returning one client's value to another.
     */
    fun set(path: String, name: String, value: String) = synchronized(lock) {
        properties.getOrPut(path) { LinkedHashMap() }[name] = value
    }

    /** Removes [name] from [path]. Returns true when it was there. */
    fun remove(path: String, name: String): Boolean = synchronized(lock) {
        properties[path]?.remove(name) != null
    }

    /** Every property set on [path], in insertion order. */
    fun all(path: String): Map<String, String> = synchronized(lock) {
        properties[path]?.toMap() ?: emptyMap()
    }

    /** The value for [name] on [path], or null. */
    fun get(path: String, name: String): String? = synchronized(lock) {
        properties[path]?.get(name)
    }

    /** Drops everything. Used when the storage root changes or the service stops. */
    fun clear() = synchronized(lock) { properties.clear() }

    /** Number of paths that carry at least one property — for tests and logs. */
    fun pathCount(): Int = synchronized(lock) { properties.size }

    companion object {
        /** The root-relative key for a normalised [segments] list. */
        fun keyOf(segments: List<String>): String =
            if (segments.isEmpty()) "/" else "/" + segments.joinToString("/")

        /**
         * The storage key for a property: `{namespace-uri}local`.
         *
         * The URI is the identity, because a prefix is only a per-document alias
         * — two clients both choose `Z` for unrelated namespaces, and keying on
         * `Z:author` would make them overwrite each other. RFC 4918 §4.4 says
         * the same: a dead property is named by its namespace and local part.
         *
         * An element with no namespace at all is stored under `{}local`, which
         * keeps it distinct from a property in the empty-namespace URI rather
         * than silently merging the two.
         */
        fun keyOf(name: WebDavXml.QualifiedName): String =
            "{${name.namespaceUri}}${name.local}"

        /** The local part of a key produced by [keyOf]. */
        fun localOf(key: String): String =
            if (key.startsWith("{") && key.contains("}")) key.substringAfter('}') else key

        /** The namespace URI of a key produced by [keyOf]; "" when it has none. */
        fun namespaceOf(key: String): String =
            if (key.startsWith("{") && key.contains("}")) key.substringAfter('{').substringBefore('}') else ""
    }
}
