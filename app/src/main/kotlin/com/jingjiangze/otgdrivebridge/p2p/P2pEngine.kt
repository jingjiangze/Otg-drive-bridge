package com.jingjiangze.otgdrivebridge.p2p

/**
 * Seam to the openp2p engine.
 *
 * The engine ships as an AAR built by `.github/workflows/openp2p-aar.yml`. It is
 * **not** committed: it is ~15 MiB of native libraries, and a build artifact in
 * git rots faster than it helps. CI downloads the latest successful artifact
 * into `app/libs/`, and only then is `app/src/openp2p/java` added to the source
 * set — so the rest of the app has to compile without it.
 *
 * That is what this interface is for. Everything that links against the
 * generated `openp2p.*` classes lives behind it, and [P2pEngineFactory] loads
 * the implementation reflectively, returning null when this build has no AAR.
 * The UI then says so instead of silently offering a button that does nothing.
 */
interface P2pEngine {

    /**
     * Starts the engine and logs in.
     *
     * Blocking: the login waits for the gateway (up to the engine's timeout),
     * so callers must not invoke this on the main thread.
     *
     * @param baseDir a directory this app owns; the engine chdirs there and
     *   writes its config.json and log/ into it.
     * @param token the numeric openp2p token as a string — the engine parses it
     *   as uint64 and a malformed value fails the login with an opaque error.
     * @param shareBandwidthMbps 0 keeps the node private: it never relays other
     *   people's traffic (and cannot use public relay nodes either).
     * @return true when the login succeeded.
     */
    fun start(baseDir: String, token: String, shareBandwidthMbps: Int): Boolean

    /**
     * The node name the **server** assigned. The engine may rewrite the
     * configured name at login (`if len(rsp.Node) >= MinNodeNameLen {
     * gConf.setNode(rsp.Node) }`), so this is the only value a peer may use as
     * `-peernode`.
     */
    fun nodeName(): String?
}

/**
 * Loads the AAR-backed implementation without a compile-time dependency.
 *
 * Reflection is the price of shipping one APK that works with or without the
 * artifact. It runs once per screen creation, so the cost is irrelevant.
 */
object P2pEngineFactory {
    private const val IMPLEMENTATION = "com.jingjiangze.otgdrivebridge.p2p.OpenP2pEngine"

    fun create(): P2pEngine? = runCatching {
        Class.forName(IMPLEMENTATION).getDeclaredConstructor().newInstance() as P2pEngine
    }.getOrNull()
}
