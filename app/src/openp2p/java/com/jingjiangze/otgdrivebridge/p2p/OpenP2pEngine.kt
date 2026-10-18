package com.jingjiangze.otgdrivebridge.p2p

import openp2p.Openp2p

/**
 * The AAR-backed implementation.
 *
 * This file lives in `app/src/openp2p/java`, which `app/build.gradle.kts` only
 * adds to the source set when `app/libs/openp2p.aar` exists — that is why the
 * main source set can reference [P2pEngine] but not `openp2p.*` directly.
 *
 * Two engine behaviours worth knowing:
 *
 *  - `runAsModule` logs in once and returns; the session then needs a periodic
 *    `connect()` heartbeat to stay alive. Upstream's own service does exactly
 *    that (`OpenP2PService.kt:128-131`: `do { sleep(1000) } while
 *    (network.connect(30000) && running)`), so [start] reproduces the loop on
 *    a daemon thread. Without it the login goes stale and the phone stops
 *    accepting tunnels after a while.
 *  - `Openp2p.stop()` is implemented as `os.Exit(0)`. It is deliberately never
 *    called here: stopping the node would kill the whole app process. The
 *    node's lifetime is the process lifetime; the heartbeat thread just stops
 *    re-connecting when [shutdown] is called.
 */
class OpenP2pEngine : P2pEngine {

    @Volatile private var running = false

    override fun start(baseDir: String, token: String, shareBandwidthMbps: Int): Boolean {
        if (token.isBlank()) return false
        if (running) return true
        val net = runCatching {
            // gomobile maps Go `int` to Java `long` (Go int is 64-bit on
            // android/arm64) — verified by the compiler, not guessed: passing
            // Ints here fails with "actual type is 'kotlin.Int', but
            // 'kotlin.Long' was expected". Upstream's literal call
            // `runAsModule(dir, token, 0, 1)` works because Kotlin types the
            // literals contextually; we pass values, so they need explicit
            // Longs.
            Openp2p.runAsModule(baseDir, token, shareBandwidthMbps.toLong(), 1L)
        }.getOrNull() ?: return false
        if (!runCatching { net.connect(LOGIN_TIMEOUT_MS) }.getOrDefault(false)) return false

        running = true
        Thread {
            // Heartbeat: each connect() blocks until the next heartbeat window
            // and returns false when the session is lost; sleep-and-relogin
            // mirrors upstream. The loop exits when [stop] clears [running] or
            // when a connect reports the network gone and the re-attempt also
            // fails (token/server could change while we sleep, so keep
            // re-trying until told to stop).
            while (running) {
                val ok = runCatching { net.connect(LOGIN_TIMEOUT_MS) }.getOrDefault(false)
                if (!ok) {
                    Thread.sleep(1000)
                }
            }
        }.apply { isDaemon = true; name = "openp2p-heartbeat" }.start()
        return true
    }

    /**
     * Stops the heartbeat (the node itself cannot be un-loaded: `Openp2p.stop()`
     * is os.Exit). Callers use this to keep the UI from showing a live session
     * the app has given up on.
     */
    fun stopHeartbeat() {
        running = false
    }

    override fun nodeName(): String? = runCatching {
        Openp2p.getAndroidNodeName()
    }.getOrNull()?.takeIf { it.isNotBlank() && it != "unknown" }

    private companion object {
        const val LOGIN_TIMEOUT_MS = 30_000L
    }
}
