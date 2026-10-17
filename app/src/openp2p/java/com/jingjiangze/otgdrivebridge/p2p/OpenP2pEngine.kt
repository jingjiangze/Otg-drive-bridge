package com.jingjiangze.otgdrivebridge.p2p

import openp2p.Openp2p
import openp2p.P2PNetwork

/**
 * The AAR-backed implementation.
 *
 * This file lives in `app/src/openp2p/java`, which `app/build.gradle.kts` only
 * adds to the source set when `app/libs/openp2p.aar` exists — that is why the
 * main source set can reference [P2pEngine] but not `openp2p.*` directly.
 *
 * Two engine behaviours worth knowing:
 *
 *  - `runAsModule` returns immediately; the login happens in
 *    `P2PNetwork.connect(timeoutMs)`. The upstream app calls it with 30000 and
 *    keeps re-calling it, which is what keeps the session alive.
 *  - `Openp2p.stop()` is implemented as `os.Exit(0)`. It is deliberately never
 *    called here: stopping the node would kill the whole app process. The
 *    node's lifetime is the process lifetime.
 */
class OpenP2pEngine : P2pEngine {

    private var network: P2PNetwork? = null

    override fun start(baseDir: String, token: String, shareBandwidthMbps: Int): Boolean {
        if (token.isBlank()) return false
        return runCatching {
            // gomobile maps Go `int` to Java `long` (Go int is 64-bit on
            // android/arm64) — verified by the compiler, not guessed: passing
            // Ints here fails with "actual type is 'kotlin.Int', but
            // 'kotlin.Long' was expected". Upstream's literal call
            // `runAsModule(dir, token, 0, 1)` works because Kotlin types the
            // literals contextually; we pass values, so they need explicit
            // Longs.
            val net = Openp2p.runAsModule(baseDir, token, shareBandwidthMbps.toLong(), 1L)
            network = net
            net.connect(LOGIN_TIMEOUT_MS)
        }.getOrDefault(false)
    }

    override fun nodeName(): String? = runCatching {
        Openp2p.getAndroidNodeName()
    }.getOrNull()?.takeIf { it.isNotBlank() && it != "unknown" }

    private companion object {
        const val LOGIN_TIMEOUT_MS = 30_000L
    }
}
