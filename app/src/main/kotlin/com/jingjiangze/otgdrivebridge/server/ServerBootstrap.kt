package com.jingjiangze.otgdrivebridge.server

import com.jingjiangze.otgdrivebridge.security.DigestAuthenticator
import com.jingjiangze.otgdrivebridge.webdav.DavStorage
import com.jingjiangze.otgdrivebridge.webdav.LockManager
import io.ktor.server.application.Application
import io.ktor.server.application.call
import io.ktor.server.cio.CIO
import io.ktor.server.engine.ApplicationEngine
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.route
import io.ktor.server.routing.routing

/**
 * The single place where the WebDAV server is assembled and started.
 *
 * It exists so the Android service, the JVM end-to-end tests and the
 * cross-language interop harness (which runs a Go client against this server)
 * all go through **one** assembly. When each caller wired its own
 * `embeddedServer { routing { ... } }` block, any routing change had to be made
 * in several places at once — and the places silently drifted, which shows up
 * as differences that look like protocol bugs but are only assembly bugs.
 */
object ServerBootstrap {

    /** A started server plus the handler that owns its request processing. */
    class StartedServer(
        val engine: ApplicationEngine,
        val handler: WebDavRequestHandler
    ) : AutoCloseable {
        override fun close() {
            runCatching { engine.stop(500, 1000) }
        }
    }

    /**
     * Starts a WebDAV server on [port] serving [storage].
     *
     * @param host interface to bind; `0.0.0.0` for the Android service, a
     *   loopback address for tests and the interop harness.
     * @param authenticator / [lockManager] are injectable so a caller can share
     *   one instance across restarts (the Android engine does) or hand in a
     *   fresh pair (a test does).
     * @param onCompleted receives (method, path, user, status) per request.
     */
    fun start(
        port: Int,
        storage: DavStorage,
        credentialProvider: (origin: String) -> List<DigestAuthenticator.Credentials>,
        host: String = "0.0.0.0",
        authenticator: DigestAuthenticator = DigestAuthenticator(),
        lockManager: LockManager = LockManager(),
        onCompleted: (String, String, String, Int) -> Unit = { _, _, _, _ -> }
    ): StartedServer {
        val handler = WebDavRequestHandler(
            storage = storage,
            authenticator = authenticator,
            lockManager = lockManager
        ).apply {
            this.credentialProvider = credentialProvider
            this.onCompleted = onCompleted
        }
        val engine = embeddedServer(CIO, port = port, host = host) {
            configureModule(handler)
        }
        engine.start(wait = false)
        return StartedServer(engine, handler)
    }

    /**
     * The routing, shared by every caller.
     *
     * One catch-all route with no method selector: every verb reaches the
     * handler, which dispatches internally and answers 405 for anything it does
     * not implement. Registering the methods one by one meant an unknown verb
     * (TRACE, REPORT, …) never matched a route at all and Ktor answered 404,
     * which tells a WebDAV client the resource is missing rather than the
     * method unsupported.
     */
    fun Application.configureModule(handler: WebDavRequestHandler) {
        routing {
            route("/{...}") {
                handle { handler.handle(call) }
            }
        }
    }
}
