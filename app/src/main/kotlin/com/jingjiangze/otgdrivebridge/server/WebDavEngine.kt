package com.jingjiangze.otgdrivebridge.server

import com.jingjiangze.otgdrivebridge.security.DigestAuthenticator
import com.jingjiangze.otgdrivebridge.webdav.DavStorage
import com.jingjiangze.otgdrivebridge.webdav.LockManager
import io.ktor.server.application.Application
// `handle { }` is a member of Route, but the `call` property its lambda sees is
// this extension on PipelineContext, so it has to be imported explicitly.
import io.ktor.server.application.call
import io.ktor.server.application.install
import io.ktor.server.cio.CIO
import io.ktor.server.engine.ApplicationEngine
import io.ktor.server.engine.embeddedServer
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Snapshot of the server's runtime state, observed by the UI. */
data class ServerState(
    val isRunning: Boolean = false,
    val port: Int = WebDavEngine.DEFAULT_PORT,
    val bindAddress: String = WebDavEngine.BIND_ALL_INTERFACES,
    val lanAddress: String? = null,
    val startedAtMillis: Long = 0L,
    val lastError: String? = null
) {
    val displayAddress: String
        get() = lanAddress?.let { "http://$it:$port/" } ?: "Not connected"
}

/**
 * Owns the Ktor CIO server and the [WebDavRequestHandler].
 *
 * The engine is deliberately Android-framework-free: it takes a [DavStorage]
 * and a credential provider, so it can be driven from a JVM test or from the
 * Android foreground service without changes.
 */
class WebDavEngine(
    private val storageProvider: () -> DavStorage?,
    private val credentialProvider: () -> DigestAuthenticator.Credentials?,
    private val realm: String = DigestAuthenticator.DEFAULT_REALM
) {

    private val authenticator = DigestAuthenticator(realm)
    private val lockManager = LockManager()

    private var engine: ApplicationEngine? = null
    private var handler: WebDavRequestHandler? = null

    private val _state = MutableStateFlow(ServerState())
    val state: StateFlow<ServerState> = _state.asStateFlow()

    /** Called for every completed request (method, path, user, status). */
    var onRequestLogged: ((String, String, String, Int) -> Unit)? = null

    @Synchronized
    fun start(port: Int = DEFAULT_PORT, lanAddress: String? = null): Result<Unit> {
        if (engine != null) return Result.success(Unit)
        val storage = storageProvider() ?: return Result.failure(
            IllegalStateException("Shared root is not available")
        )
        return runCatching {
            val requestHandler = WebDavRequestHandler(
                storage = storage,
                authenticator = authenticator,
                lockManager = lockManager
            ).also {
                it.credentialProvider = credentialProvider
                it.onCompleted = { m, p, u, s -> onRequestLogged?.invoke(m, p, u, s) }
            }
            val application = embeddedServer(CIO, port = port, host = BIND_ALL_INTERFACES) {
                configureModule(requestHandler)
            }
            application.start(wait = false)
            engine = application
            handler = requestHandler
            _state.value = ServerState(
                isRunning = true,
                port = port,
                bindAddress = BIND_ALL_INTERFACES,
                lanAddress = lanAddress,
                startedAtMillis = System.currentTimeMillis()
            )
        }.onFailure { t ->
            _state.value = _state.value.copy(isRunning = false, lastError = t.message)
        }
    }

    @Synchronized
    fun stop() {
        runCatching { engine?.stop(500, 1000) }
        engine = null
        handler = null
        lockManager.clear()
        _state.value = _state.value.copy(isRunning = false, lanAddress = null)
    }

    @Synchronized
    fun refreshAddress(lanAddress: String?) {
        if (_state.value.isRunning) {
            _state.value = _state.value.copy(lanAddress = lanAddress)
        }
    }

    val isRunning: Boolean get() = engine != null

    private fun Application.configureModule(requestHandler: WebDavRequestHandler) {
        routing {
            // One catch-all route with no method selector: every verb reaches the
            // handler, which dispatches internally and answers 405 for anything
            // it does not implement. Registering the methods one by one meant an
            // unknown verb (TRACE, REPORT, …) never matched a route at all and
            // Ktor answered 404, which tells a WebDAV client the resource is
            // missing rather than the method unsupported.
            route("/{...}") {
                handle { requestHandler.handle(call) }
            }
        }
    }

    companion object {
        const val DEFAULT_PORT = 8080
        const val BIND_ALL_INTERFACES = "0.0.0.0"
    }
}
