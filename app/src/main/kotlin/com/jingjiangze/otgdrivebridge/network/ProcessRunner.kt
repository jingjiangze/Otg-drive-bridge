package com.jingjiangze.otgdrivebridge.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * A process-bridge runner: executes a CLI and reports its output.
 *
 * Declared as an interface so tests can supply a fake without spawning
 * processes, and so the Android build can bind it to `Runtime.exec` while a
 * future build could use a different mechanism.
 */
interface ProcessRunner {
    /**
     * Runs [command] and returns (exitCode, stdout, stderr).
     * Implementations must not block the caller's thread indefinitely.
     */
    suspend fun run(command: List<String>, env: Map<String, String> = emptyMap()): ProcessResult
}

data class ProcessResult(val exitCode: Int, val stdout: String, val stderr: String) {
    val ok: Boolean get() = exitCode == 0
}

/** [ProcessRunner] backed by `java.lang.ProcessBuilder`. */
class SystemProcessRunner : ProcessRunner {
    override suspend fun run(command: List<String>, env: Map<String, String>): ProcessResult =
        withContext(Dispatchers.IO) {
            runCatching {
                val builder = ProcessBuilder(command)
                if (env.isNotEmpty()) builder.environment().putAll(env)
                builder.redirectErrorStream(false)
                val process = builder.start()
                val stdout = process.inputStream.bufferedReader().use { it.readText() }
                val stderr = process.errorStream.bufferedReader().use { it.readText() }
                val code = process.waitFor()
                ProcessResult(code, stdout, stderr)
            }.getOrElse { t ->
                ProcessResult(-1, "", t.message ?: "failed to start process")
            }
        }
}
