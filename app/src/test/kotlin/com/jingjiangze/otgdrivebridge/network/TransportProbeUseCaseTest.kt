package com.jingjiangze.otgdrivebridge.network

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Transport selection must follow the documented priority and must never offer
 * a card whose tooling is absent.
 */
class TransportProbeUseCaseTest {

    private class FakeLanAddress(private val address: String?) : LanAddressProvider {
        override suspend fun currentAddress(): String? = address
        override suspend fun isServingHotspot(): Boolean = false
    }

    private class FakeExposure(
        override val id: String,
        private val available: Boolean,
        private val url: String? = null
    ) : InternetExposure {
        override suspend fun isAvailable(): Boolean = available
        override suspend fun start(localPort: Int): Result<PublicEndpoint> =
            if (url == null) Result.failure(ExposureUnavailableException("no url"))
            else Result.success(PublicEndpoint(url = url, https = url.startsWith("https://")))
        override suspend fun stop() = Unit
        override val isActive: Boolean = false
    }

    private class FakeRunner(
        private val version: String = "netbird version 0.99.0",
        private val exposeOutput: String = "URL: https://myapp-a1b2c3.proxy.example.com"
    ) : ProcessRunner {
        override suspend fun run(command: List<String>, env: Map<String, String>): ProcessResult =
            when {
                command.contains("version") -> ProcessResult(0, version, "")
                command.contains("expose") -> ProcessResult(0, exposeOutput, "")
                else -> ProcessResult(0, "", "")
            }
    }

    @Test
    fun `lan card is offered first when an address exists`() = runBlocking {
        val useCase = TransportProbeUseCase(
            lanAddressResolver = FakeLanAddress("192.168.43.1"),
            exposures = emptyList(),
            localPort = 8080,
            internetEnabled = false
        )
        val probe = useCase.probe()
        assertEquals(1, probe.transports.size)
        val lan = probe.transports.first()
        assertEquals(TransportKind.LAN, lan.kind)
        assertEquals("http://192.168.43.1:8080/", lan.url)
        assertFalse(lan.https)
        assertNotNull(lan.warning, "plain HTTP must carry an encryption warning")
        assertEquals("192.168.43.1", probe.lanAddress)
    }

    @Test
    fun `no lan card when offline`() = runBlocking {
        val useCase = TransportProbeUseCase(
            FakeLanAddress(null), emptyList(), 8080, internetEnabled = false
        )
        assertTrue(useCase.probe().transports.isEmpty())
        assertNull(useCase.probe().preferred)
    }

    @Test
    fun `internet exposure is not started unless the user enabled it`() = runBlocking {
        val useCase = TransportProbeUseCase(
            FakeLanAddress("10.0.0.5"),
            listOf(FakeExposure("netbird-expose", available = true, url = "https://x.proxy.example.com")),
            localPort = 8080,
            internetEnabled = false
        )
        assertEquals(1, useCase.probe().transports.size)
        assertEquals(TransportKind.LAN, useCase.probe().transports.single().kind)
    }

    @Test
    fun `virtual lan sorts above tunnel and both above nothing`() = runBlocking {
        val useCase = TransportProbeUseCase(
            FakeLanAddress("10.0.0.5"),
            listOf(
                FakeExposure("cloudflare-tunnel", available = true, url = "https://drive.example.com/"),
                FakeExposure("netbird-expose", available = true, url = "https://myapp.proxy.example.com")
            ),
            localPort = 8080,
            internetEnabled = true
        )
        val kinds = useCase.probe().transports.map { it.kind }
        assertEquals(
            listOf(TransportKind.LAN, TransportKind.VIRTUAL_LAN, TransportKind.TUNNEL),
            kinds
        )
    }

    @Test
    fun `unavailable tooling produces no card`() = runBlocking {
        val useCase = TransportProbeUseCase(
            FakeLanAddress("10.0.0.5"),
            listOf(FakeExposure("netbird-expose", available = false)),
            localPort = 8080,
            internetEnabled = true
        )
        assertEquals(1, useCase.probe().transports.size)
    }

    @Test
    fun `tunnel card carries the free tier size warning`() = runBlocking {
        val useCase = TransportProbeUseCase(
            FakeLanAddress("10.0.0.5"),
            listOf(FakeExposure("cloudflare-tunnel", available = true, url = "https://drive.example.com/")),
            localPort = 8080,
            internetEnabled = true
        )
        val tunnel = useCase.probe().transports.last()
        assertEquals(TransportKind.TUNNEL, tunnel.kind)
        assertTrue(tunnel.warning!!.contains("100 MB"))
    }
}

class NetBirdExposureTest {

    @Test
    fun `parses the https url out of netbird output`() {
        val exposure = NetBirdExposure(FakeRunner())
        assertEquals(
            "https://myapp-a1b2c3.proxy.example.com",
            exposure.parsePublicUrl("Starting exposure\nURL: https://myapp-a1b2c3.proxy.example.com\n")
        )
    }

    @Test
    fun `returns null when netbird printed no url`() {
        val exposure = NetBirdExposure(FakeRunner(exposeOutput = "peer not connected"))
        assertNull(exposure.parsePublicUrl("peer not connected"))
    }

    @Test
    fun `start fails when the command fails`() = runBlocking {
        val exposure = NetBirdExposure(object : ProcessRunner {
            override suspend fun run(command: List<String>, env: Map<String, String>) =
                ProcessResult(1, "", "netbird: peer not found")
        })
        val result = exposure.start(8080)
        assertTrue(result.isFailure)
        assertFalse(exposure.isActive)
    }

    @Test
    fun `isAvailable requires the version string`() = runBlocking {
        val present = NetBirdExposure(object : ProcessRunner {
            override suspend fun run(command: List<String>, env: Map<String, String>) =
                ProcessResult(0, "netbird version 0.99.0", "")
        })
        assertTrue(present.isAvailable())

        val absent = NetBirdExposure(object : ProcessRunner {
            override suspend fun run(command: List<String>, env: Map<String, String>) =
                ProcessResult(127, "", "command not found")
        })
        assertFalse(absent.isAvailable())
    }
}

class PublicEndpointTest {

    @Test
    fun `mount url always ends with a slash`() {
        assertEquals("https://drive.example.com/", PublicEndpoint("https://drive.example.com").mountUrl)
        assertEquals("https://drive.example.com/", PublicEndpoint("https://drive.example.com/").mountUrl)
    }
}
