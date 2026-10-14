package com.jingjiangze.otgdrivebridge.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Builds the ordered list of transports to show the user.
 *
 * Priority is fixed by the design in `docs/dual-transport-plan.md`:
 *  1. LAN (direct, free, fastest)
 *  2. Virtual LAN (tailnet / NetBird expose — 443 + valid certificate)
 *  3. Internet tunnel (Cloudflare named tunnel)
 *
 * The LAN card is always offered when an address exists; the Internet cards are
 * only listed when their tooling is actually available, so the user never sees
 * an option that cannot work. Internet exposure is **never started
 * automatically** — the user must opt in.
 */
class TransportProbeUseCase(
    private val lanAddressResolver: LanAddressProvider,
    private val exposures: List<InternetExposure>,
    private val localPort: Int,
    private val internetEnabled: Boolean
) {

    suspend fun probe(): TransportProbe = withContext(Dispatchers.IO) {
        val transports = ArrayList<Transport>()
        val lanAddress = lanAddressResolver.currentAddress()

        if (lanAddress != null) {
            val servingHotspot = lanAddressResolver.isServingHotspot()
            transports += Transport(
                kind = TransportKind.LAN,
                label = "局域网",
                url = "http://$lanAddress:$localPort/",
                https = false,
                priority = PRIORITY_LAN,
                detail = if (servingHotspot) {
                    "手机热点：电脑直接连接此 Wi-Fi"
                } else {
                    "电脑与手机在同一 Wi-Fi"
                },
                warning = "未加密：同网段设备可嗅探流量。请使用 Digest 凭据，不要在公共 Wi-Fi 上启用写入。"
            )
        }

        if (internetEnabled) {
            for (exposure in exposures.sortedBy { it.priorityRank() }) {
                val available = runCatching { exposure.isAvailable() }.getOrDefault(false)
                if (!available) continue
                // start() already returns Result; flatten it (and tolerate a
                // thrown exception) so `endpoint` is a PublicEndpoint rather
                // than a nested Result.
                val endpoint = runCatching { exposure.start(localPort).getOrThrow() }.getOrNull()
                if (endpoint == null) continue
                transports += Transport(
                    kind = if (exposure.id == "netbird-expose") TransportKind.VIRTUAL_LAN else TransportKind.TUNNEL,
                    label = when (exposure.id) {
                        "netbird-expose" -> "虚拟局域网（NetBird）"
                        else -> "互联网隧道（Cloudflare）"
                    },
                    url = endpoint.mountUrl,
                    https = endpoint.https,
                    priority = when (exposure.id) {
                        "netbird-expose" -> PRIORITY_VIRTUAL_LAN
                        else -> PRIORITY_TUNNEL
                    },
                    detail = endpoint.notes,
                    warning = if (exposure.id == "cloudflare-tunnel") {
                        "免费档单次上传上限 100 MB；更大文件请改用 frp + Caddy。"
                    } else null
                )
            }
        }

        TransportProbe(
            transports = transports.sortedBy { it.priority },
            lanAddress = lanAddress,
            checkedAtMillis = System.currentTimeMillis()
        )
    }

    private fun InternetExposure.priorityRank(): Int = when (id) {
        "netbird-expose" -> 0
        else -> 1
    }

    companion object {
        const val PRIORITY_LAN = 0
        const val PRIORITY_VIRTUAL_LAN = 1
        const val PRIORITY_TUNNEL = 2
    }
}
