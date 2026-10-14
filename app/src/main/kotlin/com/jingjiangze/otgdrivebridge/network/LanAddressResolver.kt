package com.jingjiangze.otgdrivebridge.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import java.net.Inet4Address
import java.net.NetworkInterface
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * LAN address discovery.
 *
 * Uses [ConnectivityManager] + [NetworkInterface] rather than the deprecated
 * `WifiManager.getConnectionInfo()`: that API returns a stale address after a
 * network switch, which produced wrong URLs in existing apps. Only IPv4 is
 * reported — a mapped drive cannot reliably use a link-local IPv6 address.
 *
 * Phone hotspots hand out `192.168.43.1`/`192.168.49.1` to the phone itself, so
 * a PC connected to the phone's hotspot sees the phone on that address.
 */
class LanAddressResolver(private val context: Context) : LanAddressProvider {

    override suspend fun currentAddress(): String? = withContext(Dispatchers.IO) {
        activeNetworkAddress() ?: fallbackInterfaceAddress()
    }

    override suspend fun isServingHotspot(): Boolean = withContext(Dispatchers.IO) {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return@withContext false
        val network: Network = cm.activeNetwork ?: return@withContext false
        val caps = cm.getNetworkCapabilities(network) ?: return@withContext false
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            cm.getLinkProperties(network)?.interfaceName?.startsWith("ap") == true
    }

    private fun activeNetworkAddress(): String? {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
        val network: Network = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(network) ?: return null
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return null
        val props: LinkProperties = cm.getLinkProperties(network) ?: return null
        return props.linkAddresses
            .map { it.address }
            .firstOrNull { it is Inet4Address && !it.isLoopbackAddress }
            ?.hostAddress
    }

    private fun fallbackInterfaceAddress(): String? = runCatching {
        NetworkInterface.getNetworkInterfaces().asSequence()
            .filter { it.isUp && !it.isLoopback }
            .flatMap { it.inetAddresses.asSequence() }
            .filterIsInstance<Inet4Address>()
            .firstOrNull { !it.isLoopbackAddress && it.hostAddress?.contains(':') == false }
            ?.hostAddress
    }.getOrNull()
}
