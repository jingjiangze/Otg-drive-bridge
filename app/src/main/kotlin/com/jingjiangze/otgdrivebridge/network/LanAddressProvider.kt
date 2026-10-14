package com.jingjiangze.otgdrivebridge.network

/**
 * Supplies the phone's current LAN address.
 *
 * An interface rather than a concrete class so the transport probe can be
 * unit-tested without an Android device, and so the implementation can move to
 * the non-deprecated [android.net.ConnectivityManager] API without touching
 * callers.
 */
interface LanAddressProvider {

    /** The phone's current IPv4 address, or null when offline. */
    suspend fun currentAddress(): String?

    /** True when the phone is serving its own hotspot (a PC connects directly). */
    suspend fun isServingHotspot(): Boolean
}
