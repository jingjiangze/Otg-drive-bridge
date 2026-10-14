package com.jingjiangze.otgdrivebridge

import android.app.Application

/**
 * Application entry point.
 *
 * Holds the singleton the storage layer reads preferences through. Everything
 * else — the shared root, the credentials — lives in
 * `storage/StorageRootRepository`.
 */
class OtgDriveBridgeApp : Application() {
    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    companion object {
        @Volatile
        lateinit var instance: OtgDriveBridgeApp
            private set
    }
}
