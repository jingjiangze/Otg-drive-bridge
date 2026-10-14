package com.jingjiangze.otgdrivebridge.storage

import android.os.Build
import android.os.Environment

/**
 * Whether the app holds "all files access" (`MANAGE_EXTERNAL_STORAGE`).
 *
 * [Environment.isExternalStorageManager] only exists from API 30, while this
 * app supports API 24. On older releases the permission does not exist at all,
 * so this reports `false` and callers fall back to a direct read/write probe on
 * the path — which is the only check available there anyway.
 *
 * Keeping the version test inside one function is what lets the callers stay
 * lint-clean: `NewApi` is an error-severity check, so an unguarded call would
 * fail `lintDebug`.
 */
internal fun hasAllFilesAccess(): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && Environment.isExternalStorageManager()
