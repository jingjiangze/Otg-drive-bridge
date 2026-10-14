// Top-level build file — plugin versions are declared here and applied in :app.
plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    // The Compose Compiler Gradle plugin exists only from Kotlin 2.0.0 onward.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}
