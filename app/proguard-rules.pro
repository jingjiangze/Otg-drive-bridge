# Ktor / coroutines metadata
-dontwarn io.ktor.**
-dontwarn kotlinx.coroutines.**
-keep class io.ktor.** { *; }
-keep class kotlinx.coroutines.** { *; }

# Keep the WebDAV handler classes (dispatched by name from the router)
-keep class com.jingjiangze.otgdrivebridge.server.** { *; }
