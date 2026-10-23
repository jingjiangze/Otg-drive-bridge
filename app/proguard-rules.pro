# Ktor / coroutines metadata
-dontwarn io.ktor.**
-dontwarn kotlinx.coroutines.**
-keep class io.ktor.** { *; }
-keep class kotlinx.coroutines.** { *; }

# Ktor pulls slf4j-api, whose 1.x binder lookup references a binding class
# that is deliberately not shipped. Only the minified release build runs R8,
# so this never surfaced in the debug-only CI builds.
-dontwarn org.slf4j.**

# Keep the WebDAV handler classes (dispatched by name from the router)
-keep class com.jingjiangze.otgdrivebridge.server.** { *; }
