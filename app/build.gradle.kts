plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// The openp2p engine AAR is a build artifact (~15 MiB of native libraries), not
// a source file: CI downloads the latest successful `openp2p-aar` artifact into
// app/libs/ before assembling. When it is absent the app still builds — the P2P
// card then reports that this build has no engine (see p2p/P2pEngine.kt).
val openP2pAar: File = file("libs/openp2p.aar")

android {
    namespace = "com.jingjiangze.otgdrivebridge"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.jingjiangze.otgdrivebridge"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        vectorDrawables { useSupportLibrary = true }

        // Phone APKs: ship only 64-bit ARM. Emulators can add -PincludeX86=true.
        ndk {
            val abis = mutableListOf("arm64-v8a")
            if (project.findProperty("includeX86") == "true") abis += listOf("x86_64")
            abiFilters.clear()
            abiFilters.addAll(abis)
        }
    }

    signingConfigs {
        create("release") {
            val keystorePath = System.getenv("KEYSTORE_PATH")
            if (keystorePath != null && file(keystorePath).exists()) {
                storeFile = file(keystorePath)
                storePassword = System.getenv("KEYSTORE_PASS")
                keyAlias = System.getenv("KEY_ALIAS")
                keyPassword = System.getenv("KEY_PASS")
            }
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val keystorePath = System.getenv("KEYSTORE_PATH")
            if (keystorePath != null && file(keystorePath).exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        // The protocol layer deliberately uses java.time and java.util.Base64
        // instead of their android.* counterparts so it stays testable on a
        // plain JVM. Both landed in API 26 while minSdk is 24, so the calls get
        // rewritten to the desugar library; without this, lint's error-severity
        // NewApi check fails the build.
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs = freeCompilerArgs + listOf(
            "-opt-in=kotlin.RequiresOptIn",
            "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
            "-opt-in=androidx.compose.foundation.ExperimentalFoundationApi",
            "-opt-in=androidx.compose.animation.ExperimentalAnimationApi"
        )
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
            // Only compiled when the AAR is present; see p2p/P2pEngine.kt.
            if (openP2pAar.exists()) java.srcDirs("src/openp2p/java")
        }
        getByName("test") { java.srcDirs("src/test/kotlin") }
    }

    testOptions {
        unitTests.all {
            it.useJUnitPlatform()
        }
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/INDEX.LIST",
                "/META-INF/DEPENDENCIES",
                "META-INF/*.kotlin_module",
                "DebugProbesKt.bin",
                "kotlin-tooling-metadata.json"
            )
        }
    }
}

dependencies {
    // Rewrites java.time / java.util.Base64 (API 26) down to minSdk 24.
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.0.4")

    // openp2p engine (optional): only when CI downloaded the AAR. `files()`
    // does not go through repository resolution, so FAIL_ON_PROJECT_REPOS in
    // settings.gradle.kts does not apply.
    if (openP2pAar.exists()) implementation(files(openP2pAar))

    // Ktor server — CIO engine only (smallest server stack)
    implementation("io.ktor:ktor-server-core:2.3.12")
    implementation("io.ktor:ktor-server-cio:2.3.12")

    // Jetpack Compose
    implementation(platform("androidx.compose:compose-bom:2024.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.navigation:navigation-compose:2.8.1")
    implementation("androidx.datastore:datastore-preferences:1.1.1")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.5")
    implementation("androidx.lifecycle:lifecycle-service:2.8.5")
    implementation("androidx.documentfile:documentfile:1.0.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // Unit tests
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    testImplementation("io.ktor:ktor-server-test-host:2.3.12")
    testImplementation("io.ktor:ktor-client-core:2.3.12")
    testImplementation("io.ktor:ktor-client-cio:2.3.12")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.10.2")
}
