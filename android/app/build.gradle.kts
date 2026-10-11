plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "org.scmess.app"
    compileSdk = 36
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "org.scmess.app"
        minSdk = 26
        targetSdk = 36
        versionCode = 20
        versionName = "2.0"
    }

    // Release key comes from ~/.gradle/gradle.properties (SCMESS_STORE_FILE, SCMESS_STORE_PASSWORD,
    // SCMESS_KEY_ALIAS). Without it the build falls back to the debug key, and such an APK
    // cannot update one signed with the release key.
    val storeFile = providers.gradleProperty("SCMESS_STORE_FILE").orNull
    signingConfigs {
        if (storeFile != null) create("release") {
            this.storeFile = file(storeFile)
            storePassword = providers.gradleProperty("SCMESS_STORE_PASSWORD").get()
            keyAlias = providers.gradleProperty("SCMESS_KEY_ALIAS").get()
            keyPassword = storePassword
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging {
        resources.excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons)
    debugImplementation(libs.androidx.compose.ui.tooling)

    // Streaming AES-GCM: Android's provider buffers the whole input until doFinal().
    implementation(libs.bouncycastle.prov)

    testImplementation(libs.junit)
    // Real org.json for JVM tests (the android.jar copy is stubbed).
    testImplementation(libs.org.json)
}

// ./gradlew test -Pscmess.vectors=<dir> runs the Python interop test (see src/test/compat.py).
tasks.withType<Test>().configureEach {
    providers.gradleProperty("scmess.vectors").orNull?.let { systemProperty("scmess.vectors", it) }
}
