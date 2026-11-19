import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Signing key and node table come from the private bundle, never the repo.
val privateDir = System.getenv("ARC_PRIVATE") ?: (System.getProperty("user.home") + "/arc-private")
val keysDir = System.getenv("ARC_KEYS") ?: "$privateDir/keys"
val keystoreProps = file("$keysDir/keystore.properties")
// build.sh copies the node table here (gitignored) before packaging.
val generatedAssets: File = layout.buildDirectory.dir("generated/arc/assets").get().asFile

tasks.matching { it.name == "assembleRelease" || it.name == "packageRelease" }.configureEach {
    doFirst {
        require(keystoreProps.exists()) { "missing $keysDir/keystore.properties" }
        require(generatedAssets.resolve("nodes.json").isFile) {
            "missing build/generated/arc/assets/nodes.json: build with ~/arc/build.sh"
        }
    }
}

android {
    packaging {

        jniLibs { useLegacyPackaging = false }
        resources {

            excludes += setOf(
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE",
                "META-INF/LICENSE.txt",
                "META-INF/NOTICE",
                "META-INF/NOTICE.txt",
                "META-INF/*.kotlin_module",
                "META-INF/*.version",
                "META-INF/androidx/**",
                "DebugProbesKt.bin",
                "kotlin-tooling-metadata.json",
                "kotlin/**",
            )
        }
    }

    androidResources {
        localeFilters += listOf("zh")
    }
    namespace = "com.arc.app"
    ndkVersion = "30.0.16248370"
    buildToolsVersion = "37.0.0"

    compileSdk {
        version = release(37) {
            minorApiLevel = 2
        }
    }

    defaultConfig {
        applicationId = "com.arc.app"
        minSdk = 37
        targetSdk = 37
        ndk { abiFilters += listOf("arm64-v8a") }
        versionCode = 162
        versionName = "16.2"
    }

    signingConfigs {
        create("release") {
            // Read only when present so debug builds, tests and IDE sync work
            // without keys; assembleRelease fails below if they are missing.
            if (keystoreProps.exists()) {
                val props = Properties()
                keystoreProps.inputStream().use { props.load(it) }
                storeFile = File(keysDir).resolve(props.getProperty("storeFile"))
                storePassword = props.getProperty("storePassword")
                keyAlias = props.getProperty("keyAlias")
                keyPassword = props.getProperty("keyPassword")
            }
        }
    }

    sourceSets {
        getByName("main") { assets.srcDir(generatedAssets) }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            signingConfig = signingConfigs.getByName("release")
            vcsInfo {
                include = false
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_27
        targetCompatibility = JavaVersion.VERSION_27
    }
    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_27)
        }
    }
    buildFeatures {
        compose = true
    }
}

configurations.configureEach {
    exclude(group = "androidx.compose.material", module = "material-icons-core")
}

dependencies {
    implementation(platform("androidx.compose:compose-bom-beta:2026.11.00"))
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.animation:animation")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.datastore:datastore-preferences:1.3.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814")
}
