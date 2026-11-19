// Pin AGP's built-in Kotlin Gradle plugin to the same compiler as the Compose plugin.
buildscript {
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.5.0-RC")
    }
}

plugins {
    id("com.android.application") version "9.6.0-alpha04" apply false

    id("org.jetbrains.kotlin.plugin.compose") version "2.5.0-RC" apply false
}
