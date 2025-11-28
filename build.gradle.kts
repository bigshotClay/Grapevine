plugins {
    kotlin("jvm") version "2.1.0" apply false
    kotlin("plugin.serialization") version "2.1.0" apply false
    kotlin("plugin.compose") version "2.1.0" apply false
    id("org.jetbrains.compose") version "1.7.1" apply false
    id("app.cash.sqldelight") version "2.0.1" apply false
    id("org.jetbrains.kotlinx.kover") version "0.8.3" apply false
}

allprojects {
    group = "io.grapevine"
    version = "0.1.0-SNAPSHOT"
}

subprojects {
    tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
        kotlinOptions {
            jvmTarget = "17"
            freeCompilerArgs = listOf("-Xjvm-default=all")
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        sourceCompatibility = "17"
        targetCompatibility = "17"
    }
}
