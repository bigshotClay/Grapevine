plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.sqldelight)
    id("org.jetbrains.kotlinx.kover")
}

sqldelight {
    databases {
        create("GrapevineDatabase") {
            packageName.set("io.grapevine.storage.db")
        }
    }
}

dependencies {
    implementation(project(":core"))

    implementation(libs.kotlin.stdlib)
    implementation(libs.bundles.coroutines)
    implementation(libs.bundles.serialization)
    implementation(libs.sqldelight.driver)
    implementation(libs.sqldelight.coroutines)
    implementation(libs.bundles.logging)

    testImplementation(libs.bundles.testing)
}

tasks.test {
    useJUnitPlatform()
}
