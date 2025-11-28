plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    id("org.jetbrains.kotlinx.kover")
}

dependencies {
    implementation(libs.kotlin.stdlib)
    implementation(libs.bundles.coroutines)
    implementation(libs.bundles.serialization)
    implementation(libs.bundles.crypto)
    implementation(libs.bundles.logging)

    testImplementation(libs.bundles.testing)
}

tasks.test {
    useJUnitPlatform()
}

kover {
    reports {
        verify {
            rule {
                minBound(80)
            }
        }
    }
}
