plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    implementation(project(":core"))

    implementation(libs.kotlin.stdlib)
    implementation(libs.bundles.coroutines)
    implementation(libs.bundles.serialization)
    implementation(libs.ipv8)
    implementation(libs.ipv8.jvm)
    implementation(libs.sqldelight.driver)
    implementation(libs.bundles.logging)

    testImplementation(libs.bundles.testing)
}

tasks.test {
    useJUnitPlatform()
}
