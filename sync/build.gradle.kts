plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    implementation(project(":core"))
    implementation(project(":network"))
    implementation(project(":storage"))

    implementation(libs.kotlin.stdlib)
    implementation(libs.bundles.coroutines)
    implementation(libs.bundles.serialization)
    implementation(libs.bundles.logging)

    testImplementation(libs.bundles.testing)
}

tasks.test {
    useJUnitPlatform()
}
