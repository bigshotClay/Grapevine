plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.compose)
}

dependencies {
    implementation(project(":core"))
    implementation(project(":network"))
    implementation(project(":storage"))
    implementation(project(":sync"))
    implementation(project(":ui"))

    implementation(libs.kotlin.stdlib)
    implementation(libs.bundles.coroutines)
    implementation(libs.bundles.logging)

    implementation(compose.desktop.currentOs)

    testImplementation(libs.bundles.testing)
}

compose.desktop {
    application {
        mainClass = "io.grapevine.app.MainKt"

        nativeDistributions {
            targetFormats(
                org.jetbrains.compose.desktop.application.dsl.TargetFormat.Dmg,
                org.jetbrains.compose.desktop.application.dsl.TargetFormat.Msi,
                org.jetbrains.compose.desktop.application.dsl.TargetFormat.Deb
            )
            packageName = "Grapevine"
            packageVersion = "1.0.0"

            windows {
                menuGroup = "Grapevine"
                upgradeUuid = "b3a9e3a0-4c6f-4d2e-9f5a-1c2d3e4f5a6b"
            }

            macOS {
                bundleID = "io.grapevine.app"
            }

            linux {
                packageName = "grapevine"
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
}
