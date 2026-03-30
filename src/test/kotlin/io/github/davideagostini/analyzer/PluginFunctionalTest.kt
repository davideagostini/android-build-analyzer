package io.github.davideagostini.analyzer

import io.github.davideagostini.analyzer.tasks.FindingFilterSupport
import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File
import java.util.Properties

class PluginFunctionalTest {

    @TempDir
    lateinit var projectDir: File

    @Test
    fun generateAnalysisReportAvoidsDebugAppIdFalsePositive() {
        writeFixtureProject(
            buildGradle = """
                plugins {
                    id("com.android.application") version "8.2.2"
                    id("io.github.davideagostini.analyzer")
                }

                android {
                    namespace = "com.example.testapp"
                    compileSdk = 34

                    defaultConfig {
                        applicationId = "com.example.testapp"
                        minSdk = 24
                        targetSdk = 34
                        versionCode = 1
                        versionName = "1.0"
                    }
                }
            """.trimIndent(),
            manifest = """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android"
                    package="com.example.testapp">
                    <application
                        android:allowBackup="true"
                        android:label="@string/app_name" />
                </manifest>
            """.trimIndent(),
            stringsXml = """
                <resources>
                    <string name="app_name">Analyzer Fixture</string>
                    <string name="unused_value">Unused</string>
                </resources>
            """.trimIndent()
        )

        val result = gradleRunner("generateAnalysisReport").build()

        assertEquals(TaskOutcome.SUCCESS, result.task(":generateAnalysisReport")?.outcome)
        val report = File(projectDir, "build/reports/analyzer/report.json").readText()
        assertFalse(report.contains("DEBUG_APP_ID"))
        assertTrue(report.contains("ALLOW_BACKUP_ENABLED"))
    }

    @Test
    fun generatedBaselineSuppressesExistingFindings() {
        val customPermission = "com.example.testapp.permission.SYNC"
        writeFixtureProject(
            buildGradle = """
                plugins {
                    id("com.android.application") version "8.2.2"
                    id("io.github.davideagostini.analyzer")
                }

                android {
                    namespace = "com.example.testapp"
                    compileSdk = 34

                    defaultConfig {
                        applicationId = "com.example.testapp"
                        minSdk = 24
                        targetSdk = 34
                        versionCode = 1
                        versionName = "1.0"
                    }
                }
            """.trimIndent(),
            manifest = """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android"
                    package="com.example.testapp">
                    <uses-permission android:name="$customPermission" />
                    <application android:label="@string/app_name" />
                </manifest>
            """.trimIndent(),
            stringsXml = """
                <resources>
                    <string name="app_name">Analyzer Fixture</string>
                </resources>
            """.trimIndent()
        )

        val baselineResult = gradleRunner("generateAnalysisBaseline").build()
        assertEquals(TaskOutcome.SUCCESS, baselineResult.task(":generateAnalysisBaseline")?.outcome)

        val baselineFile = File(projectDir, "android-build-analyzer-baseline.json")
        assertTrue(baselineFile.exists())

        val expectedFingerprint = FindingFilterSupport.sha256(
            "PERMISSION_NOT_DEFINED:AndroidManifest.xml (uses-permission):Uses custom permission '$customPermission' that is not declared in manifest"
        )
        val baselineContent = baselineFile.readText()
        assertTrue(baselineContent.contains(expectedFingerprint))

        val reportResult = gradleRunner("generateAnalysisReport").build()
        assertEquals(TaskOutcome.SUCCESS, reportResult.task(":generateAnalysisReport")?.outcome)

        val report = File(projectDir, "build/reports/analyzer/report.json").readText()
        assertFalse(report.contains("PERMISSION_NOT_DEFINED"))
    }

    private fun gradleRunner(vararg arguments: String): GradleRunner {
        return GradleRunner.create()
            .withProjectDir(projectDir)
            .withArguments(*arguments, "--stacktrace")
            .withPluginClasspath()
            .forwardOutput()
    }

    private fun writeFixtureProject(
        buildGradle: String,
        manifest: String,
        stringsXml: String
    ) {
        writeFile(
            "settings.gradle.kts",
            """
            pluginManagement {
                repositories {
                    google()
                    mavenCentral()
                    gradlePluginPortal()
                }
            }

            dependencyResolutionManagement {
                repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
                repositories {
                    google()
                    mavenCentral()
                }
            }

            rootProject.name = "functional-fixture"
            """.trimIndent()
        )

        writeFile("build.gradle.kts", buildGradle)
        writeFile("local.properties", "sdk.dir=${loadSdkDir()}")
        writeFile("src/main/AndroidManifest.xml", manifest)
        writeFile("src/main/res/values/strings.xml", stringsXml)
    }

    private fun loadSdkDir(): String {
        val props = Properties()
        File("local.properties").inputStream().use { props.load(it) }
        return props.getProperty("sdk.dir")
    }

    private fun writeFile(relativePath: String, content: String) {
        val file = File(projectDir, relativePath)
        file.parentFile?.mkdirs()
        file.writeText(content)
    }
}
