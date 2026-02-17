package com.davideagostini.analyzer.tasks

import com.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Internal
import org.gradle.api.provider.Property

/**
 * Security issue types.
 */
enum class SecurityIssueType(val displayName: String) {
    DEBUG_ENABLED("Debug Enabled in Release"),
    PROGUARD_DISABLED("ProGuard/R8 Disabled"),
    DEBUG_APP_ID("Debug Application ID"),
    MANIFEST_DEBUGGABLE("Manifest Debuggable Flag"),
    ALLOW_BACKUP_ENABLED("Backup Enabled"),
    CLEARTEXT_TRAFFIC("Cleartext Traffic Allowed"),
    EXPORTED_COMPONENT("Exported Component Without Permission")
}

/**
 * Task that checks for security best practices.
 */
open class SecurityCheckTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> = project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:Internal
    val findings: MutableList<SecurityFinding> = mutableListOf()

    @TaskAction
    fun analyze() {
        findings.clear()

        if (!extension.get().enabled) {
            return
        }

        checkBuildConfig()
        checkManifest()
        logFindings()
    }

    private fun checkBuildConfig() {
        try {
            val androidExtension = project.extensions.getByType(com.android.build.gradle.BaseExtension::class.java)

            if (extension.get().checkDebuggable || extension.get().checkMinifyEnabled) {
                val buildFile = project.file("build.gradle")
                if (buildFile.exists()) {
                    val content = buildFile.readText()

                    if (extension.get().checkDebuggable) {
                        val releaseDebugPattern = Regex("""release\s*\{[^}]*debuggable\s*=\s*true""", RegexOption.MULTILINE)
                        if (releaseDebugPattern.containsMatchIn(content)) {
                            findings.add(
                                SecurityFinding(
                                    type = SecurityIssueType.DEBUG_ENABLED,
                                    severity = Severity.HIGH,
                                    message = "Release build type has debuggable=true. This allows debugging the release APK.",
                                    location = "build.gradle (buildTypes.release.debuggable)",
                                    buildType = "release"
                                )
                            )
                        }
                    }

                    if (extension.get().checkMinifyEnabled) {
                        val releaseMinifyPattern = Regex("""release\s*\{[^}]*minifyEnabled\s*=\s*false""", RegexOption.MULTILINE)
                        if (releaseMinifyPattern.containsMatchIn(content)) {
                            findings.add(
                                SecurityFinding(
                                    type = SecurityIssueType.PROGUARD_DISABLED,
                                    severity = Severity.HIGH,
                                    message = "Release build type does not have minifyEnabled=true. Code obfuscation is disabled.",
                                    location = "build.gradle (buildTypes.release.minifyEnabled)",
                                    buildType = "release"
                                )
                            )
                        }
                    }
                }
            }

            androidExtension.defaultConfig.applicationId?.let { appId ->
                if (appId.contains(".debug") || appId.contains(".test")) {
                    findings.add(
                        SecurityFinding(
                            type = SecurityIssueType.DEBUG_APP_ID,
                            severity = Severity.MEDIUM,
                            message = "Application ID contains '.debug' or '.test', which may indicate a debug build configuration in production.",
                            location = "build.gradle (defaultConfig.applicationId)",
                            buildType = "all"
                        )
                    )
                }
            }

        } catch (e: Exception) {
            logger.warn("Could not analyze build config: ${e.message}")
        }
    }

    private fun checkManifest() {
        val manifestFile = project.file("src/main/AndroidManifest.xml")
        if (!manifestFile.exists()) {
            return
        }

        try {
            val content = manifestFile.readText()

            if (content.contains("android:debuggable=\"true\"")) {
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.MANIFEST_DEBUGGABLE,
                        severity = Severity.HIGH,
                        message = "Manifest has android:debuggable=\"true\" which allows debugging the app.",
                        location = "AndroidManifest.xml (<application>)",
                        buildType = "all"
                    )
                )
            }

            if (extension.get().checkAllowBackup) {
                if (content.contains("android:allowBackup=\"true\"")) {
                    findings.add(
                        SecurityFinding(
                            type = SecurityIssueType.ALLOW_BACKUP_ENABLED,
                            severity = Severity.MEDIUM,
                            message = "Manifest has android:allowBackup=\"true\" which allows app data backup.",
                            location = "AndroidManifest.xml (<application>)",
                            buildType = "all"
                        )
                    )
                }
            }

            if (content.contains("android:usesCleartextTraffic=\"true\"")) {
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.CLEARTEXT_TRAFFIC,
                        severity = Severity.MEDIUM,
                        message = "Manifest allows cleartext (HTTP) traffic which can be intercepted.",
                        location = "AndroidManifest.xml (<application>)",
                        buildType = "all"
                    )
                )
            }

            val exportedPattern = "android:exported=\"true\"".toRegex()
            val permissionPattern = "android:permission=".toRegex()

            exportedPattern.findAll(content).forEach { _ ->
                val lineEnd = content.indexOf(">", exportedPattern.find(content)?.range?.first ?: 0)
                if (lineEnd != -1) {
                    val lineStart = content.lastIndexOf('<', lineEnd)
                    val line = content.substring(lineStart, lineEnd + 1)

                    if (!permissionPattern.containsMatchIn(line)) {
                        findings.add(
                            SecurityFinding(
                                type = SecurityIssueType.EXPORTED_COMPONENT,
                                severity = Severity.LOW,
                                message = "Component is exported but has no permission set.",
                                location = "AndroidManifest.xml",
                                buildType = "all"
                            )
                        )
                    }
                }
            }

        } catch (e: Exception) {
            logger.warn("Could not analyze manifest: ${e.message}")
        }
    }

    private fun logFindings() {
        logger.quiet("=".repeat(50))
        logger.quiet("Security Check Results")
        logger.quiet("=".repeat(50))

        if (findings.isEmpty()) {
            logger.quiet("No security issues found.")
        } else {
            val highCount = findings.count { it.severity == Severity.HIGH }
            val mediumCount = findings.count { it.severity == Severity.MEDIUM }
            val lowCount = findings.count { it.severity == Severity.LOW }

            logger.quiet("Found ${findings.size} issue(s): HIGH=$highCount, MEDIUM=$mediumCount, LOW=$lowCount")

            findings.forEach { finding ->
                val colorCode = when (finding.severity) {
                    Severity.HIGH -> "\u001B[31m"
                    Severity.MEDIUM -> "\u001B[33m"
                    Severity.LOW -> "\u001B[32m"
                }
                val reset = "\u001B[0m"

                logger.quiet("$colorCode${finding.severity.name}$reset: ${finding.type.displayName}")
                logger.quiet("   ${finding.message}")
                logger.quiet("   Location: ${finding.location}")
            }
        }
    }
}

data class SecurityFinding(
    val type: SecurityIssueType,
    val severity: Severity,
    val message: String,
    val location: String,
    val buildType: String
)
