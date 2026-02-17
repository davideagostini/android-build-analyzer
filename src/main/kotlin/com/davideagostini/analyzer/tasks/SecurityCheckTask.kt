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
    EXPORTED_COMPONENT("Exported Component Without Permission"),
    // New: Permission Analysis
    DANGEROUS_PERMISSION("Dangerous Permission Usage"),
    PERMISSION_NOT_DEFINED("Permission Not Defined"),
    // New: Component Security
    EXPORTED_SERVICE("Exported Service Without Permission"),
    EXPORTED_RECEIVER("Exported Broadcast Receiver Without Permission"),
    EXPORTED_PROVIDER("Exported Content Provider Without Permission"),
    // New: Intent Filter Security
    INTENT_FILTER_DATA_EXPOSURE("Intent Filter May Expose Data")
}

/**
 * Dangerous permissions that should be reviewed.
 */
private val DANGEROUS_PERMISSIONS = listOf(
    "READ_CALENDAR", "WRITE_CALENDAR",
    "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
    "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE",
    "BODY_SENSORS", "ACCESS_BACKGROUND_LOCATION"
)

/**
 * Permissions that should always require explicit declaration.
 */
private val HIGH_RISK_PERMISSIONS = listOf(
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
    "WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW"
)

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

            // Enhanced Manifest Analysis
            checkPermissions(content)
            checkComponentSecurity(content)
            checkIntentFilterSecurity(content)

        } catch (e: Exception) {
            logger.warn("Could not analyze manifest: ${e.message}")
        }
    }

    private fun checkPermissions(content: String) {
        // Check for dangerous permissions
        DANGEROUS_PERMISSIONS.forEach { permission ->
            if (content.contains("android.permission.$permission")) {
                val severity = if (permission in HIGH_RISK_PERMISSIONS) Severity.HIGH else Severity.MEDIUM
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.DANGEROUS_PERMISSION,
                        severity = severity,
                        message = "Uses dangerous permission: $permission - Review if absolutely necessary",
                        location = "AndroidManifest.xml (uses-permission)",
                        buildType = "all"
                    )
                )
            }
        }

        // Check for permission declarations
        val permissionDeclarations = Regex("""<permission[^>]*android:name="([^"]+)"""").findAll(content)
        val declaredPermissions = permissionDeclarations.map { it.groupValues[1] }.toSet()

        // Check for uses-permission with undefined permissions
        val usesPermissions = Regex("""android:name="android\.permission\.([^"]+)"""").findAll(content)
        usesPermissions.forEach { match ->
            val permName = "android.permission.${match.groupValues[1]}"
            if (permName !in declaredPermissions && !permName.startsWith("android.permission.COMPANION_")) {
                // Only warn for custom permissions, not system permissions
                if (!permName.startsWith("android.permission.")) {
                    findings.add(
                        SecurityFinding(
                            type = SecurityIssueType.PERMISSION_NOT_DEFINED,
                            severity = Severity.MEDIUM,
                            message = "Uses permission '$permName' that is not explicitly declared",
                            location = "AndroidManifest.xml (uses-permission)",
                            buildType = "all"
                        )
                    )
                }
            }
        }
    }

    private fun checkComponentSecurity(content: String) {
        // Check exported services without permission
        val servicePattern = """<service[^>]*android:exported="true"[^>]*>""".toRegex()
        servicePattern.findAll(content).forEach { match ->
            val serviceContent = match.value
            if (!serviceContent.contains("android:permission=")) {
                val nameMatch = Regex("""android:name="([^"]+)"""").find(serviceContent)
                val componentName = nameMatch?.groupValues?.get(1) ?: "Unknown Service"
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_SERVICE,
                        severity = Severity.MEDIUM,
                        message = "Exported service '$componentName' has no permission protection",
                        location = "AndroidManifest.xml ($componentName)",
                        buildType = "all"
                    )
                )
            }
        }

        // Check exported broadcast receivers without permission
        val receiverPattern = """<receiver[^>]*android:exported="true"[^>]*>""".toRegex()
        receiverPattern.findAll(content).forEach { match ->
            val receiverContent = match.value
            if (!receiverContent.contains("android:permission=")) {
                val nameMatch = Regex("""android:name="([^"]+)"""").find(receiverContent)
                val componentName = nameMatch?.groupValues?.get(1) ?: "Unknown Receiver"
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_RECEIVER,
                        severity = Severity.MEDIUM,
                        message = "Exported broadcast receiver '$componentName' has no permission protection",
                        location = "AndroidManifest.xml ($componentName)",
                        buildType = "all"
                    )
                )
            }
        }

        // Check exported content providers without permission
        val providerPattern = """<provider[^>]*android:exported="true"[^>]*>""".toRegex()
        providerPattern.findAll(content).forEach { match ->
            val providerContent = match.value
            if (!providerContent.contains("android:permission=") && !providerContent.contains("android:grantUriPermissions=")) {
                val nameMatch = Regex("""android:name="([^"]+)"""").find(providerContent)
                val componentName = nameMatch?.groupValues?.get(1) ?: "Unknown Provider"
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_PROVIDER,
                        severity = Severity.HIGH,
                        message = "Exported content provider '$componentName' has no permission protection",
                        location = "AndroidManifest.xml ($componentName)",
                        buildType = "all"
                    )
                )
            }
        }
    }

    private fun checkIntentFilterSecurity(content: String) {
        // Check for intent filters with data exposure risk
        val intentFilterPattern = """<intent-filter[^>]*>[\s\S]*?</intent-filter>""".toRegex()
        intentFilterPattern.findAll(content).forEach { match ->
            val intentFilter = match.value

            // Check for implicit intents with data
            if (intentFilter.contains("<data ") && intentFilter.contains("android:exported=\"true\"")) {
                val actionMatch = Regex("""<action[^>]*android:name="([^"]+)"""").find(intentFilter)
                val action = actionMatch?.groupValues?.get(1) ?: "Unknown"

                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.INTENT_FILTER_DATA_EXPOSURE,
                        severity = Severity.LOW,
                        message = "Intent filter with action '$action' may expose data - verify intent handling",
                        location = "AndroidManifest.xml (intent-filter)",
                        buildType = "all"
                    )
                )
            }
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
