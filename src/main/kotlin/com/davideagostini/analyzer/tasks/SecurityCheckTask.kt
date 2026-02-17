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
    INTENT_FILTER_DATA_EXPOSURE("Intent Filter May Expose Data"),
    // New: Network Security
    MISSING_NETWORK_SECURITY_CONFIG("Missing Network Security Config"),
    CLEAR_TEXT_HTTP_URL("Cleartext HTTP URL Found"),
    NO_CERTIFICATE_PINNING("Missing Certificate Pinning"),
    INSECURE_HTTP_URL("Insecure HTTP URL in Code"),
    // New: ProGuard/R8 Analysis
    MISSING_PROGUARD_RULES("Missing ProGuard/R8 Rules"),
    NO_KEEP_CLASS_MEMBERS("Missing -keepclassmembers Rules"),
    NO_OBFUSCATION("No Obfuscation Enabled"),
    MISSING_LIBRARY_RULES("Missing Rules for Libraries")
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
                        val releaseDebugPattern = Regex("""release\s*\{[\s\S]*?debuggable\s*=\s*true""", RegexOption.MULTILINE)
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
                        val releaseMinifyPattern = Regex("""release\s*\{[\s\S]*?minifyEnabled\s*=\s*false""", RegexOption.MULTILINE)
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
            checkNetworkSecurity(content)
            checkHttpUrlsInCode()
            checkCertificatePinning()
            checkProGuardRules()

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

    private fun checkNetworkSecurity(content: String) {
        // Check for Network Security Config
        val networkSecurityConfigPattern = """android:networkSecurityConfig="(@+xml/|)network_security_config"""".toRegex()
        val hasNetworkSecurityConfig = networkSecurityConfigPattern.containsMatchIn(content)

        if (!hasNetworkSecurityConfig) {
            findings.add(
                SecurityFinding(
                    type = SecurityIssueType.MISSING_NETWORK_SECURITY_CONFIG,
                    severity = Severity.MEDIUM,
                    message = "Missing Network Security Config - consider adding one to enforce HTTPS",
                    location = "AndroidManifest.xml (<application>)",
                    buildType = "all"
                )
            )
        }

        // Check for cleartext traffic permission
        if (content.contains("android:usesCleartextTraffic=\"true\"")) {
            findings.add(
                SecurityFinding(
                    type = SecurityIssueType.CLEAR_TEXT_HTTP_URL,
                    severity = Severity.MEDIUM,
                    message = "Cleartext traffic (HTTP) is allowed - this can be intercepted",
                    location = "AndroidManifest.xml (<application>)",
                    buildType = "all"
                )
            )
        }
    }

    private fun checkHttpUrlsInCode() {
        // Scan source files for HTTP URLs
        val sourceDirs = listOf(
            project.file("src/main/java"),
            project.file("src/main/kotlin")
        )

        val httpUrlPattern = Regex("""https?://[^\s"'<>]+""")

        sourceDirs.forEach { dir ->
            if (dir.exists()) {
                dir.walkTopDown().filter { it.extension in listOf("kt", "java", "xml") }.forEach { file ->
                    try {
                        val content = file.readText()
                        httpUrlPattern.findAll(content).forEach { match ->
                            val url = match.value
                            if (url.startsWith("http://")) {
                                findings.add(
                                    SecurityFinding(
                                        type = SecurityIssueType.INSECURE_HTTP_URL,
                                        severity = Severity.MEDIUM,
                                        message = "Insecure HTTP URL found: $url",
                                        location = "${file.relativeTo(project.rootDir)}",
                                        buildType = "all"
                                    )
                                )
                            }
                        }
                    } catch (e: Exception) {
                        // Skip files that can't be read
                    }
                }
            }
        }
    }

    private fun checkCertificatePinning() {
        // Scan source files for certificate pinning implementation
        val sourceDirs = listOf(
            project.file("src/main/java"),
            project.file("src/main/kotlin")
        )

        val pinningKeywords = listOf(
            "CertificatePinner",
            "pinCertificate",
            "setPinning",
            "validateCertificate"
        )

        var hasPinning = false

        sourceDirs.forEach { dir ->
            if (dir.exists()) {
                dir.walkTopDown().filter { it.extension in listOf("kt", "java") }.forEach { file ->
                    try {
                        val content = file.readText()
                        if (pinningKeywords.any { content.contains(it, ignoreCase = true) }) {
                            hasPinning = true
                        }
                    } catch (e: Exception) {
                        // Skip files that can't be read
                    }
                }
            }
        }

        if (!hasPinning) {
            findings.add(
                SecurityFinding(
                    type = SecurityIssueType.NO_CERTIFICATE_PINNING,
                    severity = Severity.LOW,
                    message = "No certificate pinning detected - consider adding for enhanced security",
                    location = "Source code",
                    buildType = "all"
                )
            )
        }
    }

    private fun checkProGuardRules() {
        // Check if minify is enabled in build config
        val buildFile = project.file("build.gradle")
        val buildKtsFile = project.file("build.gradle.kts")

        var minifyEnabled = false

        // Check build.gradle.kts in current project (app module)
        if (buildKtsFile.exists()) {
            val content = buildKtsFile.readText()
            // Use [\s\S]*? to match across newlines (non-greedy)
            if (Regex("""release\s*\{[\s\S]*?isMinifyEnabled\s*=\s*true""", RegexOption.MULTILINE).containsMatchIn(content)) {
                minifyEnabled = true
            }
        }

        // Check build.gradle (Groovy) in current project
        if (buildFile.exists()) {
            val content = buildFile.readText()
            if (Regex("""release\s*\{[\s\S]*?minifyEnabled\s*=\s*true""", RegexOption.MULTILINE).containsMatchIn(content)) {
                minifyEnabled = true
            }
        }

        // Also check root project directory if we're in app module
        val rootBuildFile = project.file("../build.gradle")
        val rootBuildKtsFile = project.file("../build.gradle.kts")

        if (rootBuildKtsFile.exists()) {
            val content = rootBuildKtsFile.readText()
            if (Regex("""release\s*\{[\s\S]*?isMinifyEnabled\s*=\s*true""", RegexOption.MULTILINE).containsMatchIn(content)) {
                minifyEnabled = true
            }
        }

        if (rootBuildFile.exists()) {
            val content = rootBuildFile.readText()
            if (Regex("""release\s*\{[\s\S]*?minifyEnabled\s*=\s*true""", RegexOption.MULTILINE).containsMatchIn(content)) {
                minifyEnabled = true
            }
        }

        if (minifyEnabled) {
            // Check for ProGuard rules file
            val proguardFiles = listOf(
                project.file("proguard-rules.pro"),
                project.file("app/proguard-rules.pro"),
                project.file("../proguard-rules.pro"),
                project.file("../app/proguard-rules.pro"),
                project.file("proguard-android.txt"),
                project.file("app/proguard-android.txt")
            )

            val rulesFile = proguardFiles.firstOrNull { it.exists() }

            if (rulesFile != null) {
                val rulesContent = rulesFile.readText()

                // Check for common library rules
                val commonLibraries = listOf(
                    "okhttp" to "-dontwarn okhttp3",
                    "retrofit" to "-dontwarn retrofit2",
                    "gson" to "-keepattributes Signature",
                    "rxjava" to "-dontwarn rxjava",
                    "commons-io" to "-dontwarn org.apache.commons.io"
                )

                commonLibraries.forEach { (library, rule) ->
                    val hasLibrary = rulesContent.contains(library, ignoreCase = true)
                    // Check if there's a ProGuard rule for this library
                    // Look for lines starting with -dontwarn or -keep that contain the library name
                    // Use \b (word boundary) to avoid matching "okhttp3" for library "okhttp"
                    val proguardRulePattern = Regex("""^\s*-(dontwarn|keep|warn)\s+.*\b$library\b""", RegexOption.MULTILINE)
                    val hasRule = proguardRulePattern.containsMatchIn(rulesContent)
                    if (hasLibrary && !hasRule) {
                        findings.add(
                            SecurityFinding(
                                type = SecurityIssueType.MISSING_LIBRARY_RULES,
                                severity = Severity.LOW,
                                message = "Library '$library' may need additional rules",
                                location = rulesFile.relativeTo(project.rootDir).path,
                                buildType = "release"
                            )
                        )
                    }
                }

                // Check for -keepclassmembers rules (ignore comments, look for rule at start of line)
                val keepClassMembersPattern = Regex("""^\s*-keepclassmembers""", RegexOption.MULTILINE)
                val hasKeepClassMembers = keepClassMembersPattern.containsMatchIn(rulesContent)
                if (!hasKeepClassMembers) {
                    findings.add(
                        SecurityFinding(
                            type = SecurityIssueType.NO_KEEP_CLASS_MEMBERS,
                            severity = Severity.LOW,
                            message = "No -keepclassmembers rules found - consider adding for model classes",
                            location = rulesFile.relativeTo(project.rootDir).path,
                            buildType = "release"
                        )
                    )
                }
            } else {
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.MISSING_PROGUARD_RULES,
                        severity = Severity.MEDIUM,
                        message = "ProGuard rules file not found - create one for better obfuscation",
                        location = "proguard-rules.pro",
                        buildType = "release"
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
