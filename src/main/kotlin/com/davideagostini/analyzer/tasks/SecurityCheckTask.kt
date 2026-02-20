package com.davideagostini.analyzer.tasks

import com.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Internal
import org.gradle.api.provider.Property

/**
 * ========================================================================
 * Security Issue Types Enumeration
 * ========================================================================
 * Defines all types of security issues that can be detected by the analyzer.
 * Each type has a display name for reporting purposes.
 */
enum class SecurityIssueType(val displayName: String) {
    // Build Configuration Issues
    DEBUG_ENABLED("Debug Enabled in Release"),           // debuggable=true in release build
    PROGUARD_DISABLED("ProGuard/R8 Disabled"),           // minifyEnabled=false in release
    DEBUG_APP_ID("Debug Application ID"),                // Application ID contains .debug or .test

    // Manifest Security Issues
    MANIFEST_DEBUGGABLE("Manifest Debuggable Flag"),     // android:debuggable="true" in manifest
    ALLOW_BACKUP_ENABLED("Backup Enabled"),              // android:allowBackup="true"
    CLEARTEXT_TRAFFIC("Cleartext Traffic Allowed"),      // android:usesCleartextTraffic="true"
    EXPORTED_COMPONENT("Exported Component Without Permission"), // Exported without permission

    // Permission Analysis Issues
    DANGEROUS_PERMISSION("Dangerous Permission Usage"),        // Uses dangerous permissions
    PERMISSION_NOT_DEFINED("Permission Not Defined"),           // Uses undefined custom permission

    // Component Security Issues
    EXPORTED_SERVICE("Exported Service Without Permission"),           // Service exported without permission
    EXPORTED_RECEIVER("Exported Broadcast Receiver Without Permission"), // Receiver exported without permission
    EXPORTED_PROVIDER("Exported Content Provider Without Permission"), // Provider exported without permission

    // Intent Filter Security Issues
    INTENT_FILTER_DATA_EXPOSURE("Intent Filter May Expose Data"), // Intent filter may expose data

    // Network Security Issues
    MISSING_NETWORK_SECURITY_CONFIG("Missing Network Security Config"), // No network security config
    CLEAR_TEXT_HTTP_URL("Cleartext HTTP URL Found"),                 // Cleartext traffic allowed
    NO_CERTIFICATE_PINNING("Missing Certificate Pinning"),           // No certificate pinning detected
    INSECURE_HTTP_URL("Insecure HTTP URL in Code"),                   // HTTP URL found in source code

    // ProGuard/R8 Analysis Issues
    MISSING_PROGUARD_RULES("Missing ProGuard/R8 Rules"),        // ProGuard rules file not found
    NO_KEEP_CLASS_MEMBERS("Missing -keepclassmembers Rules"),    // No keepclassmembers rules
    NO_OBFUSCATION("No Obfuscation Enabled"),                   // No obfuscation enabled
    MISSING_LIBRARY_RULES("Missing Rules for Libraries")        // Library missing proper rules
}

/**
 * ========================================================================
 * Dangerous Permissions List
 * ========================================================================
 * Android permissions that are considered dangerous because they
 * can access sensitive user data or affect other apps.
 * These permissions require runtime permission requests on Android 6.0+
 */
private val DANGEROUS_PERMISSIONS = listOf(
    // Calendar permissions
    "READ_CALENDAR", "WRITE_CALENDAR",
    // Camera and contacts
    "CAMERA", "READ_CONTACTS", "WRITE_CONTACTS",
    // Account and location
    "GET_ACCOUNTS", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    // Audio and phone
    "RECORD_AUDIO", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "CALL_PHONE", "READ_CALL_LOG", "WRITE_CALL_LOG",
    // SMS
    "SEND_SMS", "RECEIVE_SMS", "READ_SMS",
    // Storage
    "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE",
    // Sensors
    "BODY_SENSORS", "ACCESS_BACKGROUND_LOCATION"
)

/**
 * ========================================================================
 * High Risk Permissions List
 * ========================================================================
 * Permissions that are particularly sensitive and should always
 * require explicit declaration and careful review.
 */
private val HIGH_RISK_PERMISSIONS = listOf(
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
    "WRITE_SETTINGS", "SYSTEM_ALERT_WINDOW"
)

/**
 * ========================================================================
 * SecurityCheckTask
 * ========================================================================
 * Gradle task that analyzes Android projects for security vulnerabilities
 * and best practice violations.
 *
 * This task performs comprehensive security analysis including:
 * - Build configuration checks (debuggable, minifyEnabled)
 * - AndroidManifest.xml analysis
 * - Permission usage analysis
 * - Component security (services, receivers, providers)
 * - Network security configuration
 * - ProGuard/R8 rules validation
 *
 * Usage: ./gradlew securityCheck
 */
open class SecurityCheckTask : DefaultTask() {

    // ====================================================================
    // Task Properties
    // ====================================================================

    /**
     * Reference to the plugin extension for configuration.
     * Annotated with @get:Internal to exclude from Gradle up-to-date checking.
     */
    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> = project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    /**
     * List to store all security findings during analysis.
     * Annotated with @get:Internal to exclude from Gradle up-to-date checking.
     */
    @get:Internal
    val findings: MutableList<SecurityFinding> = mutableListOf()

    // ====================================================================
    // Main Task Action
    // ====================================================================

    /**
     * Main entry point for the security check task.
     * This method is called when the task is executed.
     * It orchestrates all security checks and logs the results.
     */
    @TaskAction
    fun analyze() {
        // Clear previous findings
        findings.clear()

        // Check if the analyzer is enabled in configuration
        if (!extension.get().enabled) {
            return
        }

        // Run all security checks
        checkBuildConfig()    // Check build.gradle configuration
        checkManifest()       // Check AndroidManifest.xml
        logFindings()         // Output results
    }

    // ====================================================================
    // Build Configuration Checks
    // ====================================================================

    /**
     * Analyzes the project's build.gradle files for security issues
     * in the build configuration.
     *
     * Checks for:
     * - debuggable=true in release build type
     * - minifyEnabled=false in release build type
     * - Application ID containing debug/test patterns
     */
    private fun checkBuildConfig() {
        try {
            // Get the Android extension to access build configuration
            val androidExtension = project.extensions.getByType(com.android.build.gradle.BaseExtension::class.java)

            // Check debuggable and minifyEnabled settings if enabled in configuration
            if (extension.get().checkDebuggable || extension.get().checkMinifyEnabled) {
                val buildFile = project.file("build.gradle")
                if (buildFile.exists()) {
                    val content = buildFile.readText()

                    // Check if debuggable=true is set in release build type
                    // Uses regex with MULTILINE to match across multiple lines
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

                    // Check if minifyEnabled=false in release build type
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

            // Check application ID for debug/test patterns
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

    // ====================================================================
    // AndroidManifest.xml Checks
    // ====================================================================

    /**
     * Main method for analyzing the AndroidManifest.xml file.
     * This is the entry point for all manifest-related security checks.
     *
     * It delegates to specialized methods for different security aspects:
     * - Basic manifest security
     * - Permission analysis
     * - Component security
     * - Intent filter security
     * - Network security
     * - HTTP URL scanning in code
     * - Certificate pinning detection
     * - ProGuard rules validation
     */
    private fun checkManifest() {
        // Locate the AndroidManifest.xml file
        val manifestFile = project.file("src/main/AndroidManifest.xml")
        if (!manifestFile.exists()) {
            return
        }

        try {
            // Read the manifest content
            val content = manifestFile.readText()

            // ================================================================
            // Basic Manifest Security Checks
            // ================================================================

            // Check for android:debuggable="true" in application tag
            if (content.contains("android:debuggable=\"true\"")) {
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.MANIFEST_DEBUGGABLE,
                        severity = Severity.HIGH,
                        message = "Manifest has android:debuggable=\"true\" which allows debugging the app.\nSuggested fix:\nRemove android:debuggable attribute or set to \"false\" in AndroidManifest.xml",
                        location = "AndroidManifest.xml (<application>)",
                        buildType = "all"
                    )
                )
            }

            // Check for android:allowBackup="true" (if enabled in config)
            if (extension.get().checkAllowBackup) {
                if (content.contains("android:allowBackup=\"true\"")) {
                    findings.add(
                        SecurityFinding(
                            type = SecurityIssueType.ALLOW_BACKUP_ENABLED,
                            severity = Severity.MEDIUM,
                            message = "Manifest has android:allowBackup=\"true\" which allows app data backup.\nSuggested fix:\nSet android:allowBackup=\"false\" in AndroidManifest.xml or use android:fullBackupContent=\"@xml/backup_rules\" to control what gets backed up",
                            location = "AndroidManifest.xml (<application>)",
                            buildType = "all"
                        )
                    )
                }
            }

            // Check for android:usesCleartextTraffic="true"
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

            // Check for exported components without permission protection
            // Pattern to find android:exported="true"
            val exportedPattern = "android:exported=\"true\"".toRegex()
            // Pattern to find android:permission attribute
            val permissionPattern = "android:permission=".toRegex()

            // Iterate through all exported components
            exportedPattern.findAll(content).forEach { _ ->
                // Find the component tag containing the exported attribute
                val lineEnd = content.indexOf(">", exportedPattern.find(content)?.range?.first ?: 0)
                if (lineEnd != -1) {
                    val lineStart = content.lastIndexOf('<', lineEnd)
                    val line = content.substring(lineStart, lineEnd + 1)

                    // If no permission is set, add a finding
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

            // ================================================================
            // Advanced Security Analysis
            // ================================================================

            // Delegate to specialized analysis methods
            checkPermissions(content)           // Analyze permission usage
            checkComponentSecurity(content)     // Check services, receivers, providers
            checkIntentFilterSecurity(content)  // Analyze intent filters
            checkNetworkSecurity(content)        // Check network security config
            checkHttpUrlsInCode()               // Scan for HTTP URLs in source code
            checkCertificatePinning()           // Check for certificate pinning
            checkProGuardRules()                // Validate ProGuard/R8 rules

        } catch (e: Exception) {
            logger.warn("Could not analyze manifest: ${e.message}")
        }
    }

    // ====================================================================
    // Permission Analysis
    // ====================================================================

    /**
     * Analyzes permissions declared in the manifest.
     *
     * Checks for:
     * - Dangerous permissions that should be reviewed
     * - High-risk permissions that require explicit handling
     * - Custom permissions that are used but not declared
     *
     * @param content The AndroidManifest.xml content as a string
     */
    private fun checkPermissions(content: String) {
        // ================================================================
        // Check for dangerous permissions
        // ================================================================
        // Iterate through all known dangerous permissions and check if they're used
        DANGEROUS_PERMISSIONS.forEach { permission ->
            if (content.contains("android.permission.$permission")) {
                // Determine severity: HIGH for high-risk permissions, MEDIUM for others
                val severity = if (permission in HIGH_RISK_PERMISSIONS) Severity.HIGH else Severity.MEDIUM
                val fixSuggestion = if (permission in HIGH_RISK_PERMISSIONS) {
                    "\nThis is a high-risk permission. Ensure you have a legitimate need and proper user consent flow."
                } else {
                    "\nConsider if this permission is absolutely necessary. Request at runtime on Android 6.0+."
                }
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.DANGEROUS_PERMISSION,
                        severity = severity,
                        message = "Uses dangerous permission: $permission - Review if absolutely necessary$fixSuggestion",
                        location = "AndroidManifest.xml (uses-permission)",
                        buildType = "all"
                    )
                )
            }
        }

        // ================================================================
        // Check for undefined custom permissions
        // ================================================================
        // Find all permission declarations in the manifest
        val permissionDeclarations = Regex("""<permission[^>]*android:name="([^"]+)"""").findAll(content)
        val declaredPermissions = permissionDeclarations.map { it.groupValues[1] }.toSet()

        // Find all uses-permission declarations
        val usesPermissions = Regex("""android:name="android\.permission\.([^"]+)"""").findAll(content)
        usesPermissions.forEach { match ->
            val permName = "android.permission.${match.groupValues[1]}"
            // Check if the permission is not a system permission and not declared
            if (permName !in declaredPermissions && !permName.startsWith("android.permission.COMPANION_")) {
                // Only warn for custom permissions, not standard Android permissions
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

    // ====================================================================
    // Component Security Analysis
    // ====================================================================

    /**
     * Analyzes Android components (services, receivers, providers) for
     * security issues related to export and permission settings.
     *
     * Checks for:
     * - Exported services without permission protection
     * - Exported broadcast receivers without permission protection
     * - Exported content providers without permission protection
     *
     * @param content The AndroidManifest.xml content as a string
     */
    private fun checkComponentSecurity(content: String) {
        // ================================================================
        // Check exported services without permission
        // ================================================================
        // Pattern matches <service> tags with android:exported="true"
        val servicePattern = """<service[^>]*android:exported="true"[^>]*>""".toRegex()
        servicePattern.findAll(content).forEach { match ->
            val serviceContent = match.value
            // Check if the service has a permission attribute
            if (!serviceContent.contains("android:permission=")) {
                // Extract the service name
                val nameMatch = Regex("""android:name="([^"]+)"""").find(serviceContent)
                val componentName = nameMatch?.groupValues?.get(1) ?: "Unknown Service"

                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_SERVICE,
                        severity = Severity.MEDIUM,
                        message = "Exported service '$componentName' has no permission protection\nSuggested fix:\nAdd android:permission=\"your.package.permission.NAME\" or set android:exported=\"false\" if not needed",
                        location = "AndroidManifest.xml ($componentName)",
                        buildType = "all"
                    )
                )
            }
        }

        // ================================================================
        // Check exported broadcast receivers without permission
        // ================================================================
        // Pattern matches <receiver> tags with android:exported="true"
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
                        message = "Exported broadcast receiver '$componentName' has no permission protection\nSuggested fix:\nAdd android:permission=\"your.package.permission.NAME\" or set android:exported=\"false\" if not needed",
                        location = "AndroidManifest.xml ($componentName)",
                        buildType = "all"
                    )
                )
            }
        }

        // ================================================================
        // Check exported content providers without permission
        // ================================================================
        // Pattern matches <provider> tags with android:exported="true"
        val providerPattern = """<provider[^>]*android:exported="true"[^>]*>""".toRegex()
        providerPattern.findAll(content).forEach { match ->
            val providerContent = match.value
            // Check for both permission and grantUriPermissions attributes
            if (!providerContent.contains("android:permission=") && !providerContent.contains("android:grantUriPermissions=")) {
                val nameMatch = Regex("""android:name="([^"]+)"""").find(providerContent)
                val componentName = nameMatch?.groupValues?.get(1) ?: "Unknown Provider"

                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.EXPORTED_PROVIDER,
                        severity = Severity.HIGH,
                        message = "Exported content provider '$componentName' has no permission protection\nSuggested fix:\nAdd android:permission=\"your.package.permission.NAME\" or android:grantUriPermissions=\"true\" or set android:exported=\"false\" if not needed",
                        location = "AndroidManifest.xml ($componentName)",
                        buildType = "all"
                    )
                )
            }
        }
    }

    // ====================================================================
    // Intent Filter Security Analysis
    // ====================================================================

    /**
     * Analyzes intent filters for potential data exposure risks.
     *
     * Checks for:
     * - Intent filters with data elements that are exported
     * - Implicit intents that may expose sensitive data
     *
     * @param content The AndroidManifest.xml content as a string
     */
    private fun checkIntentFilterSecurity(content: String) {
        // Pattern matches complete intent-filter blocks (including nested elements)
        val intentFilterPattern = """<intent-filter[^>]*>[\s\S]*?</intent-filter>""".toRegex()
        intentFilterPattern.findAll(content).forEach { match ->
            val intentFilter = match.value

            // Check if intent filter has both data and is exported
            // This could indicate a potential data exposure
            if (intentFilter.contains("<data ") && intentFilter.contains("android:exported=\"true\"")) {
                // Extract the action name for the finding message
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

    // ====================================================================
    // Network Security Analysis
    // ====================================================================

    /**
     * Analyzes network security configuration in the manifest.
     *
     * Checks for:
     * - Missing Network Security Config
     * - Cleartext traffic allowed in manifest
     *
     * @param content The AndroidManifest.xml content as a string
     */
    private fun checkNetworkSecurity(content: String) {
        // ================================================================
        // Check for Network Security Config
        // ================================================================
        // Pattern matches android:networkSecurityConfig attribute
        val networkSecurityConfigPattern = """android:networkSecurityConfig="(@+xml/|)network_security_config"""".toRegex()
        val hasNetworkSecurityConfig = networkSecurityConfigPattern.containsMatchIn(content)

        if (!hasNetworkSecurityConfig) {
            val suggestedNetworkSecurityConfig = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>"""
            findings.add(
                SecurityFinding(
                    type = SecurityIssueType.MISSING_NETWORK_SECURITY_CONFIG,
                    severity = Severity.MEDIUM,
                    message = "Missing Network Security Config - consider adding one to enforce HTTPS\nSuggested fix:\n1. Create res/xml/network_security_config.xml:\n$suggestedNetworkSecurityConfig\n\n2. Add to AndroidManifest.xml:\nandroid:networkSecurityConfig=\"@xml/network_security_config\"",
                    location = "AndroidManifest.xml (<application>)",
                    buildType = "all"
                )
            )
        }

        // ================================================================
        // Check for cleartext traffic permission
        // ================================================================
        if (content.contains("android:usesCleartextTraffic=\"true\"")) {
            findings.add(
                SecurityFinding(
                    type = SecurityIssueType.CLEAR_TEXT_HTTP_URL,
                    severity = Severity.MEDIUM,
                    message = "Cleartext traffic (HTTP) is allowed - this can be intercepted\nSuggested fix:\nSet android:usesCleartextTraffic=\"false\" in AndroidManifest.xml or create a network security config to enforce HTTPS",
                    location = "AndroidManifest.xml (<application>)",
                    buildType = "all"
                )
            )
        }
    }

    // ====================================================================
    // HTTP URL Scanning in Source Code
    // ====================================================================

    /**
     * Scans source code files for insecure HTTP URLs.
     *
     * Searches through:
     * - src/main/java
     * - src/main/kotlin
     *
     * Looks for URLs starting with "http://" (not "https://")
     */
    private fun checkHttpUrlsInCode() {
        // Define source directories to scan
        val sourceDirs = listOf(
            project.file("src/main/java"),
            project.file("src/main/kotlin")
        )

        // Regex pattern to match HTTP and HTTPS URLs
        val httpUrlPattern = Regex("""https?://[^\s"'<>]+""")

        val excludePaths = extension.get().excludePaths

        // Iterate through each source directory
        sourceDirs.forEach { dir ->
            if (dir.exists()) {
                // Walk through all files in the directory
                dir.walkTopDown()
                    .filter { it.extension in listOf("kt", "java", "xml") }
                    .filter { file -> excludePaths.none { excluded -> file.relativeTo(project.rootDir).path.contains(excluded) } }
                    .forEach { file ->
                    try {
                        val content = file.readText()
                        // Find all URLs in the file
                        httpUrlPattern.findAll(content).forEach { match ->
                            val url = match.value
                            // Flag insecure HTTP URLs (not HTTPS)
                            if (url.startsWith("http://")) {
                                val secureUrl = url.replace("http://", "https://")
                                findings.add(
                                    SecurityFinding(
                                        type = SecurityIssueType.INSECURE_HTTP_URL,
                                        severity = Severity.MEDIUM,
                                        message = "Insecure HTTP URL found: $url\nSuggested fix: Replace with HTTPS URL:\n$secureUrl",
                                        location = "${file.relativeTo(project.rootDir)}",
                                        buildType = "all"
                                    )
                                )
                            }
                        }
                    } catch (e: Exception) {
                        // Skip files that can't be read (binary files, encoding issues, etc.)
                    }
                }
            }
        }
    }

    // ====================================================================
    // Certificate Pinning Detection
    // ====================================================================

    /**
     * Scans source code for certificate pinning implementation.
     *
     * If no certificate pinning is found, it suggests adding it
     * for enhanced security.
     *
     * Looks for common certificate pinning keywords:
     * - CertificatePinner (OkHttp)
     * - pinCertificate
     * - setPinning
     * - validateCertificate
     */
    private fun checkCertificatePinning() {
        // Define source directories to scan
        val sourceDirs = listOf(
            project.file("src/main/java"),
            project.file("src/main/kotlin")
        )

        // Keywords that indicate certificate pinning implementation
        val pinningKeywords = listOf(
            "CertificatePinner",
            "pinCertificate",
            "setPinning",
            "validateCertificate"
        )

        var hasPinning = false
        val excludePaths = extension.get().excludePaths

        // Scan each source directory
        sourceDirs.forEach { dir ->
            if (dir.exists()) {
                dir.walkTopDown()
                    .filter { it.extension in listOf("kt", "java") }
                    .filter { file -> excludePaths.none { excluded -> file.relativeTo(project.rootDir).path.contains(excluded) } }
                    .forEach { file ->
                    try {
                        val content = file.readText()
                        // Check if any pinning keyword is present
                        if (pinningKeywords.any { content.contains(it, ignoreCase = true) }) {
                            hasPinning = true
                        }
                    } catch (e: Exception) {
                        // Skip files that can't be read
                    }
                }
            }
        }

        // If no pinning found, add a finding suggesting to add it
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

    // ====================================================================
    // ProGuard/R8 Rules Analysis
    // ====================================================================

    /**
     * Analyzes ProGuard/R8 configuration for best practices.
     *
     * This method:
     * 1. Checks if minifyEnabled is set to true in release build
     * 2. Looks for proguard-rules.pro file
     * 3. Validates library-specific rules
     * 4. Checks for -keepclassmembers rules
     *
     * Only performs analysis if code obfuscation is enabled.
     */
    private fun checkProGuardRules() {
        // ================================================================
        // Step 1: Check if minify is enabled in build config
        // ================================================================
        // Look for build.gradle and build.gradle.kts files
        val buildFile = project.file("build.gradle")
        val buildKtsFile = project.file("build.gradle.kts")

        var minifyEnabled = false

        // Check build.gradle.kts (Kotlin DSL) for isMinifyEnabled
        if (buildKtsFile.exists()) {
            val content = buildKtsFile.readText()
            // Use [\s\S]*? to match across newlines (non-greedy)
            // This regex finds "release { ... isMinifyEnabled = true"
            if (Regex("""release\s*\{[\s\S]*?isMinifyEnabled\s*=\s*true""", RegexOption.MULTILINE).containsMatchIn(content)) {
                minifyEnabled = true
            }
        }

        // Check build.gradle (Groovy) for minifyEnabled
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

        // ================================================================
        // Step 2: Analyze ProGuard rules if minify is enabled
        // ================================================================
        if (minifyEnabled) {
            // Define possible locations for ProGuard rules files
            val proguardFiles = listOf(
                project.file("proguard-rules.pro"),
                project.file("app/proguard-rules.pro"),
                project.file("../proguard-rules.pro"),
                project.file("../app/proguard-rules.pro"),
                project.file("proguard-android.txt"),
                project.file("app/proguard-android.txt")
            )

            // Find the first existing rules file
            val rulesFile = proguardFiles.firstOrNull { it.exists() }

            if (rulesFile != null) {
                val rulesContent = rulesFile.readText()

                // ============================================================
                // Step 3: Check for library-specific rules
                // ============================================================
                // Common libraries that need ProGuard rules
                val commonLibraries = listOf(
                    "okhttp" to "-dontwarn okhttp3",
                    "retrofit" to "-dontwarn retrofit2",
                    "gson" to "-keepattributes Signature",
                    "rxjava" to "-dontwarn rxjava",
                    "commons-io" to "-dontwarn org.apache.commons.io"
                )

                // Check each library for proper rules
                commonLibraries.forEach { (library, _) ->
                    // First check if the library is referenced in the rules
                    val hasLibrary = rulesContent.contains(library, ignoreCase = true)

                    // Then check if there's a proper ProGuard rule for it
                    // Use word boundaries (\b) to avoid matching "okhttp3" for library "okhttp"
                    val proguardRulePattern = Regex("""^\s*-(dontwarn|keep|warn)\s+.*\b$library\b""", RegexOption.MULTILINE)
                    val hasRule = proguardRulePattern.containsMatchIn(rulesContent)

                    // Get suggested rules for this library
                    val suggestedRule = when (library) {
                        "okhttp" -> "-dontwarn okhttp3.**\n-dontwarn okio.**"
                        "retrofit" -> "-dontwarn retrofit2.**\n-keepattributes Signature"
                        "gson" -> "-keepattributes Signature\n-keep class com.google.gson.** { *; }"
                        "rxjava" -> "-dontwarn rxjava.**\n-dontwarn rxplugins.**"
                        "commons-io" -> "-dontwarn org.apache.commons.io.**"
                        else -> ""
                    }

                    // If library is used but no proper rule exists, add a finding
                    if (hasLibrary && !hasRule) {
                        findings.add(
                            SecurityFinding(
                                type = SecurityIssueType.MISSING_LIBRARY_RULES,
                                severity = Severity.LOW,
                                message = "Library '$library' may need additional rules\nSuggested fix:\n$suggestedRule",
                                location = rulesFile.relativeTo(project.rootDir).path,
                                buildType = "release"
                            )
                        )
                    }
                }

                // ============================================================
                // Step 4: Check for -keepclassmembers rules
                // ============================================================
                // These rules are important for serializable/model classes
                // Use regex that matches at start of line (ignoring comments)
                val keepClassMembersPattern = Regex("""^\s*-keepclassmembers""", RegexOption.MULTILINE)
                val hasKeepClassMembers = keepClassMembersPattern.containsMatchIn(rulesContent)

                if (!hasKeepClassMembers) {
                    val suggestedKeepClassMembers = """
# Keep class members (for model classes with serialization)
-keepclassmembers class * {
    @com.google.gson.annotations.SerializedName <fields>;
}
-keepclassmembers class com.example.yourpackage.model.** {
    *;
}
                    """.trimIndent()
                    findings.add(
                        SecurityFinding(
                            type = SecurityIssueType.NO_KEEP_CLASS_MEMBERS,
                            severity = Severity.LOW,
                            message = "No -keepclassmembers rules found - consider adding for model classes\nSuggested fix:\n$suggestedKeepClassMembers",
                            location = rulesFile.relativeTo(project.rootDir).path,
                            buildType = "release"
                        )
                    )
                }
            } else {
                // No ProGuard rules file found - suggest basic template
                val suggestedProGuardRules = """
# Android ProGuard Rules
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep application class
-keep class your.app.package.MyApplication { *; }

# Keep model classes
-keep class your.app.package.model.** { *; }

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }
                """.trimIndent()
                findings.add(
                    SecurityFinding(
                        type = SecurityIssueType.MISSING_PROGUARD_RULES,
                        severity = Severity.MEDIUM,
                        message = "ProGuard rules file not found - create one for better obfuscation\nSuggested fix:\nCreate proguard-rules.pro with:\n$suggestedProGuardRules",
                        location = "proguard-rules.pro",
                        buildType = "release"
                    )
                )
            }
        }
    }

    // ====================================================================
    // Results Logging
    // ====================================================================

    /**
     * Logs all security findings to the console.
     * Uses color-coded output for different severity levels.
     *
     * Output format:
     * - HIGH: Red
     * - MEDIUM: Yellow
     * - LOW: Green
     */
    private fun logFindings() {
        // Print header
        logger.quiet("=".repeat(50))
        logger.quiet("Security Check Results")
        logger.quiet("=".repeat(50))

        if (findings.isEmpty()) {
            // No issues found
            logger.quiet("No security issues found.")
        } else {
            // Count findings by severity
            val highCount = findings.count { it.severity == Severity.HIGH }
            val mediumCount = findings.count { it.severity == Severity.MEDIUM }
            val lowCount = findings.count { it.severity == Severity.LOW }

            // Print summary
            logger.quiet("Found ${findings.size} issue(s): HIGH=$highCount, MEDIUM=$mediumCount, LOW=$lowCount")

            // Print each finding with color coding
            findings.forEach { finding ->
                // Select color based on severity
                val colorCode = when (finding.severity) {
                    Severity.HIGH -> "\u001B[31m"   // Red
                    Severity.MEDIUM -> "\u001B[33m"  // Yellow
                    Severity.LOW -> "\u001B[32m"     // Green
                }
                val reset = "\u001B[0m"  // Reset color

                // Print finding with color
                logger.quiet("$colorCode${finding.severity.name}$reset: ${finding.type.displayName}")
                logger.quiet("   ${finding.message}")
                logger.quiet("   Location: ${finding.location}")
            }

            if (extension.get().failOnCriticalIssues && highCount > 0) {
                throw org.gradle.api.GradleException(
                    "Security check failed: $highCount HIGH severity issue(s) found. " +
                    "Fix the issues above or set failOnCriticalIssues = false to suppress this check."
                )
            }
        }
    }
}

/**
 * ========================================================================
 * SecurityFinding Data Class
 * ========================================================================
 * Represents a single security issue found during analysis.
 *
 * @property type The type of security issue (from SecurityIssueType enum)
 * @property severity The severity level (HIGH, MEDIUM, LOW)
 * @property description Human-readable description of the issue
 * @property location File path or location where the issue was found
 * @property buildType The build type where this applies (debug, release, all)
 */
data class SecurityFinding(
    val type: SecurityIssueType,
    val severity: Severity,
    val message: String,
    val location: String,
    val buildType: String
)
