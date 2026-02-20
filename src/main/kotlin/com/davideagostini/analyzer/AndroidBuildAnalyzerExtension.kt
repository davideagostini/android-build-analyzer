package com.davideagostini.analyzer

import org.gradle.api.tasks.Input
import org.gradle.api.file.FileCollection

/**
 * Extension class for configuring the Android Build Analyzer plugin.
 *
 * This class provides configurable options that can be set in build.gradle:
 *
 * androidBuildAnalyzer {
 *     enabled = true
 *     checkDebuggable = true
 *     checkMinifyEnabled = true
 *     checkAllowBackup = true
 *     reportPath = "build/reports/analyzer"
 *     failOnCriticalIssues = false
 * }
 */
open class AndroidBuildAnalyzerExtension {

    /**
     * Enable or disable the analyzer.
     * When false, all analysis tasks will skip their work.
     * Default: true
     */
    @get:Input
    var enabled: Boolean = true

    /**
     * List of regex patterns to use for API key detection.
     * Each pattern should match potential API keys in source code.
     * Default: See AndroidBuildAnalyzerExtension.defaultApiKeyPatterns
     */
    @get:Input
    var apiKeyPatterns: List<String> = defaultApiKeyPatterns

    /**
     * Source directories to scan for API keys.
     * These are automatically set to common Android source directories.
     */
    @get:Input
    var srcDirs: FileCollection? = null

    /**
     * Whether to check for debuggable=true in release build type.
     * Default: true
     */
    @get:Input
    var checkDebuggable: Boolean = true

    /**
     * Whether to check for minifyEnabled=true in release build type.
     * Default: true
     */
    @get:Input
    var checkMinifyEnabled: Boolean = true

    /**
     * Whether to check for allowBackup in AndroidManifest.xml.
     * Default: true
     */
    @get:Input
    var checkAllowBackup: Boolean = true

    /**
     * Path where the HTML report will be generated.
     * Default: "build/reports/analyzer"
     */
    @get:Input
    var reportPath: String = "build/reports/analyzer"

    /**
     * Whether to fail the build when critical security issues are found.
     * Default: false
     */
    @get:Input
    var failOnCriticalIssues: Boolean = false

    /**
     * List of path substrings to exclude from all file scanning tasks.
     * Any file whose path contains one of these strings will be skipped.
     *
     * Example: excludePaths = listOf("src/test", "src/androidTest", "example/")
     * Default: empty (no exclusions)
     */
    @get:Input
    var excludePaths: List<String> = emptyList()

    companion object {
        /**
         * Default regex patterns for detecting API keys in source code.
         *
         * These patterns cover common API key formats:
         * - AWS Access Keys (AKIA, ASIA prefixes)
         * - Firebase API Keys (AIza prefix)
         * - Generic API keys (api_key, API_KEY, etc.)
         * - Private keys (RSA, EC, DSA)
         * - Stripe public keys
         * - Google API keys
         */
        val defaultApiKeyPatterns = listOf(
            "(AKIA|ASIA)[A-Z0-9]{16}",           // AWS keys
            "AIza[0-9A-Za-z\\\\-_]{35}",         // Firebase
            "[aA][pP][iI][-_]?[kK][eE][yY].*['\\\"][a-zA-Z0-9]{20,}['\\\"]",  // Generic API key
            "-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",  // Private keys
            "[sS][tT][rR][iI][pP][eE][_]?[pP][uU][bB][lL][iI][cC][_]?[kK][eE][yY].*['\\\"][a-zA-Z0-9]{20,}['\\\"]",  // Stripe
            "[gG][oO][oO][gG][lL][eE][_]?[aA][pP][iI][_]?[kK][eE][yY].*['\\\"][a-zA-Z0-9]{20,}['\\\"]"  // Google API key
        )
    }
}
