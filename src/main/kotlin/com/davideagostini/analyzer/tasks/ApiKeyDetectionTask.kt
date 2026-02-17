package com.davideagostini.analyzer.tasks

import com.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Internal
import org.gradle.api.provider.Property

/**
 * Severity levels for findings.
 */
enum class Severity {
    HIGH,
    MEDIUM,
    LOW
}

/**
 * Task that scans source files for exposed API keys.
 */
open class ApiKeyDetectionTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> = project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:Input
    var patterns: List<String> = emptyList()

    @get:Internal
    val findings: MutableList<ApiKeyFinding> = mutableListOf()

    @TaskAction
    fun analyze() {
        findings.clear()

        if (!extension.get().enabled) {
            return
        }

        val effectivePatterns = if (patterns.isNotEmpty()) patterns else extension.get().apiKeyPatterns
        val compiledPatterns = effectivePatterns.map { java.util.regex.Pattern.compile(it) }

        val sourceDirs = extension.get().srcDirs!!.filter { it.exists() && it.isDirectory }

        // Scan each source directory
        sourceDirs.forEach { dir ->
            val tree = project.fileTree(dir) {
                include("**/*.java")
                include("**/*.kt")
                include("**/*.xml")
                include("**/*.gradle")
                include("**/*.gradle.kts")
            }

            tree.forEach { file ->
                compiledPatterns.forEach { pattern ->
                    detectInFile(file, pattern)
                }
            }
        }

        logFindings()
    }

    private fun detectInFile(file: java.io.File, pattern: java.util.regex.Pattern) {
        try {
            val content = file.readText()
            val lines = content.lines()

            lines.forEachIndexed { index, line ->
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    val matchedText = matcher.group()
                    val maskedText = maskSensitiveData(matchedText)

                    findings.add(
                        ApiKeyFinding(
                            file = file.relativeTo(project.rootDir).path,
                            line = index + 1,
                            pattern = pattern.pattern(),
                            matched = maskedText,
                            severity = determineSeverity(pattern.pattern())
                        )
                    )
                }
            }
        } catch (e: Exception) {
            // Skip files that can't be read
        }
    }

    private fun maskSensitiveData(matched: String): String {
        return when {
            matched.length <= 8 -> "***MASKED***"
            else -> matched.take(4) + "***" + matched.takeLast(4)
        }
    }

    private fun determineSeverity(pattern: String): Severity {
        return when {
            pattern.contains("PRIVATE KEY") -> Severity.HIGH
            pattern.contains("AKIA") || pattern.contains("ASIA") -> Severity.HIGH
            pattern.contains("Firebase") || pattern.contains("AIza") -> Severity.HIGH
            pattern.contains("STRIPE") -> Severity.HIGH
            else -> Severity.MEDIUM
        }
    }

    private fun logFindings() {
        logger.quiet("=".repeat(50))
        logger.quiet("API Key Detection Results")
        logger.quiet("=".repeat(50))

        if (findings.isEmpty()) {
            logger.quiet("No exposed API keys detected.")
        } else {
            logger.quiet("Found ${findings.size} potential API key(s):")
            findings.forEach { finding ->
                val colorCode = when (finding.severity) {
                    Severity.HIGH -> "\u001B[31m"
                    Severity.MEDIUM -> "\u001B[33m"
                    Severity.LOW -> "\u001B[32m"
                }
                val reset = "\u001B[0m"
                logger.quiet("$colorCode${finding.severity.name}$reset: ${finding.file}:${finding.line}")
                logger.quiet("   Pattern: ${finding.pattern}")
                logger.quiet("   Matched: ${finding.matched}")
            }
        }
    }
}

data class ApiKeyFinding(
    val file: String,
    val line: Int,
    val pattern: String,
    val matched: String,
    val severity: Severity
)
