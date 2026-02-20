package com.davideagostini.analyzer.tasks

import com.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.api.provider.Property
import java.util.Properties

/**
 * Types of gradle.properties optimization issues.
 */
enum class GradlePropertyIssueType(val displayName: String) {
    MISSING_PARALLEL("Parallel Execution Disabled"),
    MISSING_CACHING("Build Cache Disabled"),
    MISSING_CONFIGURATION_CACHE("Configuration Cache Disabled"),
    LOW_HEAP_SIZE("Low or Missing JVM Heap Size"),
    MISSING_FILE_SYSTEM_WATCHING("File System Watching Disabled")
}

/**
 * Task that checks gradle.properties for missing build optimization settings.
 *
 * Checks for:
 * - org.gradle.parallel
 * - org.gradle.caching
 * - org.gradle.configuration-cache
 * - org.gradle.jvmargs (-Xmx >= 2g)
 * - org.gradle.vfs.watch
 *
 * Usage: ./gradlew checkGradleProperties
 */
open class GradlePropertiesCheckTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> =
        project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:Internal
    val findings: MutableList<GradlePropertyFinding> = mutableListOf()

    @TaskAction
    fun analyze() {
        findings.clear()
        if (!extension.get().enabled) return
        checkGradleProperties()
        logFindings()
    }

    private fun checkGradleProperties() {
        val props = Properties()
        // Check both module-level and root-level gradle.properties
        listOf(
            project.file("gradle.properties"),
            project.file("../gradle.properties")
        ).firstOrNull { it.exists() }?.inputStream()?.use { props.load(it) }

        // org.gradle.parallel
        if (props.getProperty("org.gradle.parallel") != "true") {
            findings.add(
                GradlePropertyFinding(
                    type = GradlePropertyIssueType.MISSING_PARALLEL,
                    severity = Severity.LOW,
                    message = "Parallel project execution is not enabled — speeds up multi-module builds.",
                    suggestedFix = "org.gradle.parallel=true"
                )
            )
        }

        // org.gradle.caching
        if (props.getProperty("org.gradle.caching") != "true") {
            findings.add(
                GradlePropertyFinding(
                    type = GradlePropertyIssueType.MISSING_CACHING,
                    severity = Severity.LOW,
                    message = "Build cache is not enabled — can dramatically speed up incremental builds.",
                    suggestedFix = "org.gradle.caching=true"
                )
            )
        }

        // org.gradle.configuration-cache
        if (props.getProperty("org.gradle.configuration-cache") != "true") {
            findings.add(
                GradlePropertyFinding(
                    type = GradlePropertyIssueType.MISSING_CONFIGURATION_CACHE,
                    severity = Severity.LOW,
                    message = "Configuration cache is not enabled — reduces Gradle configuration time on repeated builds.",
                    suggestedFix = "org.gradle.configuration-cache=true"
                )
            )
        }

        // JVM heap size
        val jvmArgs = props.getProperty("org.gradle.jvmargs") ?: ""
        val xmxMatch = Regex("-Xmx(\\d+)([gGmM])").find(jvmArgs)
        if (xmxMatch == null) {
            findings.add(
                GradlePropertyFinding(
                    type = GradlePropertyIssueType.LOW_HEAP_SIZE,
                    severity = Severity.LOW,
                    message = "JVM heap size is not configured — may cause OutOfMemoryError on large projects.",
                    suggestedFix = "org.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=512m -XX:+HeapDumpOnOutOfMemoryError"
                )
            )
        } else {
            val size = xmxMatch.groupValues[1].toIntOrNull() ?: 0
            val unit = xmxMatch.groupValues[2].lowercase()
            val sizeMb = if (unit == "g") size * 1024 else size
            if (sizeMb < 2048) {
                findings.add(
                    GradlePropertyFinding(
                        type = GradlePropertyIssueType.LOW_HEAP_SIZE,
                        severity = Severity.LOW,
                        message = "JVM heap is set to ${xmxMatch.value} — consider at least -Xmx4g for Android builds.",
                        suggestedFix = "org.gradle.jvmargs=-Xmx4g -XX:MaxMetaspaceSize=512m -XX:+HeapDumpOnOutOfMemoryError"
                    )
                )
            }
        }

        // File system watching
        if (props.getProperty("org.gradle.vfs.watch") != "true") {
            findings.add(
                GradlePropertyFinding(
                    type = GradlePropertyIssueType.MISSING_FILE_SYSTEM_WATCHING,
                    severity = Severity.LOW,
                    message = "File system watching is not enabled — reduces I/O overhead on incremental builds.",
                    suggestedFix = "org.gradle.vfs.watch=true"
                )
            )
        }
    }

    private fun logFindings() {
        logger.quiet("=".repeat(50))
        logger.quiet("Gradle Properties Check Results")
        logger.quiet("=".repeat(50))

        if (findings.isEmpty()) {
            logger.quiet("Gradle properties are well configured.")
        } else {
            logger.quiet("Found ${findings.size} optimization opportunity/ies:")
            findings.forEach { finding ->
                val reset = "\u001B[0m"
                logger.quiet("\u001B[32m${finding.severity.name}$reset: ${finding.type.displayName}")
                logger.quiet("   ${finding.message}")
                logger.quiet("   Suggested fix: ${finding.suggestedFix}")
            }
        }
    }
}

data class GradlePropertyFinding(
    val type: GradlePropertyIssueType,
    val severity: Severity,
    val message: String,
    val suggestedFix: String
)
