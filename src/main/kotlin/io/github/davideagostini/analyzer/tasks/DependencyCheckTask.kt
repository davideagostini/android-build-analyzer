package io.github.davideagostini.analyzer.tasks

import io.github.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.api.provider.Property
import java.net.HttpURLConnection
import java.net.URI

/**
 * Task that checks declared dependencies against Maven Central for outdated versions.
 *
 * Parses build.gradle.kts / build.gradle for implementation/api/testImplementation
 * dependencies, then queries the Maven Central search API to find the latest stable version.
 *
 * Network calls use a 5-second timeout and fail gracefully if Maven Central is unreachable.
 * Only Maven Central is queried — Google Maven (androidx.*) dependencies may not be found.
 *
 * Usage: ./gradlew checkDependencyVersions
 */
open class DependencyCheckTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> =
        project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:Internal
    val findings: MutableList<DependencyFinding> = mutableListOf()

    @TaskAction
    fun analyze() {
        findings.clear()
        if (!extension.get().enabled) return

        val deps = parseDependencies()
        if (deps.isEmpty()) {
            logger.quiet("No pinned dependencies found to check.")
            logFindings()
            return
        }

        logger.quiet("Checking ${deps.size} dependencies against Maven Central...")
        deps.forEach { dep ->
            try {
                val latest = fetchLatestVersion(dep.group, dep.artifact)
                if (latest != null && isNewer(latest, dep.version)) {
                    findings.add(
                        DependencyFinding(
                            groupId = dep.group,
                            artifactId = dep.artifact,
                            currentVersion = dep.version,
                            latestVersion = latest,
                            severity = Severity.LOW
                        )
                    )
                }
            } catch (e: Exception) {
                logger.debug("Could not check ${dep.group}:${dep.artifact} — ${e.message}")
            }
        }

        logFindings()
    }

    // ====================================================================
    // Dependency Parsing
    // ====================================================================

    private data class Dep(val group: String, val artifact: String, val version: String)

    private fun parseDependencies(): List<Dep> {
        val buildFiles = listOf(
            project.file("build.gradle.kts"),
            project.file("build.gradle")
        ).filter { it.exists() }

        // Matches: implementation("group:artifact:version") and similar configurations
        // Skips variable-based versions like $kotlinVersion or ${versions.okhttp}
        val depPattern = Regex(
            """(?:implementation|api|testImplementation|debugImplementation|runtimeOnly)\s*\(\s*["']([^"':]+):([^"':]+):([^"'${'$'}\{]+)["']"""
        )

        val deps = mutableListOf<Dep>()
        buildFiles.forEach { file ->
            try {
                depPattern.findAll(file.readText()).forEach { match ->
                    val version = match.groupValues[3].trim()
                    if (version.isNotEmpty()) {
                        deps.add(
                            Dep(
                                group = match.groupValues[1].trim(),
                                artifact = match.groupValues[2].trim(),
                                version = version
                            )
                        )
                    }
                }
            } catch (e: Exception) {
                logger.warn("Could not parse ${file.name}: ${e.message}")
            }
        }

        // Deduplicate by group:artifact
        return deps.distinctBy { "${it.group}:${it.artifact}" }
    }

    // ====================================================================
    // Maven Central API
    // ====================================================================

    private fun fetchLatestVersion(group: String, artifact: String): String? {
        val url = "https://search.maven.org/solrsearch/select" +
            "?q=g:${group}+AND+a:${artifact}&rows=1&wt=json"

        val connection = URI.create(url).toURL().openConnection() as HttpURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", "Android-Build-Analyzer/1.0")

        return try {
            if (connection.responseCode != 200) return null
            val response = connection.inputStream.bufferedReader().readText()
            // Extract latestVersion field — avoids adding a JSON parsing dependency
            val match = Regex(""""latestVersion"\s*:\s*"([^"]+)"""").find(response)
            val latest = match?.groupValues?.get(1) ?: return null
            // Skip pre-release versions (alpha, beta, RC) to avoid false positives
            if (latest.contains('-')) null else latest
        } finally {
            connection.disconnect()
        }
    }

    // ====================================================================
    // Version Comparison
    // ====================================================================

    /**
     * Returns true if [latest] is strictly newer than [current].
     * Compares each dot-separated numeric segment left-to-right.
     */
    private fun isNewer(latest: String, current: String): Boolean {
        return try {
            val latestParts = latest.split(".").map { it.filter(Char::isDigit).toIntOrNull() ?: 0 }
            val currentParts = current.split(".").map { it.filter(Char::isDigit).toIntOrNull() ?: 0 }
            for (i in 0 until maxOf(latestParts.size, currentParts.size)) {
                val l = latestParts.getOrElse(i) { 0 }
                val c = currentParts.getOrElse(i) { 0 }
                if (l > c) return true
                if (l < c) return false
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    // ====================================================================
    // Logging
    // ====================================================================

    private fun logFindings() {
        logger.quiet("=".repeat(50))
        logger.quiet("Dependency Version Check Results")
        logger.quiet("=".repeat(50))

        if (findings.isEmpty()) {
            logger.quiet("All checked dependencies are up to date.")
        } else {
            logger.quiet("Found ${findings.size} outdated dependency/ies:")
            findings.forEach { finding ->
                val reset = "\u001B[0m"
                logger.quiet("\u001B[33m${finding.severity.name}$reset: ${finding.groupId}:${finding.artifactId}")
                logger.quiet("   Current: ${finding.currentVersion}  →  Latest: ${finding.latestVersion}")
            }
        }
    }
}

data class DependencyFinding(
    val groupId: String,
    val artifactId: String,
    val currentVersion: String,
    val latestVersion: String,
    val severity: Severity
)
