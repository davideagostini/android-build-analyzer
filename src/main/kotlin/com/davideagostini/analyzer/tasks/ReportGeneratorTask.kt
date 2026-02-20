package com.davideagostini.analyzer.tasks

import com.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Internal
import org.gradle.api.provider.Property

/**
 * Task that generates HTML, JSON and SARIF reports from all analysis tasks.
 *
 * Outputs (in reportPath directory):
 * - report.html  — human-readable with color-coded severity badges
 * - report.json  — structured JSON for programmatic consumption
 * - report.sarif — SARIF 2.1.0 for GitHub Advanced Security / IDE integration
 */
open class ReportGeneratorTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> =
        project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:OutputDirectory
    val reportDir: java.io.File by lazy {
        project.file(extension.get().reportPath)
    }

    @get:Internal
    val apiKeyTask: Property<ApiKeyDetectionTask> =
        project.objects.property(ApiKeyDetectionTask::class.java)

    @get:Internal
    val apkAnalysisTask: Property<ApkAnalysisTask> =
        project.objects.property(ApkAnalysisTask::class.java)

    @get:Internal
    val securityCheckTask: Property<SecurityCheckTask> =
        project.objects.property(SecurityCheckTask::class.java)

    @get:Internal
    val resourceAnalysisTask: Property<ResourceAnalysisTask> =
        project.objects.property(ResourceAnalysisTask::class.java)

    @get:Internal
    val gradlePropertiesTask: Property<GradlePropertiesCheckTask> =
        project.objects.property(GradlePropertiesCheckTask::class.java)

    @get:Internal
    val dependencyCheckTask: Property<DependencyCheckTask> =
        project.objects.property(DependencyCheckTask::class.java)

    @TaskAction
    fun generate() {
        if (!extension.get().enabled) return

        reportDir.mkdirs()

        val htmlFile = java.io.File(reportDir, "report.html")
        val jsonFile = java.io.File(reportDir, "report.json")
        val sarifFile = java.io.File(reportDir, "report.sarif")

        htmlFile.writeText(buildHtmlReport())
        jsonFile.writeText(buildJsonReport())
        sarifFile.writeText(buildSarifReport())

        logger.quiet("=".repeat(50))
        logger.quiet("Reports generated:")
        logger.quiet("  HTML  → ${htmlFile.absolutePath}")
        logger.quiet("  JSON  → ${jsonFile.absolutePath}")
        logger.quiet("  SARIF → ${sarifFile.absolutePath}")
        logger.quiet("=".repeat(50))
    }

    // ====================================================================
    // HTML Helpers
    // ====================================================================

    private fun String.escapeHtml(): String = this
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#x27;")

    // ====================================================================
    // JSON Helpers
    // ====================================================================

    private fun String.escapeJson(): String = this
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")

    private fun jsonStr(value: String) = "\"${value.escapeJson()}\""

    // ====================================================================
    // HTML Report
    // ====================================================================

    private fun buildHtmlReport(): String {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Android Build Analyzer Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        h1 { color: #333; border-bottom: 3px solid #007acc; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 13px; color: #666; text-transform: uppercase; }
        .summary-card .count { font-size: 36px; font-weight: bold; margin: 0; }
        .high { color: #dc3545; }
        .medium { color: #e6a817; }
        .low { color: #28a745; }
        .section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-high { background: #dc3545; color: white; }
        .badge-medium { background: #e6a817; color: white; }
        .badge-low { background: #28a745; color: white; }
        .timestamp { color: #999; font-size: 14px; margin-top: 20px; }
        .reports-note { color: #666; font-size: 13px; margin-top: 8px; }
        pre { white-space: pre-wrap; word-break: break-word; margin: 0; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Android Build Analyzer Report</h1>
    <p class="reports-note">Also available: <code>report.json</code> · <code>report.sarif</code></p>

    <div class="summary">
        <div class="summary-card">
            <h3>API Keys Found</h3>
            <p class="count high">${apiKeyTask.get().findings.size}</p>
        </div>
        <div class="summary-card">
            <h3>Security Issues</h3>
            <p class="count high">${securityCheckTask.get().findings.size}</p>
        </div>
        <div class="summary-card">
            <h3>Resource Issues</h3>
            <p class="count medium">${resourceAnalysisTask.get().findings.size}</p>
        </div>
        <div class="summary-card">
            <h3>Outdated Deps</h3>
            <p class="count medium">${dependencyCheckTask.get().findings.size}</p>
        </div>
        <div class="summary-card">
            <h3>Gradle Optimizations</h3>
            <p class="count low">${gradlePropertiesTask.get().findings.size}</p>
        </div>
    </div>

    ${buildApiKeySection()}
    ${buildSecuritySection()}
    ${buildResourceSection()}
    ${buildDependencySection()}
    ${buildGradlePropertiesSection()}

    <p class="timestamp">Generated: ${java.time.LocalDateTime.now()}</p>
</body>
</html>
        """.trimIndent()
    }

    private fun buildApiKeySection(): String {
        val findings = apiKeyTask.get().findings
        if (findings.isEmpty()) return htmlSection("API Key Detection", "<p>No exposed API keys detected.</p>")

        val rows = findings.joinToString("\n") { f ->
            "<tr><td>${f.file.escapeHtml()}:${f.line}</td>" +
            "<td><span class=\"badge badge-${f.severity.name.lowercase()}\">${f.severity.name}</span></td>" +
            "<td>${f.matched.escapeHtml()}</td>" +
            "<td><code>${f.pattern.escapeHtml()}</code></td></tr>"
        }
        return htmlSection(
            "API Key Detection",
            "<p>Found ${findings.size} potential API key(s).</p>" +
            "<table><thead><tr><th>Location</th><th>Severity</th><th>Matched</th><th>Pattern</th></tr></thead>" +
            "<tbody>$rows</tbody></table>"
        )
    }

    private fun buildSecuritySection(): String {
        val findings = securityCheckTask.get().findings
        if (findings.isEmpty()) return htmlSection("Security Checks", "<p>No security issues found.</p>")

        val rows = findings.joinToString("\n") { f ->
            "<tr><td>${f.type.displayName.escapeHtml()}</td>" +
            "<td><span class=\"badge badge-${f.severity.name.lowercase()}\">${f.severity.name}</span></td>" +
            "<td><pre>${f.message.escapeHtml()}</pre></td>" +
            "<td><code>${f.location.escapeHtml()}</code></td></tr>"
        }
        return htmlSection(
            "Security Checks",
            "<p>Found ${findings.size} security issue(s).</p>" +
            "<table><thead><tr><th>Issue</th><th>Severity</th><th>Message</th><th>Location</th></tr></thead>" +
            "<tbody>$rows</tbody></table>"
        )
    }

    private fun buildResourceSection(): String {
        val findings = resourceAnalysisTask.get().findings
        if (findings.isEmpty()) return htmlSection("Resource Analysis", "<p>No resource issues found.</p>")

        val rows = findings.joinToString("\n") { f ->
            "<tr><td>${f.type.displayName.escapeHtml()}</td>" +
            "<td><span class=\"badge badge-${f.severity.name.lowercase()}\">${f.severity.name}</span></td>" +
            "<td>${f.resourceName.escapeHtml()}</td>" +
            "<td>${f.message.escapeHtml()}</td></tr>"
        }
        return htmlSection(
            "Resource Analysis",
            "<p>Found ${findings.size} resource issue(s).</p>" +
            "<table><thead><tr><th>Type</th><th>Severity</th><th>Resource</th><th>Message</th></tr></thead>" +
            "<tbody>$rows</tbody></table>"
        )
    }

    private fun buildDependencySection(): String {
        val findings = dependencyCheckTask.get().findings
        if (findings.isEmpty()) return htmlSection("Dependency Versions", "<p>All checked dependencies are up to date.</p>")

        val rows = findings.joinToString("\n") { f ->
            "<tr><td><code>${f.groupId.escapeHtml()}:${f.artifactId.escapeHtml()}</code></td>" +
            "<td><span class=\"badge badge-${f.severity.name.lowercase()}\">${f.severity.name}</span></td>" +
            "<td>${f.currentVersion.escapeHtml()}</td>" +
            "<td><strong>${f.latestVersion.escapeHtml()}</strong></td></tr>"
        }
        return htmlSection(
            "Dependency Versions",
            "<p>Found ${findings.size} outdated dependency/ies (Maven Central only).</p>" +
            "<table><thead><tr><th>Dependency</th><th>Severity</th><th>Current</th><th>Latest</th></tr></thead>" +
            "<tbody>$rows</tbody></table>"
        )
    }

    private fun buildGradlePropertiesSection(): String {
        val findings = gradlePropertiesTask.get().findings
        if (findings.isEmpty()) return htmlSection("Gradle Properties", "<p>Gradle properties are well configured.</p>")

        val rows = findings.joinToString("\n") { f ->
            "<tr><td>${f.type.displayName.escapeHtml()}</td>" +
            "<td><span class=\"badge badge-${f.severity.name.lowercase()}\">${f.severity.name}</span></td>" +
            "<td>${f.message.escapeHtml()}</td>" +
            "<td><code>${f.suggestedFix.escapeHtml()}</code></td></tr>"
        }
        return htmlSection(
            "Gradle Properties",
            "<p>Found ${findings.size} build optimization opportunity/ies.</p>" +
            "<table><thead><tr><th>Issue</th><th>Severity</th><th>Description</th><th>Suggested Fix</th></tr></thead>" +
            "<tbody>$rows</tbody></table>"
        )
    }

    private fun htmlSection(title: String, body: String) =
        "<div class=\"section\"><h2>${title.escapeHtml()}</h2>$body</div>"

    // ====================================================================
    // JSON Report
    // ====================================================================

    private fun buildJsonReport(): String {
        val apiKeys = apiKeyTask.get().findings.map { f ->
            """{"file":${jsonStr(f.file)},"line":${f.line},"severity":${jsonStr(f.severity.name)},"matched":${jsonStr(f.matched)},"pattern":${jsonStr(f.pattern)}}"""
        }
        val security = securityCheckTask.get().findings.map { f ->
            """{"type":${jsonStr(f.type.name)},"displayName":${jsonStr(f.type.displayName)},"severity":${jsonStr(f.severity.name)},"message":${jsonStr(f.message)},"location":${jsonStr(f.location)},"buildType":${jsonStr(f.buildType)}}"""
        }
        val resources = resourceAnalysisTask.get().findings.map { f ->
            """{"type":${jsonStr(f.type.name)},"displayName":${jsonStr(f.type.displayName)},"severity":${jsonStr(f.severity.name)},"resourceName":${jsonStr(f.resourceName)},"message":${jsonStr(f.message)},"location":${jsonStr(f.location)}}"""
        }
        val dependencies = dependencyCheckTask.get().findings.map { f ->
            """{"groupId":${jsonStr(f.groupId)},"artifactId":${jsonStr(f.artifactId)},"currentVersion":${jsonStr(f.currentVersion)},"latestVersion":${jsonStr(f.latestVersion)},"severity":${jsonStr(f.severity.name)}}"""
        }
        val gradleProps = gradlePropertiesTask.get().findings.map { f ->
            """{"type":${jsonStr(f.type.name)},"displayName":${jsonStr(f.type.displayName)},"severity":${jsonStr(f.severity.name)},"message":${jsonStr(f.message)},"suggestedFix":${jsonStr(f.suggestedFix)}}"""
        }

        return """{
  "tool": "Android Build Analyzer",
  "version": "1.0.1",
  "generatedAt": "${java.time.Instant.now()}",
  "summary": {
    "apiKeys": ${apiKeys.size},
    "security": ${security.size},
    "resources": ${resources.size},
    "outdatedDependencies": ${dependencies.size},
    "gradleOptimizations": ${gradleProps.size}
  },
  "findings": {
    "apiKeys": [${apiKeys.joinToString(",")}],
    "security": [${security.joinToString(",")}],
    "resources": [${resources.joinToString(",")}],
    "outdatedDependencies": [${dependencies.joinToString(",")}],
    "gradleProperties": [${gradleProps.joinToString(",")}]
  }
}"""
    }

    // ====================================================================
    // SARIF Report
    // ====================================================================

    private fun buildSarifReport(): String {
        val results = mutableListOf<String>()
        val ruleIds = mutableSetOf<String>()

        securityCheckTask.get().findings.forEach { f ->
            ruleIds.add(f.type.name)
            val level = when (f.severity) {
                Severity.HIGH -> "error"
                Severity.MEDIUM -> "warning"
                Severity.LOW -> "note"
            }
            results.add(sarifResult(ruleId = f.type.name, level = level, message = f.message, uri = f.location))
        }

        apiKeyTask.get().findings.forEach { f ->
            val ruleId = "API_KEY_EXPOSURE"
            ruleIds.add(ruleId)
            results.add(
                sarifResult(
                    ruleId = ruleId,
                    level = "error",
                    message = "Potential API key exposure: ${f.matched}",
                    uri = f.file,
                    startLine = f.line
                )
            )
        }

        dependencyCheckTask.get().findings.forEach { f ->
            val ruleId = "OUTDATED_DEPENDENCY"
            ruleIds.add(ruleId)
            results.add(
                sarifResult(
                    ruleId = ruleId,
                    level = "note",
                    message = "${f.groupId}:${f.artifactId} is outdated (${f.currentVersion} → ${f.latestVersion})",
                    uri = "build.gradle.kts"
                )
            )
        }

        gradlePropertiesTask.get().findings.forEach { f ->
            ruleIds.add(f.type.name)
            results.add(
                sarifResult(
                    ruleId = f.type.name,
                    level = "note",
                    message = "${f.message} Suggested fix: ${f.suggestedFix}",
                    uri = "gradle.properties"
                )
            )
        }

        val rulesJson = ruleIds.joinToString(",") { id ->
            """{"id":${jsonStr(id)},"name":${jsonStr(id)},"helpUri":"https://github.com/davideagostini/android-build-analyzer"}"""
        }
        val resultsJson = results.joinToString(",")
        val dollarSign = "$"

        return """{
  "${dollarSign}schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Android Build Analyzer",
          "version": "1.0.1",
          "informationUri": "https://github.com/davideagostini/android-build-analyzer",
          "rules": [$rulesJson]
        }
      },
      "results": [$resultsJson]
    }
  ]
}"""
    }

    private fun sarifResult(
        ruleId: String,
        level: String,
        message: String,
        uri: String,
        startLine: Int? = null
    ): String {
        val lineRegion = if (startLine != null) ""","region":{"startLine":$startLine}""" else ""
        return """{"ruleId":${jsonStr(ruleId)},"level":${jsonStr(level)},"message":{"text":${jsonStr(message)}},"locations":[{"physicalLocation":{"artifactLocation":{"uri":${jsonStr(uri)}}$lineRegion}}]}"""
    }
}
