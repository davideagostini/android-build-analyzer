package com.davideagostini.analyzer.tasks

import com.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.Internal
import org.gradle.api.provider.Property

/**
 * Task that generates an HTML report from all analysis tasks.
 */
open class ReportGeneratorTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> = project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:OutputDirectory
    val reportDir: java.io.File by lazy {
        project.file(extension.get().reportPath)
    }

    @get:Internal
    val apiKeyTask: Property<ApiKeyDetectionTask> = project.objects.property(ApiKeyDetectionTask::class.java)

    @get:Internal
    val apkAnalysisTask: Property<ApkAnalysisTask> = project.objects.property(ApkAnalysisTask::class.java)

    @get:Internal
    val securityCheckTask: Property<SecurityCheckTask> = project.objects.property(SecurityCheckTask::class.java)

    @get:Internal
    val resourceAnalysisTask: Property<ResourceAnalysisTask> = project.objects.property(ResourceAnalysisTask::class.java)

    @TaskAction
    fun generate() {
        if (!extension.get().enabled) {
            return
        }

        reportDir.mkdirs()

        val html = buildHtmlReport()

        val reportFile = java.io.File(reportDir, "report.html")
        reportFile.writeText(html)

        logger.quiet("=".repeat(50))
        logger.quiet("Report generated: ${reportFile.absolutePath}")
        logger.quiet("=".repeat(50))
    }

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
        h1 {
            color: #333;
            border-bottom: 3px solid #007acc;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            font-size: 14px;
            color: #666;
            text-transform: uppercase;
        }
        .summary-card .count {
            font-size: 36px;
            font-weight: bold;
            margin: 0;
        }
        .high { color: #dc3545; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eee;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-high { background: #dc3545; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
        .timestamp {
            color: #999;
            font-size: 14px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <h1>Android Build Analyzer Report</h1>

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
    </div>

    ${buildApiKeySection()}
    ${buildSecuritySection()}
    ${buildResourceSection()}

    <p class="timestamp">Generated: ${java.time.LocalDateTime.now()}</p>
</body>
</html>
        """.trimIndent()
    }

    private fun buildApiKeySection(): String {
        val findings = apiKeyTask.get().findings
        if (findings.isEmpty()) {
            return """
            <div class="section">
                <h2>API Key Detection</h2>
                <p>No exposed API keys detected.</p>
            </div>
            """.trimIndent()
        }

        val rows = findings.joinToString("\n") { f ->
            """
            <tr>
                <td>${f.file}:${f.line}</td>
                <td><span class="badge badge-${f.severity.name.lowercase()}">${f.severity.name}</span></td>
                <td>${f.matched}</td>
                <td><code>${f.pattern}</code></td>
            </tr>
            """.trimIndent()
        }

        return """
        <div class="section">
            <h2>API Key Detection</h2>
            <p>Found ${findings.size} potential API key(s).</p>
            <table>
                <thead>
                    <tr>
                        <th>Location</th>
                        <th>Severity</th>
                        <th>Matched</th>
                        <th>Pattern</th>
                    </tr>
                </thead>
                <tbody>
                    $rows
                </tbody>
            </table>
        </div>
        """.trimIndent()
    }

    private fun buildSecuritySection(): String {
        val findings = securityCheckTask.get().findings
        if (findings.isEmpty()) {
            return """
            <div class="section">
                <h2>Security Checks</h2>
                <p>No security issues found.</p>
            </div>
            """.trimIndent()
        }

        val rows = findings.joinToString("\n") { f ->
            """
            <tr>
                <td>${f.type.displayName}</td>
                <td><span class="badge badge-${f.severity.name.lowercase()}">${f.severity.name}</span></td>
                <td>${f.message}</td>
                <td><code>${f.location}</code></td>
            </tr>
            """.trimIndent()
        }

        return """
        <div class="section">
            <h2>Security Checks</h2>
            <p>Found ${findings.size} security issue(s).</p>
            <table>
                <thead>
                    <tr>
                        <th>Issue</th>
                        <th>Severity</th>
                        <th>Message</th>
                        <th>Location</th>
                    </tr>
                </thead>
                <tbody>
                    $rows
                </tbody>
            </table>
        </div>
        """.trimIndent()
    }

    private fun buildResourceSection(): String {
        val findings = resourceAnalysisTask.get().findings
        if (findings.isEmpty()) {
            return """
            <div class="section">
                <h2>Resource Analysis</h2>
                <p>No resource issues found.</p>
            </div>
            """.trimIndent()
        }

        val rows = findings.joinToString("\n") { f ->
            """
            <tr>
                <td>${f.type.displayName}</td>
                <td><span class="badge badge-${f.severity.name.lowercase()}">${f.severity.name}</span></td>
                <td>${f.resourceName}</td>
                <td>${f.message}</td>
            </tr>
            """.trimIndent()
        }

        return """
        <div class="section">
            <h2>Resource Analysis</h2>
            <p>Found ${findings.size} resource issue(s).</p>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Resource</th>
                        <th>Message</th>
                    </tr>
                </thead>
                <tbody>
                    $rows
                </tbody>
            </table>
        </div>
        """.trimIndent()
    }
}
