package io.github.davideagostini.analyzer.tasks

import io.github.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.time.Instant

/**
 * Generates a baseline file from the current findings so known issues can be suppressed.
 */
open class BaselineGeneratorTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> =
        project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:Internal
    val apiKeyTask: Property<ApiKeyDetectionTask> =
        project.objects.property(ApiKeyDetectionTask::class.java)

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

    @get:OutputFile
    val baselineFile: File
        get() = FindingFilterSupport.resolveBaselineFile(project, extension.get())

    @TaskAction
    fun generate() {
        if (!extension.get().enabled) return

        baselineFile.parentFile?.mkdirs()
        baselineFile.writeText(buildBaselineJson())
        logger.quiet("Analyzer baseline generated at ${baselineFile.absolutePath}")
    }

    private fun buildBaselineJson(): String {
        val entries = mutableListOf<String>()

        apiKeyTask.get().findings.forEach { finding ->
            entries.add(entryJson("API_KEY_EXPOSURE", apiKeyFingerprint(finding)))
        }
        securityCheckTask.get().findings.forEach { finding ->
            entries.add(entryJson(finding.type.name, securityFingerprint(finding)))
        }
        resourceAnalysisTask.get().findings.forEach { finding ->
            entries.add(entryJson(finding.type.name, resourceFingerprint(finding)))
        }
        gradlePropertiesTask.get().findings.forEach { finding ->
            entries.add(entryJson(finding.type.name, gradlePropertyFingerprint(finding)))
        }
        dependencyCheckTask.get().findings.forEach { finding ->
            entries.add(entryJson("OUTDATED_DEPENDENCY", dependencyFingerprint(finding)))
        }

        return """{
  "tool": "Android Build Analyzer",
  "version": "1.1.0",
  "generatedAt": "${Instant.now()}",
  "findings": [${entries.joinToString(",")}]
}"""
    }

    private fun entryJson(ruleId: String, fingerprint: String): String {
        return """{"ruleId":"${escape(ruleId)}","fingerprint":"${escape(fingerprint)}"}"""
    }

    private fun escape(value: String): String = value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")

    private fun apiKeyFingerprint(finding: ApiKeyFinding): String =
        FindingFilterSupport.sha256("${finding.file}:${finding.line}:${finding.pattern}")

    private fun securityFingerprint(finding: SecurityFinding): String =
        FindingFilterSupport.sha256("${finding.type}:${finding.location}:${finding.message}")

    private fun resourceFingerprint(finding: ResourceFinding): String =
        FindingFilterSupport.sha256("${finding.type}:${finding.resourceName}:${finding.location}")

    private fun gradlePropertyFingerprint(finding: GradlePropertyFinding): String =
        FindingFilterSupport.sha256("${finding.type}:${finding.suggestedFix}")

    private fun dependencyFingerprint(finding: DependencyFinding): String =
        FindingFilterSupport.sha256("${finding.groupId}:${finding.artifactId}")
}
