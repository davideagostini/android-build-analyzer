package io.github.davideagostini.analyzer.tasks

import io.github.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.Project
import java.io.File
import java.security.MessageDigest

internal data class BaselineEntry(
    val ruleId: String,
    val fingerprint: String
)

internal object FindingFilterSupport {

    fun loadBaseline(project: Project, extension: AndroidBuildAnalyzerExtension): Set<BaselineEntry> {
        val baselineFile = resolveBaselineFile(project, extension)
        if (!baselineFile.exists()) return emptySet()

        return try {
            val content = baselineFile.readText()
            val entryPattern = Regex(
                """\{\s*"ruleId"\s*:\s*"([^"]+)"\s*,\s*"fingerprint"\s*:\s*"([^"]+)"\s*}"""
            )
            entryPattern.findAll(content).map {
                BaselineEntry(
                    ruleId = it.groupValues[1],
                    fingerprint = it.groupValues[2]
                )
            }.toSet()
        } catch (_: Exception) {
            emptySet()
        }
    }

    fun resolveBaselineFile(project: Project, extension: AndroidBuildAnalyzerExtension): File {
        return project.file(extension.baselineFilePath)
    }

    fun isSuppressed(
        ruleId: String,
        fingerprint: String,
        extension: AndroidBuildAnalyzerExtension,
        baselineEntries: Set<BaselineEntry>
    ): Boolean {
        if (extension.suppressedRuleIds.contains(ruleId)) return true
        return baselineEntries.contains(BaselineEntry(ruleId = ruleId, fingerprint = fingerprint))
    }

    fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }
}
