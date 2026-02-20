package com.davideagostini.analyzer.tasks

import com.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import org.gradle.api.provider.Property
import java.io.File
import java.util.zip.ZipFile

/**
 * Task that analyzes APK composition.
 */
open class ApkAnalysisTask : DefaultTask() {

    @get:Internal
    val extension: Property<AndroidBuildAnalyzerExtension> = project.objects.property(AndroidBuildAnalyzerExtension::class.java)

    @get:Internal
    val apkComponents: MutableList<ApkComponent> = mutableListOf()

    @TaskAction
    fun analyze() {
        apkComponents.clear()

        if (!extension.get().enabled) {
            return
        }

        val apkFile = findApkFile()

        if (apkFile == null || !apkFile.exists()) {
            logger.warn("No APK file found. Run assembleDebug or assembleRelease first.")
            return
        }

        analyzeApk(apkFile)
        logResults()
    }

    private fun findApkFile(): File? {
        val buildDir = project.layout.buildDirectory.get().asFile
        val possibleLocations = listOf(
            "outputs/apk/debug",
            "outputs/apk/release"
        )

        for (location in possibleLocations) {
            val apkDir = File(buildDir, location)
            if (apkDir.exists()) {
                val apks = apkDir.listFiles { _, name -> name.endsWith(".apk") }
                if (!apks.isNullOrEmpty()) {
                    return apks.first()
                }
            }
        }
        return null
    }

    private fun analyzeApk(apkFile: File) {
        try {
            ZipFile(apkFile).use { zip ->
                val entries = zip.entries().asSequence().toList()
                val totalSize = entries.sumOf { it.size }

                val componentMap = mutableMapOf<String, Long>()

                entries.forEach { entry ->
                    val componentName = categorizeEntry(entry.name)
                    val currentSize = componentMap.getOrDefault(componentName, 0L)
                    componentMap[componentName] = currentSize + entry.size
                }

                componentMap.forEach { (name, size) ->
                    val percentage = if (totalSize > 0) (size.toDouble() / totalSize * 100) else 0.0
                    apkComponents.add(
                        ApkComponent(
                            name = name,
                            size = size,
                            percentage = percentage
                        )
                    )
                }

                apkComponents.add(
                    ApkComponent(
                        name = "TOTAL",
                        size = totalSize,
                        percentage = 100.0
                    )
                )
            }
        } catch (e: Exception) {
            logger.error("Failed to analyze APK: ${e.message}")
        }
    }

    private fun categorizeEntry(name: String): String {
        return when {
            name.endsWith(".dex") -> "DEX (Bytecode)"
            name == "resources.arsc" -> "Resources Table"
            name.startsWith("lib/") -> "Native Libraries"
            name.startsWith("res/") -> "Android Resources"
            name.startsWith("assets/") -> "Assets"
            name.startsWith("META-INF/") -> "META-INF"
            name.endsWith(".xml") -> "XML Files"
            else -> "Other"
        }
    }

    private fun logResults() {
        logger.quiet("=".repeat(50))
        logger.quiet("APK Composition Analysis")
        logger.quiet("=".repeat(50))

        val sortedComponents = apkComponents.sortedByDescending { it.size }

        logger.quiet(String.format("%-25s %15s %10s", "Component", "Size", "%"))
        logger.quiet("-".repeat(52))

        sortedComponents.forEach { component ->
            logger.quiet(String.format("%-25s %15s %9.2f%%",
                component.name,
                formatSize(component.size),
                component.percentage))
        }
    }

    private fun formatSize(bytes: Long): String {
        return when {
            bytes >= 1024 * 1024 -> String.format("%.2f MB", bytes / (1024.0 * 1024.0))
            bytes >= 1024 -> String.format("%.2f KB", bytes / 1024.0)
            else -> "$bytes B"
        }
    }
}

data class ApkComponent(
    val name: String,
    val size: Long,
    val percentage: Double
)
