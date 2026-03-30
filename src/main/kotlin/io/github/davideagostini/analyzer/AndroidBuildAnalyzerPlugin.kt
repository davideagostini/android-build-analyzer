package io.github.davideagostini.analyzer

import io.github.davideagostini.analyzer.tasks.ApiKeyDetectionTask
import io.github.davideagostini.analyzer.tasks.ApkAnalysisTask
import io.github.davideagostini.analyzer.tasks.BaselineGeneratorTask
import io.github.davideagostini.analyzer.tasks.DependencyCheckTask
import io.github.davideagostini.analyzer.tasks.GradlePropertiesCheckTask
import io.github.davideagostini.analyzer.tasks.ReportGeneratorTask
import io.github.davideagostini.analyzer.tasks.ResourceAnalysisTask
import io.github.davideagostini.analyzer.tasks.SecurityCheckTask
import org.gradle.api.Plugin
import org.gradle.api.Project

/**
 * Main Gradle plugin class for Android Build Analyzer.
 *
 * This plugin provides security and performance analysis for Android projects.
 * It applies only to projects with the 'com.android.application' or 'com.android.library' plugin.
 *
 * The plugin registers:
 * - An extension for configuration (androidBuildAnalyzer)
 * - Tasks for API key detection, APK analysis, security checks, and resource analysis
 * - A main 'analyze' task that runs all analysis and generates an HTML report
 *
 * Usage:
 *   apply plugin: 'io.github.davideagostini.analyzer'
 *   ./gradlew analyze
 */
class AndroidBuildAnalyzerPlugin : Plugin<Project> {

    /**
     * Applies the plugin to the given project.
     *
     * @param project The Gradle project to apply the plugin to
     */
    override fun apply(project: Project) {
        // Only apply to Android projects
        if (!isAndroidProject(project)) {
            project.logger.warn("Android Build Analyzer: Not an Android project. Plugin will not be applied.")
            return
        }

        // Register extension for configuration options
        val extension = project.extensions.create(
            "androidBuildAnalyzer",
            AndroidBuildAnalyzerExtension::class.java
        )

        // Set default source directories for scanning
        extension.srcDirs = project.files(
            "src/main/java",
            "src/main/kotlin",
            "src/main/res",
            "src/debug",
            "src/release"
        )

        val detectApiKeysTask = project.tasks.register("detectApiKeys", ApiKeyDetectionTask::class.java) {
            // Scans source files for exposed API keys.
            this.extension.set(extension)
        }

        val analyzeApkTask = project.tasks.register("analyzeApk", ApkAnalysisTask::class.java) {
            // Analyzes APK composition from already-built APK artifacts.
            this.extension.set(extension)
            mustRunAfter("assembleDebug", "assembleRelease")
        }

        val securityCheckTask = project.tasks.register("securityCheck", SecurityCheckTask::class.java) {
            this.extension.set(extension)
        }

        val analyzeResourcesTask = project.tasks.register("analyzeResources", ResourceAnalysisTask::class.java) {
            this.extension.set(extension)
        }

        val checkGradlePropertiesTask = project.tasks.register("checkGradleProperties", GradlePropertiesCheckTask::class.java) {
            this.extension.set(extension)
        }

        val checkDependencyVersionsTask = project.tasks.register("checkDependencyVersions", DependencyCheckTask::class.java) {
            this.extension.set(extension)
        }

        val generateAnalysisReportTask = project.tasks.register("generateAnalysisReport", ReportGeneratorTask::class.java) {
            this.extension.set(extension)
            this.apiKeyTask.set(detectApiKeysTask)
            this.apkAnalysisTask.set(analyzeApkTask)
            this.securityCheckTask.set(securityCheckTask)
            this.resourceAnalysisTask.set(analyzeResourcesTask)
            this.gradlePropertiesTask.set(checkGradlePropertiesTask)
            this.dependencyCheckTask.set(checkDependencyVersionsTask)
            dependsOn(
                detectApiKeysTask,
                analyzeApkTask,
                securityCheckTask,
                analyzeResourcesTask,
                checkGradlePropertiesTask,
                checkDependencyVersionsTask
            )
        }

        project.tasks.register("generateAnalysisBaseline", BaselineGeneratorTask::class.java) {
            this.extension.set(extension)
            this.apiKeyTask.set(detectApiKeysTask)
            this.securityCheckTask.set(securityCheckTask)
            this.resourceAnalysisTask.set(analyzeResourcesTask)
            this.gradlePropertiesTask.set(checkGradlePropertiesTask)
            this.dependencyCheckTask.set(checkDependencyVersionsTask)
            dependsOn(
                detectApiKeysTask,
                securityCheckTask,
                analyzeResourcesTask,
                checkGradlePropertiesTask,
                checkDependencyVersionsTask
            )
        }

        project.tasks.register("analyze") {
            group = "verification"
            description = "Run all Android Build Analyzer tasks"
            dependsOn(generateAnalysisReportTask)
        }
    }

    /**
     * Checks if the given project is an Android project.
     *
     * @param project The project to check
     * @return true if the project has Android application or library plugin
     */
    private fun isAndroidProject(project: Project): Boolean {
        val pluginManager = project.pluginManager
        return pluginManager.hasPlugin("com.android.application") ||
                pluginManager.hasPlugin("com.android.library")
    }
}
