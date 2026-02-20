package io.github.davideagostini.analyzer

import io.github.davideagostini.analyzer.tasks.ApiKeyDetectionTask
import io.github.davideagostini.analyzer.tasks.ApkAnalysisTask
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

        // Create the detectApiKeys task - scans source files for API keys
        project.tasks.create("detectApiKeys", ApiKeyDetectionTask::class.java).apply {
            this.extension.set(extension)
        }

        // Create the analyzeApk task - analyzes APK composition
        // Does not force a build; scans whatever APK is already present in build/outputs/apk/
        project.tasks.create("analyzeApk", ApkAnalysisTask::class.java).apply {
            this.extension.set(extension)
        }

        // Create the securityCheck task - checks for security issues
        project.tasks.create("securityCheck", SecurityCheckTask::class.java).apply {
            this.extension.set(extension)
        }

        // Create the analyzeResources task - analyzes resources
        project.tasks.create("analyzeResources", ResourceAnalysisTask::class.java).apply {
            this.extension.set(extension)
        }

        // Create the checkGradleProperties task - checks gradle.properties for build optimizations
        project.tasks.create("checkGradleProperties", GradlePropertiesCheckTask::class.java).apply {
            this.extension.set(extension)
        }

        // Create the checkDependencyVersions task - checks for outdated dependencies on Maven Central
        project.tasks.create("checkDependencyVersions", DependencyCheckTask::class.java).apply {
            this.extension.set(extension)
        }

        // Create the generateAnalysisReport task - generates HTML, JSON and SARIF reports
        project.tasks.create("generateAnalysisReport", ReportGeneratorTask::class.java).apply {
            this.extension.set(extension)
            this.apiKeyTask.set(project.tasks.getByName("detectApiKeys") as ApiKeyDetectionTask)
            this.apkAnalysisTask.set(project.tasks.getByName("analyzeApk") as ApkAnalysisTask)
            this.securityCheckTask.set(project.tasks.getByName("securityCheck") as SecurityCheckTask)
            this.resourceAnalysisTask.set(project.tasks.getByName("analyzeResources") as ResourceAnalysisTask)
            this.gradlePropertiesTask.set(project.tasks.getByName("checkGradleProperties") as GradlePropertiesCheckTask)
            this.dependencyCheckTask.set(project.tasks.getByName("checkDependencyVersions") as DependencyCheckTask)
            dependsOn(
                "detectApiKeys", "analyzeApk", "securityCheck",
                "analyzeResources", "checkGradleProperties", "checkDependencyVersions"
            )
        }

        // Create the main analyze task that runs everything
        project.tasks.create("analyze") {
            group = "verification"
            description = "Run all Android Build Analyzer tasks"
            dependsOn("generateAnalysisReport")
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
