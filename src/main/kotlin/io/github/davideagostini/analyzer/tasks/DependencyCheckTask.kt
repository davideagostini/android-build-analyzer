package io.github.davideagostini.analyzer.tasks

import io.github.davideagostini.analyzer.AndroidBuildAnalyzerExtension
import org.gradle.api.DefaultTask
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.net.HttpURLConnection
import java.net.URI

/**
 * Task that checks declared dependencies against Maven Central/Google Maven for outdated versions.
 *
 * Sources parsed:
 * - build.gradle.kts / build.gradle literal coordinates
 * - BOM coordinates declared via platform()/enforcedPlatform()
 * - Version Catalog aliases (libs.*) via gradle/libs.versions.toml
 *
 * Network calls use a 5-second timeout and fail gracefully if remotes are unreachable.
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

        logger.quiet("Checking ${deps.size} dependencies against Maven Central/Google Maven...")
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

        applySuppressions()
        logFindings()
    }

    // ====================================================================
    // Dependency Parsing
    // ====================================================================

    private data class Dep(val group: String, val artifact: String, val version: String, val source: String)

    private data class CatalogLibrary(val group: String, val artifact: String, val version: String)

    private data class VersionCatalog(
        val versions: Map<String, String>,
        val libraries: Map<String, CatalogLibrary>
    )

    private fun parseDependencies(): List<Dep> {
        val buildFiles = listOf(
            project.file("build.gradle.kts"),
            project.file("build.gradle")
        ).filter { it.exists() }

        val deps = mutableListOf<Dep>()
        val catalog = parseVersionCatalog()

        buildFiles.forEach { file ->
            try {
                val content = file.readText()
                deps += parseLiteralDependencies(content)
                deps += parseBomCoordinates(content)
                deps += parseCatalogAliasDependencies(content, catalog)
            } catch (e: Exception) {
                logger.warn("Could not parse ${file.name}: ${e.message}")
            }
        }

        return deps.distinctBy { "${it.group}:${it.artifact}" }
    }

    private fun parseLiteralDependencies(content: String): List<Dep> {
        val patterns = listOf(
            // Kotlin DSL/Groovy with parentheses: implementation("g:a:v")
            Regex("""(?:implementation|api|testImplementation|debugImplementation|runtimeOnly|compileOnly|kapt|annotationProcessor)\s*\(\s*["']([^"':\s]+):([^"':\s]+):([^"'${'$'}\{\s]+)["']\s*\)"""),
            // Groovy without parentheses: implementation 'g:a:v'
            Regex("""(?:implementation|api|testImplementation|debugImplementation|runtimeOnly|compileOnly|kapt|annotationProcessor)\s+["']([^"':\s]+):([^"':\s]+):([^"'${'$'}\{\s]+)["']""")
        )

        val deps = mutableListOf<Dep>()
        patterns.forEach { pattern ->
            pattern.findAll(content).forEach { match ->
                val version = match.groupValues[3].trim()
                if (version.isNotEmpty()) {
                    deps.add(
                        Dep(
                            group = match.groupValues[1].trim(),
                            artifact = match.groupValues[2].trim(),
                            version = version,
                            source = "build-script"
                        )
                    )
                }
            }
        }
        return deps
    }

    private fun parseBomCoordinates(content: String): List<Dep> {
        val pattern = Regex(
            """(?:platform|enforcedPlatform)\s*\(\s*["']([^"':\s]+):([^"':\s]+):([^"'${'$'}\{\s]+)["']\s*\)"""
        )
        return pattern.findAll(content).mapNotNull { match ->
            val version = match.groupValues[3].trim()
            if (version.isEmpty()) {
                null
            } else {
                Dep(
                    group = match.groupValues[1].trim(),
                    artifact = match.groupValues[2].trim(),
                    version = version,
                    source = "bom"
                )
            }
        }.toList()
    }

    private fun parseCatalogAliasDependencies(content: String, catalog: VersionCatalog?): List<Dep> {
        if (catalog == null) return emptyList()

        val aliasPatterns = listOf(
            // Dependency alias(...) style
            Regex("""(?:implementation|api|testImplementation|debugImplementation|runtimeOnly|compileOnly|kapt|annotationProcessor)\s*\(\s*alias\s*\(\s*libs\.([A-Za-z0-9_.-]+)\s*\)\s*\)"""),
            // Common version-catalog accessor style: implementation(libs.okhttp)
            Regex("""(?:implementation|api|testImplementation|debugImplementation|runtimeOnly|compileOnly|kapt|annotationProcessor)\s*\(\s*libs\.([A-Za-z0-9_.-]+)\s*\)"""),
            // BOM accessor style: implementation(platform(libs.firebase.bom))
            Regex("""(?:implementation|api|testImplementation|debugImplementation|runtimeOnly|compileOnly|kapt|annotationProcessor)\s*\(\s*(?:platform|enforcedPlatform)\s*\(\s*libs\.([A-Za-z0-9_.-]+)\s*\)\s*\)""")
        )

        val deps = mutableListOf<Dep>()
        aliasPatterns.forEach { pattern ->
            pattern.findAll(content).forEach aliasMatchLoop@{ match ->
                val accessor = match.groupValues[1]
                val possibleKeys = listOf(accessor, accessor.replace('.', '-'))
                val library = possibleKeys.asSequence()
                    .mapNotNull { key -> catalog.libraries[key] }
                    .firstOrNull()
                    ?: return@aliasMatchLoop

                deps.add(
                    Dep(
                        group = library.group,
                        artifact = library.artifact,
                        version = library.version,
                        source = "version-catalog"
                    )
                )
            }
        }

        return deps
    }

    private fun applySuppressions() {
        val baselineEntries = FindingFilterSupport.loadBaseline(project, extension.get())
        val filtered = findings.filterNot { finding ->
            FindingFilterSupport.isSuppressed(
                ruleId = "OUTDATED_DEPENDENCY",
                fingerprint = FindingFilterSupport.sha256("${finding.groupId}:${finding.artifactId}"),
                extension = extension.get(),
                baselineEntries = baselineEntries
            )
        }

        findings.clear()
        findings.addAll(filtered)
    }

    private fun parseVersionCatalog(): VersionCatalog? {
        val candidates = listOf(
            project.file("gradle/libs.versions.toml"),
            project.file("../gradle/libs.versions.toml")
        )
        val catalogFile = candidates.firstOrNull { it.exists() } ?: return null
        return try {
            parseVersionCatalogFile(catalogFile)
        } catch (e: Exception) {
            logger.debug("Could not parse version catalog ${catalogFile.path}: ${e.message}")
            null
        }
    }

    private fun parseVersionCatalogFile(file: File): VersionCatalog {
        val versions = mutableMapOf<String, String>()
        val libraries = mutableMapOf<String, CatalogLibrary>()

        var section: String? = null
        file.readLines().forEach { raw ->
            val line = raw.substringBefore('#').trim()
            if (line.isEmpty()) return@forEach

            val sectionMatch = Regex("""^\[([A-Za-z0-9_.-]+)]$""").find(line)
            if (sectionMatch != null) {
                section = sectionMatch.groupValues[1]
                return@forEach
            }

            when (section) {
                "versions" -> {
                    val match = Regex("""^([A-Za-z0-9_.-]+)\s*=\s*"([^"]+)"""").find(line) ?: return@forEach
                    versions[match.groupValues[1]] = match.groupValues[2]
                }

                "libraries" -> {
                    val keyMatch = Regex("""^([A-Za-z0-9_.-]+)\s*=\s*(.+)$""").find(line) ?: return@forEach
                    val key = keyMatch.groupValues[1]
                    val value = keyMatch.groupValues[2].trim()

                    val library = when {
                        value.startsWith("\"") -> parseShortNotationLibrary(value)
                        value.startsWith("{") -> parseInlineTableLibrary(value, versions)
                        else -> null
                    }
                    if (library != null && library.version.isNotBlank()) {
                        libraries[key] = library
                    }
                }
            }
        }

        return VersionCatalog(versions = versions, libraries = libraries)
    }

    private fun parseShortNotationLibrary(value: String): CatalogLibrary? {
        val triplet = value.trim().trim('"')
        val parts = triplet.split(':')
        if (parts.size != 3) return null
        return CatalogLibrary(
            group = parts[0].trim(),
            artifact = parts[1].trim(),
            version = parts[2].trim()
        )
    }

    private fun parseInlineTableLibrary(value: String, versions: Map<String, String>): CatalogLibrary? {
        val body = value.trim().removePrefix("{").removeSuffix("}")

        val module = extractQuotedField(body, "module")
        val group = extractQuotedField(body, "group")
        val artifact = extractQuotedField(body, "name")
        val versionLiteral = extractQuotedField(body, "version")
        val versionRef = extractQuotedField(body, "version.ref")

        val resolvedVersion = when {
            !versionLiteral.isNullOrBlank() -> versionLiteral
            !versionRef.isNullOrBlank() -> versions[versionRef]
            else -> null
        } ?: return null

        return if (!module.isNullOrBlank()) {
            val parts = module.split(':')
            if (parts.size != 2) null else CatalogLibrary(parts[0].trim(), parts[1].trim(), resolvedVersion.trim())
        } else if (!group.isNullOrBlank() && !artifact.isNullOrBlank()) {
            CatalogLibrary(group.trim(), artifact.trim(), resolvedVersion.trim())
        } else {
            null
        }
    }

    private fun extractQuotedField(body: String, key: String): String? {
        val pattern = Regex("""(?:^|,)\s*${Regex.escape(key)}\s*=\s*"([^"]+)"""")
        return pattern.find(body)?.groupValues?.getOrNull(1)
    }

    // ====================================================================
    // Repository APIs
    // ====================================================================

    private fun fetchLatestVersion(group: String, artifact: String): String? {
        return fetchFromMavenCentral(group, artifact) ?: fetchFromGoogleMaven(group, artifact)
    }

    private fun fetchFromMavenCentral(group: String, artifact: String): String? {
        val url = "https://search.maven.org/solrsearch/select" +
            "?q=g:${group}+AND+a:${artifact}&rows=20&wt=json"

        val connection = URI.create(url).toURL().openConnection() as HttpURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", "Android-Build-Analyzer/1.0")

        return try {
            if (connection.responseCode != 200) return null
            val response = connection.inputStream.bufferedReader().readText()
            val versions = Regex(""""v"\s*:\s*"([^"]+)"""")
                .findAll(response)
                .map { it.groupValues[1] }
                .toList()

            maxStableVersion(versions)
        } finally {
            connection.disconnect()
        }
    }

    private fun fetchFromGoogleMaven(group: String, artifact: String): String? {
        val groupPath = group.replace('.', '/')
        val url = "https://dl.google.com/dl/android/maven2/$groupPath/$artifact/maven-metadata.xml"

        val connection = URI.create(url).toURL().openConnection() as HttpURLConnection
        connection.connectTimeout = 5_000
        connection.readTimeout = 5_000
        connection.requestMethod = "GET"
        connection.setRequestProperty("User-Agent", "Android-Build-Analyzer/1.0")

        return try {
            if (connection.responseCode != 200) return null
            val response = connection.inputStream.bufferedReader().readText()
            val versions = Regex("""<version>([^<]+)</version>""")
                .findAll(response)
                .map { it.groupValues[1] }
                .toList()

            maxStableVersion(versions)
        } finally {
            connection.disconnect()
        }
    }

    private fun maxStableVersion(versions: List<String>): String? {
        return versions.filter(::isStableVersion).maxWithOrNull { a, b ->
            when {
                isNewer(a, b) -> 1
                isNewer(b, a) -> -1
                else -> 0
            }
        }
    }

    private fun isStableVersion(version: String): Boolean {
        val normalized = version.lowercase()
        if (version.contains('-')) return false
        return listOf("alpha", "beta", "rc", "preview", "snapshot").none { normalized.contains(it) }
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
